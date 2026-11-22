"""How much of the cost of encryption depends on the layout? (Section 5.6, Table 11)

The same 16-byte messages are hidden with five encryption layouts and without encryption,
on the pages with room for 528 carrier bits (the pages of Table 10). Every layout really
encrypts, and every message is read back from the page and decrypted.

  cbc_salt   the layout of the paper: 16-byte salt, 16-byte IV, AES-256-CBC with padding
  cbc        key agreed in advance (no salt stored), 16-byte IV, AES-256-CBC with padding
  gcm        key agreed in advance, 12-byte nonce, AES-256-GCM with a 16-byte tag
  ctr8       key agreed in advance, 8-byte random nonce, AES-256-CTR (not authenticated)
  ctr0       key and message number agreed in advance, nothing stored, AES-256-CTR
             (not authenticated; a key and number pair must never be used twice)
  plain      no encryption

Every layout keeps the two-byte length header.
Usage: python overhead_test.py <pages_dir> <results_dir>
"""
import json
import random
import statistics as st
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import experiments as ex
import extra_analyses as xa
import head_to_head as h2h
import htmlstego as hs

SEED = ex.SEED
REPS = 10
N = 16                       # message bytes
NEED = 8 * hs.blob_size(N)   # 528 carrier bits
LAYOUTS = ["cbc_salt", "cbc", "gcm", "ctr8", "ctr0", "plain"]
FIXED = {"gcm": 28, "ctr8": 8, "ctr0": 0, "plain": 0}   # bytes added by the stream layouts


def _ctr(key, block, data):
    c = Cipher(algorithms.AES(key), modes.CTR(block)).encryptor()
    return c.update(data) + c.finalize()


def seal(layout, msg, key, number, rng):
    if layout == "plain":
        return msg
    if layout == "cbc_salt":
        return hs.encrypt(msg.decode(), "pw", rng)
    if layout == "cbc":
        iv, p = rng(16), padding.PKCS7(128).padder()
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv + e.update(p.update(msg) + p.finalize()) + e.finalize()
    if layout == "gcm":
        nonce = rng(12)
        return nonce + AESGCM(key).encrypt(nonce, msg, None)
    if layout == "ctr8":
        nonce = rng(8)
        return nonce + _ctr(key, nonce + bytes(8), msg)
    return _ctr(key, number.to_bytes(8, "big") + bytes(8), msg)


def open_(layout, blob, key, number):
    if layout == "plain":
        return blob
    if layout == "cbc_salt":
        return hs.decrypt(blob, "pw").encode()
    if layout == "cbc":
        d = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
        u = padding.PKCS7(128).unpadder()
        return u.update(d.update(blob[16:]) + d.finalize()) + u.finalize()
    if layout == "gcm":
        return AESGCM(key).decrypt(blob[:12], blob[12:], None)
    if layout == "ctr8":
        return _ctr(key, blob[:8] + bytes(8), blob[8:])
    return _ctr(key, number.to_bytes(8, "big") + bytes(8), blob)


def longest(layout, cap):
    """Longest message in bytes that fits into cap carrier bits (below 1 means none)."""
    room = cap // 8 - hs.HEADER_BYTES
    if layout == "cbc_salt":
        return hs.max_message_bytes(cap)
    if layout == "cbc":
        room -= 16
        return 16 * (room // 16) - 1 if room >= 16 else -1
    return room - FIXED[layout]


def worker(path):
    hs.KDF_ITER = 1000  # speed only, as in extra_analyses.py
    tags = hs.start_tags(Path(path).read_text(encoding="utf-8"))
    sl = hs.slots(tags, "auto")
    out = {"cap": len(sl)}
    if len(sl) < NEED:
        return out
    c = ex.order_counts(tags, sl)
    out["clean"] = (ex.score_consistency(c), h2h.stat_W(tags))
    out["ok"] = 0
    for rep in range(REPS):
        rnd = random.Random(f"{SEED}-overhead-{rep}-{Path(path).name}")
        off = rnd.randrange(len(xa.TEXT) - 130)
        msg, key = xa.TEXT[off: off + N].encode(), rnd.randbytes(32)
        for lay in LAYOUTS:
            blob = seal(lay, msg, key, rep, rnd.randbytes)
            bits = hs.to_bits(len(blob).to_bytes(2, "big") + blob)
            t2 = ex.copy_tags(tags)
            for b, s in zip(bits, sl):
                hs.set_bit(t2[s.tag], s, b)
            s2 = hs.slots(t2, "auto")
            back = hs.from_bits([hs.read_bit(t2[s.tag], s) for s in s2[: len(bits)]])
            n = int.from_bytes(back[:2], "big")
            out["ok"] += open_(lay, back[2: 2 + n], key, rep) == msg
            out[f"{lay}@{rep}"] = (ex.score_consistency(ex.order_counts(t2, sl)), h2h.stat_W(t2), len(bits))
    return out


def main():
    pages, res = xa.split(sys.argv[1]), Path(sys.argv[2])
    with ProcessPoolExecutor() as pool:
        got = list(pool.map(worker, map(str, pages), chunksize=2))
    big = [g for g in got if "clean" in g]
    trips = sum(g["ok"] for g in big)
    assert trips == len(big) * REPS * len(LAYOUTS), "a message did not come back"
    out = {"pages": len(got), "pages_detection": len(big), "round_trips_ok": trips, "repetitions": REPS, "layouts": {}}
    for lay in LAYOUTS:
        lon = [longest(lay, g["cap"]) for g in got]
        r = {"carrier_bits_16B": big[0][f"{lay}@0"][2],
             "pages_cannot_hold_1B": sum(x < 1 for x in lon), "pages_hold_16B": sum(x >= N for x in lon),
             "median_longest_bytes": st.median(max(0, x) for x in lon)}
        for k, name in enumerate(("OC", "W")):
            neg = [g["clean"][k] for g in big]
            r[name] = xa.boot_auc(neg, [g[f"{lay}@0"][k] for g in big])
            reps = [h2h.roc_auc(neg, [g[f"{lay}@{i}"][k] for g in big]) for i in range(REPS)]
            r[name]["reps_mean"], r[name]["reps_min"], r[name]["reps_max"] = float(st.mean(reps)), float(min(reps)), float(max(reps))
        out["layouts"][lay] = r
        print(f"{lay:9} bits {r['carrier_bits_16B']:4} | cannot hold 1B {r['pages_cannot_hold_1B']:3} ({r['pages_cannot_hold_1B'] / len(got):.0%})"
              f" | hold 16B {r['pages_hold_16B']:3} ({r['pages_hold_16B'] / len(got):.0%}) | median longest {r['median_longest_bytes']:g} B"
              f" | OC {r['OC']['auc']:.3f} ({r['OC']['lo']:.3f} to {r['OC']['hi']:.3f}) reps {r['OC']['reps_mean']:.3f} [{r['OC']['reps_min']:.3f}, {r['OC']['reps_max']:.3f}]"
              f" | W {r['W']['auc']:.3f} ({r['W']['lo']:.3f} to {r['W']['hi']:.3f})")
    res.mkdir(parents=True, exist_ok=True)
    (res / "overhead.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print("pages", len(got), "| detection pages", len(big), "| round trips", trips)


if __name__ == "__main__":
    main()
