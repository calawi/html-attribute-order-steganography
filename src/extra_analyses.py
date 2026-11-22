"""Extra analyses requested in the review of the paper (comments 4, 10, 19, 24, 29, 31, 32, 36, 37).

A. Detection on pages that can hold a message (comment 24), from results/per_page.csv.
B. Real message lengths, plaintext against encrypted, sequential against spread positions
   (comments 4, 10, 19, 36).
C. Bit survival and failure causes after HTML processing (comments 31, 32).
D. Key-derivation time (comment 29).

Usage: python -I extra_analyses.py <pages_dir> <results_dir>
"""
import csv
import json
import random
import statistics as st
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from html.parser import HTMLParser
from pathlib import Path

import numpy as np

import experiments as ex
import head_to_head as h2h
import htmlstego as hs

SEED = ex.SEED
BOOT = 1000
TEXT = ("The meeting is moved to Thursday at ten in the main office. Please bring the signed contract and the two "
        "copies of the invoice. Do not forward this note to anyone and delete it after reading. The courier will "
        "collect the documents from reception before noon and confirm by phone when they arrive at the branch. "
        "If anything changes I will write again tonight.")


def boot_auc(neg, pos):
    neg, pos = np.asarray(neg, float), np.asarray(pos, float)
    auc = h2h.roc_auc(neg, pos)
    rs, n, b = np.random.RandomState(SEED), len(neg), []
    for _ in range(BOOT):
        i = rs.randint(0, n, n)
        b.append(h2h.roc_auc(neg[i], pos[i]))
    lo, hi = np.percentile(b, [2.5, 97.5])
    return {"auc": float(auc), "lo": float(lo), "hi": float(hi), "n": int(n)}


def split(pages_dir):
    pages = sorted(Path(pages_dir).glob("*.html"))
    rnd = random.Random(SEED)
    calib = set(rnd.sample(range(len(pages)), k=round(0.3 * len(pages))))
    return [p for i, p in enumerate(pages) if i not in calib]

# ------------------------------------------------------------------ B. message arms

ARMS = {  # name: (kind, message bytes, page set threshold in bits)
    "plain_16B": ("plain", 16), "plain_32B": ("plain", 32), "plain_64B": ("plain", 64),
    "enc_16B": ("enc", 16), "enc_16B_spread": ("enc_spread", 16),
    "plain_112B": ("plain", 112), "enc_64B": ("enc", 64),
}
SET_66 = ["plain_16B", "plain_32B", "plain_64B", "enc_16B", "enc_16B_spread"]
SET_114 = ["plain_112B" if False else "plain_112B", "enc_64B"]


def make_bits(kind, n, rnd):
    off = rnd.randrange(len(TEXT) - 130)
    msg = TEXT[off: off + n]
    if kind == "plain":
        framed = (n).to_bytes(2, "big") + msg.encode()
    else:
        blob = hs.encrypt(msg, "pw", rnd.randbytes)
        framed = len(blob).to_bytes(2, "big") + blob
    return hs.to_bits(framed)


def worker_arms(path):
    hs.KDF_ITER = 1000  # speed only; ciphertext is still AES output
    html = Path(path).read_text(encoding="utf-8")
    tags = hs.start_tags(html)
    sl = hs.slots(tags, "auto")
    rnd = random.Random(f"{SEED}-arms-{Path(path).name}")
    out = {"cap": len(sl)}
    c = ex.order_counts(tags, sl)
    out["clean"] = (ex.score_consistency(c), h2h.stat_W(tags))
    for name, (kind, n) in ARMS.items():
        bits = make_bits("enc" if kind.startswith("enc") else "plain", n, rnd)
        if len(sl) < 8 * 66:
            continue
        if name in SET_114 and len(sl) < 8 * 114:
            continue
        t2 = ex.copy_tags(tags)
        idx = list(range(len(bits)))
        if kind == "enc_spread":
            idx = sorted(rnd.sample(range(len(sl)), len(bits)))
        for b, k in zip(bits, idx):
            s = sl[k]
            hs.set_bit(t2[s.tag], s, b)
        c2 = ex.order_counts(t2, sl)
        out[name] = (ex.score_consistency(c2), h2h.stat_W(t2), len(bits))
    return Path(path).name, out

# ------------------------------------------------------------------ C. bit survival

class _Tags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.t = []

    def handle_starttag(self, tag, attrs):
        if len(attrs) >= 2:
            self.t.append((tag, [a for a, _ in attrs]))


def tag_list(html):
    p = _Tags()
    p.feed(html)
    p.close()
    return p.t


def eligibility(html, plist):
    """Mark which tags of the parser view the method uses as carriers."""
    car = [(t.head[1:].lower(), t.names) for t in hs.start_tags(html) if len(t.names) >= 2]
    out, k = [], 0
    for tag, names in plist:
        if k < len(car) and car[k] == (tag, [n.lower() for n in names]):
            out.append(True)
            k += 1
        else:
            out.append(False)
    return out


def is_ctype(t):
    return t[0] == "meta" and "http-equiv" in t[1] and "content" in t[1]


def first_difference(stego, out):
    """First change, in document order, that can affect the carrier sequence.

    Tags with two or more attributes are compared. A lookahead separates a tag that
    was removed or inserted from a tag whose own attributes changed (without it, a
    removed tag looks like a tag with different attributes).
    """
    a, b = tag_list(stego), tag_list(out)
    ea, eb = eligibility(stego, a), eligibility(out, b)
    i = j = 0
    LOOK = 12
    while i < len(a) and j < len(b):
        x, y, u, v = a[i], b[j], ea[i], eb[j]
        if x == y and u == v:
            i, j = i + 1, j + 1
            continue
        if x == y:
            return "quotes or spacing rewritten, so a skipped tag became a carrier" if v else "tag stopped being a carrier"
        dedup = [x[0], list(dict.fromkeys(x[1]))]
        same_tag = x[0] == y[0]
        if same_tag and len(set(x[1])) < len(x[1]) and dedup[1] == y[1]:
            if not u and not v:
                i, j = i + 1, j + 1
                continue
            return "duplicate attribute removed, so a skipped tag became a carrier"
        if same_tag and any(":" in n for n in set(x[1]) - set(y[1])) and [n.split(":")[-1] for n in x[1]] == [n.split(":")[-1] for n in y[1]]:
            if not u and not v:
                i, j = i + 1, j + 1
                continue
            return "namespace prefix dropped"
        # removed or inserted tag: the next tags line up again after skipping one side
        rem = next((k for k in range(1, LOOK) if i + k < len(a) and a[i + k] == y and a[i + k + 1:i + k + 3] == b[j + 1:j + 3]), None)
        ins = next((k for k in range(1, LOOK) if j + k < len(b) and b[j + k] == x and b[j + k + 1:j + k + 3] == a[i + 1:i + 3]), None)
        if rem is not None and (ins is None or rem <= ins):
            if not any(ea[i:i + rem]):
                i += rem
                continue
            return "content-type meta tag removed" if all(is_ctype(t) for t in a[i:i + rem]) else "tag added, removed or moved"
        if ins is not None:
            if not any(eb[j:j + ins]):
                j += ins
                continue
            return "tag added, removed or moved"
        if not same_tag:
            return "tag added, removed or moved"
        if not u and not v:
            i, j = i + 1, j + 1
            continue
        if sorted(x[1]) == sorted(y[1]):
            return "attribute order changed by the tool"
        if not u and v:
            return "malformed attribute dropped or renamed, so a skipped tag became a carrier"
        return "attribute dropped or renamed"
    if any(ea[i:]) or any(eb[j:]):
        return "tag added, removed or moved"
    return "other"

# kept for tests: the same serializer without lxml's default removal of the content-type tag
def lxml_keep_meta(h):
    import lxml.html
    return lxml.html.tostring(lxml.html.document_fromstring(h), encoding="unicode", include_meta_content_type=True)


def worker_survival(args):
    path, norms = args
    html = Path(path).read_text(encoding="utf-8")
    name = Path(path).name
    rnd = random.Random(f"{SEED}-{name}")
    tags = hs.start_tags(html)
    sl = hs.slots(tags, "auto")
    if hs.max_message_bytes(len(sl)) < 1:
        return None
    # replay the random draws of experiments.analyse_page so the stego page is the same
    for rate in ex.RATES:
        t2 = ex.copy_tags(tags)
        for s in sl[: int(rate * len(sl))]:
            hs.set_bit(t2[s.tag], s, rnd.getrandbits(1))
    types = sorted({ex.pair_type(s) for s in sl})
    tbits = {t: rnd.getrandbits(1) for t in types}
    mb = hs.max_message_bytes(len(sl))
    msg = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(mb))
    stego = hs.hide(html, msg, "test-password", rng=rnd.randbytes)
    n_bits = 8 * hs.blob_size(mb)
    want = hs.read_bits(stego, n_bits)
    stego_tags = tag_list(stego)
    res = {}
    for tname, fn in ex.TRANSFORMS.items():
        try:
            out = fn(stego)
            got = hs.read_bits(out, n_bits)
        except Exception:
            res[tname] = {"ok": False, "match": 0.0, "prefix": 0.0, "cause": "tool error"}
            continue
        ok = got == want
        match = sum(g == w for g, w in zip(got, want)) / n_bits
        k = next((i for i, (g, w) in enumerate(zip(got, want)) if g != w), None)
        if k is None:
            k = len(got) if len(got) < n_bits else n_bits
        r = {"ok": ok, "match": match, "prefix": k / n_bits}
        if not ok:
            r["cause"] = first_difference(stego, out)
        res[tname] = r
    res["_lxml_keep_meta_ok"] = hs.read_bits(lxml_keep_meta(stego), n_bits) == want
    return name, res

# ------------------------------------------------------------------ main

def main():
    pages_dir, res = Path(sys.argv[1]), Path(sys.argv[2])
    out = {}
    rows = list(csv.DictReader(open(res / "per_page.csv", encoding="utf-8")))

    # A. detection on pages that can hold at least one message byte
    sub = [r for r in rows if int(r["msg_auto"]) >= 1]
    out["A_pages_that_can_hold_a_message"] = len(sub)
    for rate in ("0.1", "0.25", "0.5", "1.0"):
        out[f"A_auc_cons_{rate}"] = boot_auc([float(r["clean_cons"]) for r in sub], [float(r[f"stego{rate}_cons"]) for r in sub])
    small = [r for r in rows if int(r["msg_auto"]) < 1]
    out["A_pages_too_small"] = len(small)

    # Cachin-style numbers
    cl = [float(r["clean_cons"]) for r in rows]
    fu = [float(r["stego1.0_cons"]) for r in rows]
    out["cons_clean_median"] = float(np.median(cl))
    out["cons_full_median"] = float(np.median(fu))
    out["clean_above_0.20"] = int(sum(x > 0.20 for x in cl))
    out["full_above_0.20"] = int(sum(x > 0.20 for x in fu))
    out["clean_max"] = float(max(cl))

    ev = split(pages_dir)
    workers = max(2, (__import__("os").cpu_count() or 4) - 1)

    # B. message arms
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=workers) as ex_:
        got = dict(ex_.map(worker_arms, [str(p) for p in ev], chunksize=2))
    arms = {}
    for names, minbits in ((SET_66, 528), (SET_114, 912)):
        pageset = [n for n, o in got.items() if o["cap"] >= minbits and all(a in o for a in names)]
        neg_c = [got[n]["clean"][0] for n in pageset]
        neg_w = [got[n]["clean"][1] for n in pageset]
        for a in names:
            pc = [got[n][a][0] for n in pageset]
            pw = [got[n][a][1] for n in pageset]
            arms[a] = {"pages": len(pageset), "bits": got[pageset[0]][a][2],
                       "oc": boot_auc(neg_c, pc), "w": boot_auc(neg_w, pw),
                       "median_cons": float(np.median(pc)), "median_cons_clean": float(np.median(neg_c))}
    out["B_arms"] = arms
    print("arms done", round(time.time() - t0), "s", flush=True)

    # C. survival
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=workers) as ex_:
        surv = [r for r in ex_.map(worker_survival, [(str(p), None) for p in ev], chunksize=2) if r]
    C = {}
    for tname in ex.TRANSFORMS:
        rs = [o[tname] for _, o in surv]
        fails = [r for r in rs if not r["ok"]]
        C[tname] = {"pages": len(rs), "ok": sum(r["ok"] for r in rs), "fail": len(fails),
                    "median_match_all": float(np.median([r["match"] for r in rs])),
                    "median_match_failed": float(np.median([r["match"] for r in fails])) if fails else None,
                    "median_prefix_failed": float(np.median([r["prefix"] for r in fails])) if fails else None,
                    "share_failed_with_prefix_ge_half": float(np.mean([r["prefix"] >= 0.5 for r in fails])) if fails else None,
                    "causes": dict(Counter(r["cause"] for r in fails))}
    out["C_survival"] = C
    out["C_lxml_keep_meta_ok"] = sum(o["_lxml_keep_meta_ok"] for _, o in surv)
    out["C_lxml_keep_meta_rescued"] = sum(o["_lxml_keep_meta_ok"] and not o["lxml_reserialize"]["ok"] for _, o in surv)
    out["C_lxml_meta_cause_rescued"] = sum(o["_lxml_keep_meta_ok"] for _, o in surv if o["lxml_reserialize"].get("cause") == "content-type meta tag removed")
    print("survival done", round(time.time() - t0), "s", flush=True)

    # D. key derivation time
    ts = []
    for i in range(30):
        t = time.perf_counter()
        hs._key("test-password", bytes(16))
        ts.append(time.perf_counter() - t)
    out["D_kdf_median_s"] = st.median(ts)

    (res / "extra.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
