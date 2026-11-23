"""Does a careful sender escape detection? (review comment 38; Section 5.7, Table 12)

Two embeddings that try to respect the statistics of the cover page, both with the auto-key
pairs of the paper. Rules fixed before the run:

  mixed  Writes bits only into pair types that already appear in both orders on the clean page
         (at least three occurrences). The list of these types is a key file shared with the
         receiver, as in Garg (2011).
  model  Model-based embedding (Sallee, 2004) on the same carriers: each written order is drawn
         with the probability that the pair type has on the clean page, so that each type keeps
         its proportions on average. This simulates an ideal coder: drawing orders at random with
         these probabilities is what decoding a random (encrypted) message with an arithmetic
         decoder does, and the capacity is the entropy of the drawn orders. The receiver needs the
         probabilities as part of the key. No real coder was implemented.

Payloads: 10, 25, 50 and 100% of each scheme's carriers in document order, on all 454 evaluation
pages (pages without carriers stay unchanged), and a fixed 16-byte message, which takes 144 bits
with the compact layout of Table 11, on the pages that can hold it, against plain pairwise
writing of the same 144 bits on the same pages.
Detectors: order consistency, W, SD, web norm and APCC with a multilayer perceptron over 20
attributes; thresholds, norms and training come only from the 194 calibration pages.

Usage: python careful_sender.py <pages_dir> <results_dir>
"""
import json
import math
import random
import statistics as st
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

import experiments as ex
import head_to_head as h2h
import htmlstego as hs

SEED = ex.SEED
RATES = [0.1, 0.25, 0.5, 1.0]
MSG_BITS = 8 * (2 + 16)  # 16-byte message, compact layout of Table 11 (header + ciphertext)
MIN_N = ex.MIN_TYPE_COUNT


def h(p):
    return 0.0 if p in (0.0, 1.0) else -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def carriers(tags, sl):
    """Carrier slots of the mixed pair types, with the clean share of bit 1 of their type."""
    c = ex.order_counts(tags, sl)
    p1 = {t: c1 / (c0 + c1) for t, (c0, c1) in c.items() if c0 and c1 and c0 + c1 >= MIN_N}
    return [(s, p1[ex.pair_type(s)]) for s in sl if ex.pair_type(s) in p1]


def write(tags, use, scheme, rnd):
    t2 = ex.copy_tags(tags)
    for s, p in use:
        bit = rnd.getrandbits(1) if scheme in ("mixed", "plain") else int(rnd.random() < p)
        hs.set_bit(t2[s.tag], s, bit)
    return t2


def until_bits(car, bits, scheme):
    """Carriers in document order until the scheme has written `bits` bits (None if too few)."""
    got = 0.0
    for k, (_, p) in enumerate(car):
        got += 1.0 if scheme == "mixed" else h(p)
        if got >= bits:
            return car[: k + 1]
    return None


def worker(args):
    path, norms = args
    tags = hs.start_tags(Path(path).read_text(encoding="utf-8"))
    sl = hs.slots(tags, "auto")
    car = carriers(tags, sl)
    rnd = random.Random(f"{SEED}-careful-{Path(path).name}")
    out = {"clean": h2h.page_stats(tags, norms), "slots": len(sl), "carriers": len(car),
           "cap_mixed": len(car), "cap_model": sum(h(p) for _, p in car)}
    changed = {}
    for scheme in ("mixed", "model"):
        for q in RATES:
            use = car[: int(q * len(car))]
            t2 = write(tags, use, scheme, rnd)
            out[f"{scheme}@{q}"] = h2h.page_stats(t2, norms)
            changed[f"{scheme}@{q}"] = sum(hs.read_bit(a, s) != hs.read_bit(b, s) for s in sl for a, b in [(tags[s.tag], t2[s.tag])])
        use = until_bits(car, MSG_BITS, scheme)
        if use is not None:
            out[f"{scheme}@msg"] = h2h.page_stats(write(tags, use, scheme, rnd), norms)
    if len(sl) >= MSG_BITS:
        out["plain@msg"] = h2h.page_stats(write(tags, [(s, 0.5) for s in sl[:MSG_BITS]], "plain", rnd), norms)
    out["changed"] = changed
    return Path(path).name, out


def evaluate(got, cal, ev, key):
    """AUC (with intervals) of the untrained detectors and of APCC-MLP-20 for one stego version."""
    cal = [n for n in cal if key in got[n]]
    ev = [n for n in ev if key in got[n]]
    res = {"pages": len(ev)}
    for det in ("OC", "W", "SD", "WN"):
        m = h2h.metrics([got[n]["clean"][det] for n in cal], [got[n][key][det] for n in cal],
                        [got[n]["clean"][det] for n in ev], [got[n][key][det] for n in ev])
        res[det] = {k: m[k] for k in ("auc", "lo", "hi", "tpr1", "fpr1")}
    occ = Counter()
    for n in cal:
        occ.update(got[n]["clean"]["occ"])
    top = [a for a, _ in occ.most_common(20)]
    Xc = [h2h.vec(got[n]["clean"]["APCC"], top) for n in cal]
    Xs = [h2h.vec(got[n][key]["APCC"], top) for n in cal]
    clf = h2h.classifiers()["MLP"]
    clf.fit(np.array(Xc + Xs, float), np.r_[np.zeros(len(Xc)), np.ones(len(Xs))])
    sc = lambda X: clf.predict_proba(np.array(X, float))[:, 1]
    m = h2h.metrics(sc(Xc), sc(Xs), sc([h2h.vec(got[n]["clean"]["APCC"], top) for n in ev]),
                    sc([h2h.vec(got[n][key]["APCC"], top) for n in ev]))
    res["APCC"] = {k: m[k] for k in ("auc", "lo", "hi", "tpr1", "fpr1")}
    return res


def main():
    pages_dir, res = Path(sys.argv[1]), Path(sys.argv[2])
    pages = sorted(pages_dir.glob("*.html"))
    rnd = random.Random(SEED)
    calib_idx = set(rnd.sample(range(len(pages)), k=round(0.3 * len(pages))))
    cal = [p for i, p in enumerate(pages) if i in calib_idx]
    ev = [p for i, p in enumerate(pages) if i not in calib_idx]
    order = defaultdict(lambda: [0, 0])
    for p in cal:
        tags = hs.start_tags(p.read_text(encoding="utf-8"))
        for s in hs.slots(tags, "auto"):
            order[ex.pair_type(s)][hs.read_bit(tags[s.tag], s)] += 1
    norms = {t: (0 if c0 >= c1 else 1) for t, (c0, c1) in order.items() if c0 + c1 >= 20}
    with ProcessPoolExecutor() as pool:
        got = dict(pool.map(worker, [(str(p), norms) for p in cal + ev], chunksize=2))
    cn, en = [p.name for p in cal], [p.name for p in ev]
    E = [got[n] for n in en]
    out = {"n_cal": len(cn), "n_eval": len(en), "msg_bits": MSG_BITS, "capacity": {}, "detection": {}}
    for scheme, key in (("pairwise", "slots"), ("mixed", "cap_mixed"), ("model", "cap_model")):
        v = [g[key] for g in E]
        out["capacity"][scheme] = {"median_bits": float(st.median(v)), "q1": float(np.percentile(v, 25)), "q3": float(np.percentile(v, 75)),
                                   "pages_zero": sum(x < 1 for x in v),
                                   "pages_hold_16B_compact": sum(x >= MSG_BITS for x in v),
                                   "pages_hold_16B_table2": sum(x >= 8 * hs.blob_size(16) for x in v)}
    out["capacity"]["median_changed_pairs_full"] = {s: float(st.median(g["changed"][f"{s}@1.0"] for g in E)) for s in ("mixed", "model")}
    keys = [f"{s}@{q}" for s in ("mixed", "model") for q in RATES] + ["mixed@msg", "model@msg", "plain@msg"]
    for key in keys:
        out["detection"][key] = evaluate(got, cn, en, key)
    # the fixed message: plain pairwise writing on exactly the pages where the careful schemes hold it
    for s in ("mixed", "model"):
        both = [n for n in en if f"{s}@msg" in got[n]]
        cal_b = [n for n in cn if f"{s}@msg" in got[n]]
        sub = {n: got[n] for n in both + cal_b}
        out["detection"][f"plain@msg_on_{s}_pages"] = evaluate(sub, cal_b, both, "plain@msg")
    res.mkdir(parents=True, exist_ok=True)
    (res / "careful_sender.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    for k, v in out["capacity"].items():
        print(k, v)
    for k, v in out["detection"].items():
        print(f"{k:28} pages {v['pages']:3} | " + " | ".join(f"{d} {v[d]['auc']:.3f} ({v[d]['lo']:.2f}-{v[d]['hi']:.2f})" for d in ("OC", "W", "SD", "WN", "APCC")))


if __name__ == "__main__":
    main()
