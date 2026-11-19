"""Experiments for the HTML attribute-order steganography paper.

Run from the code folder:  python experiments.py <pages_dir> <results_dir>

E1  Corpus description
E2  Capacity (auto key, top-20 key file, per-type embedding, permutation bound)
E3  Correctness: full hide/reveal with AES on every page, file size, DOM identity
E4  Robustness: does the hidden data survive common HTML processing?
E5  Detectability: two simple detectors (within-page order consistency and
    deviation from web-wide order norms) against clean and stego pages
"""
from __future__ import annotations

import json
import math
import os
import random
import statistics as st
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import htmlstego as hs

SEED = 20261117
RATES = [0.1, 0.25, 0.5, 1.0]
MIN_TYPE_COUNT = 3

# ------------------------------------------------------------------ helpers

def copy_tags(tags):
    return [hs.Tag(t.start, t.end, t.head, list(t.seps), list(t.tokens), list(t.names)) for t in tags]


def serialize(html, tags):
    out, pos = [], 0
    for t in tags:
        out.append(html[pos:t.start])
        out.append(t.text())
        pos = t.end
    out.append(html[pos:])
    return "".join(out)


def pair_type(slot):
    return (slot.primary, slot.secondary)


def order_counts(tags, sl):
    """per pair type: [count of bit 0, count of bit 1]"""
    c = defaultdict(lambda: [0, 0])
    for s in sl:
        c[pair_type(s)][hs.read_bit(tags[s.tag], s)] += 1
    return c


def score_consistency(counts):
    """Weighted share of minority order within the page (0 = fully consistent)."""
    num = den = 0
    for (c0, c1) in counts.values():
        n = c0 + c1
        if n >= MIN_TYPE_COUNT:
            num += min(c0, c1)
            den += n
    return num / den if den else 0.0


def score_norm(counts, norms):
    """Share of carrier pairs whose order disagrees with the web-wide majority."""
    num = den = 0
    for t, (c0, c1) in counts.items():
        if t in norms:
            major = norms[t]
            num += c1 if major == 0 else c0
            den += c0 + c1
    return num / den if den else 0.0


def auc(neg, pos):
    """Probability that a random stego page scores higher than a random clean page."""
    allv = sorted([(v, 0) for v in neg] + [(v, 1) for v in pos])
    ranks, i = {}, 0
    rank_sum = 0.0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        avg = (i + j + 1) / 2
        for k in range(i, j):
            if allv[k][1] == 1:
                rank_sum += avg
        i = j
    n1, n0 = len(pos), len(neg)
    return (rank_sum - n1 * (n1 + 1) / 2) / (n1 * n0) if n1 and n0 else float("nan")


def tpr_at_fpr(neg, pos, fpr=0.01):
    thr = sorted(neg)[min(len(neg) - 1, int(math.ceil((1 - fpr) * len(neg))) - 1)]
    return sum(v > thr for v in pos) / len(pos)

# ------------------------------------------------------------------ per page work

def analyse_page(args):
    path, key20, norms, do_heavy = args
    html = Path(path).read_text(encoding="utf-8")
    rnd = random.Random(f"{SEED}-{Path(path).name}")
    tags = hs.start_tags(html)
    sl = hs.slots(tags, "auto")
    sl20 = hs.slots(tags, key20)
    natt = sum(len(t.names) for t in tags)
    types = sorted({pair_type(s) for s in sl})
    perm_bits = sum(math.log2(math.factorial(len(t.names))) for t in tags)
    r = {
        "page": Path(path).name,
        "bytes": len(html.encode("utf-8")),
        "start_tags": len(tags),
        "tags_2plus_attrs": sum(1 for t in tags if len(t.names) >= 2),
        "attributes": natt,
        "cap_auto": len(sl),
        "cap_key20": len(sl20),
        "cap_type": len(types),
        "cap_perm": round(perm_bits, 1),
        "msg_auto": hs.max_message_bytes(len(sl)),
        "msg_key20": hs.max_message_bytes(len(sl20)),
    }
    # ---- detectability scores (no serialisation needed)
    clean_counts = order_counts(tags, sl)
    r["clean_cons"] = score_consistency(clean_counts)
    r["clean_norm"] = score_norm(clean_counts, norms)
    for rate in RATES:
        t2 = copy_tags(tags)
        n = int(rate * len(sl))
        for s in sl[:n]:
            hs.set_bit(t2[s.tag], s, rnd.getrandbits(1))
        c = order_counts(t2, sl)
        r[f"stego{rate}_cons"] = score_consistency(c)
        r[f"stego{rate}_norm"] = score_norm(c, norms)
    # per-type embedding: one bit per pair type, all occurrences share the order
    t2 = copy_tags(tags)
    tbits = {t: rnd.getrandbits(1) for t in types}
    for s in sl:
        hs.set_bit(t2[s.tag], s, tbits[pair_type(s)])
    c = order_counts(t2, sl)
    r["type_cons"] = score_consistency(c)
    r["type_norm"] = score_norm(c, norms)

    if not do_heavy:
        return r
    # ---- correctness with real AES at full capacity
    mb = r["msg_auto"]
    if mb >= 1:
        msg = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(mb))
        t0 = time.perf_counter()
        stego = hs.hide(html, msg, "test-password", rng=rnd.randbytes)
        t1 = time.perf_counter()
        try:
            back = hs.reveal(stego, "test-password")
        except Exception as e:
            back = None
            r["reveal_error"] = type(e).__name__
            Path(path).with_suffix(".failed_stego.txt").write_text(stego, encoding="utf-8")
        t2_ = time.perf_counter()
        r["ok_reveal"] = back == msg
        r["ok_size"] = len(stego.encode("utf-8")) == r["bytes"]
        r["ok_dom"] = dom_signature(html) == dom_signature(stego)
        r["changed_pairs"] = sum(a != b for a, b in zip(hs.read_bits(html), hs.read_bits(stego)))
        r["t_hide"] = t1 - t0
        r["t_reveal"] = t2_ - t1
        # embedding only (no key derivation): time to write random bits
        bits = [rnd.getrandbits(1) for _ in range(len(sl))]
        t0 = time.perf_counter()
        hs.write_bits(html, bits)
        r["t_embed_only"] = time.perf_counter() - t0
        # ---- robustness: compare extracted bits with embedded bits
        n_bits = 8 * hs.blob_size(mb)
        want = hs.read_bits(stego, n_bits)
        for name, fn in TRANSFORMS.items():
            try:
                out = fn(stego)
                got = hs.read_bits(out, n_bits)
                r[f"robust_{name}"] = got == want
            except Exception as e:  # a transform that crashes counts as failure
                r[f"robust_{name}"] = False
                r[f"robust_{name}_err"] = type(e).__name__
    return r


def dom_signature(html):
    import lxml.html
    root = lxml.html.document_fromstring(html)
    return [(e.tag, tuple(sorted(e.attrib.items())), (e.text or ""), (e.tail or ""))
            for e in root.iter() if isinstance(e.tag, str)]


def _lxml(h):
    import lxml.html
    return lxml.html.tostring(lxml.html.document_fromstring(h), encoding="unicode")


def _bs4(h):
    from bs4 import BeautifulSoup
    return str(BeautifulSoup(h, "html.parser"))


def _html5lib(h, alpha=False):
    import html5lib
    from html5lib.serializer import HTMLSerializer
    walker = html5lib.getTreeWalker("etree")
    tree = html5lib.parse(h)
    s = HTMLSerializer(quote_attr_values="always", omit_optional_tags=False, alphabetical_attributes=alpha)
    return s.render(walker(tree))


def _minify(h):
    import minify_html
    return minify_html.minify(h)


TRANSFORMS = {
    "lxml_reserialize": _lxml,
    "bs4_reserialize": _bs4,
    "html5lib_reserialize": _html5lib,
    "minify_html": _minify,
    "html5lib_sorted_attributes": lambda h: _html5lib(h, alpha=True),
}

# ------------------------------------------------------------------ main

def main():
    pages_dir, res = Path(sys.argv[1]), Path(sys.argv[2])
    res.mkdir(parents=True, exist_ok=True)
    pages = sorted(pages_dir.glob("*.html"))
    rnd = random.Random(SEED)
    calib = set(rnd.sample(range(len(pages)), k=round(0.3 * len(pages))))
    cal_pages = [p for i, p in enumerate(pages) if i in calib]
    ev_pages = [p for i, p in enumerate(pages) if i not in calib]

    # ---- calibration: top-20 key and web-wide order norms
    type_freq, type_order = Counter(), defaultdict(lambda: [0, 0])
    for p in cal_pages:
        h = p.read_text(encoding="utf-8")
        tags = hs.start_tags(h)
        for s in hs.slots(tags, "auto"):
            type_freq[pair_type(s)] += 1
            type_order[pair_type(s)][hs.read_bit(tags[s.tag], s)] += 1
    key20 = [t for t, _ in type_freq.most_common(20)]
    norms = {t: (0 if c0 >= c1 else 1) for t, (c0, c1) in type_order.items() if c0 + c1 >= 20}
    with open(res / "key_top20.txt", "w", encoding="utf-8") as fh:
        fh.write("# primary,secondary  (20 most frequent attribute pairs in the calibration pages)\n")
        for p, s in key20:
            fh.write(f"{p},{s}\n")
    norm_rows = sorted(((t, c0, c1) for t, (c0, c1) in type_order.items() if c0 + c1 >= 20),
                       key=lambda x: -(x[1] + x[2]))

    # ---- evaluation pages
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=max(2, (os.cpu_count() or 4) - 1)) as ex:
        rows = list(ex.map(analyse_page, [(str(p), key20, norms, True) for p in ev_pages], chunksize=2))
    elapsed = time.time() - t0

    # ---- summaries
    def q(vals):
        vals = sorted(vals)
        return {"median": st.median(vals), "q1": vals[len(vals) // 4], "q3": vals[(3 * len(vals)) // 4],
                "min": vals[0], "max": vals[-1], "mean": st.mean(vals)}

    S = {"n_pages_total": len(pages), "n_calibration": len(cal_pages), "n_evaluation": len(rows),
         "elapsed_s": round(elapsed), "seed": SEED}
    S["corpus"] = {k: q([r[k] for r in rows]) for k in ["bytes", "start_tags", "tags_2plus_attrs", "attributes"]}
    S["capacity_bits"] = {k: q([r[k] for r in rows]) for k in ["cap_auto", "cap_key20", "cap_type", "cap_perm"]}
    S["bits_per_kb_auto"] = q([1000 * r["cap_auto"] / r["bytes"] for r in rows])
    S["max_message_bytes"] = {k: q([max(r[k], 0) for r in rows]) for k in ["msg_auto", "msg_key20"]}
    S["share_pages_holding"] = {
        f"{n}B_{k}": sum(r[k] >= n for r in rows) / len(rows) for n in (1, 100, 500, 1000, 5000)
        for k in ("msg_auto", "msg_key20")}
    heavy = [r for r in rows if "ok_reveal" in r]
    S["correctness"] = {"pages_tested": len(heavy),
                        "reveal_ok": sum(r["ok_reveal"] for r in heavy),
                        "size_unchanged": sum(r["ok_size"] for r in heavy),
                        "dom_identical": sum(r["ok_dom"] for r in heavy),
                        "share_pairs_swapped": q([r["changed_pairs"] / r["cap_auto"] for r in heavy]),
                        "t_hide_s": q([r["t_hide"] for r in heavy]),
                        "t_reveal_s": q([r["t_reveal"] for r in heavy]),
                        "t_embed_only_s": q([r["t_embed_only"] for r in heavy])}
    S["robustness"] = {name: sum(r.get(f"robust_{name}", False) for r in heavy) / len(heavy) for name in TRANSFORMS}
    S["robustness_errors"] = Counter(r[k] for r in heavy for k in r if k.endswith("_err"))
    det = {}
    for stat in ("cons", "norm"):
        neg = [r[f"clean_{stat}"] for r in rows]
        for rate in RATES:
            pos = [r[f"stego{rate}_{stat}"] for r in rows]
            det[f"{stat}_rate{rate}"] = {"auc": auc(neg, pos), "tpr_at_fpr1": tpr_at_fpr(neg, pos)}
        pos = [r[f"type_{stat}"] for r in rows]
        det[f"{stat}_per_type"] = {"auc": auc(neg, pos), "tpr_at_fpr1": tpr_at_fpr(neg, pos)}
    S["detectability"] = det
    S["clean_scores"] = {s: q([r[f"clean_{s}"] for r in rows]) for s in ("cons", "norm")}
    S["top_pairs"] = [{"pair": f"{p}/{s}", "count": type_freq[(p, s)]} for p, s in key20]
    S["order_norms_top15"] = [{"pair": f"{t[0]}/{t[1]}", "primary_first": c1, "secondary_first": c0,
                               "majority_share": round(max(c0, c1) / (c0 + c1), 3)} for t, c0, c1 in norm_rows[:15]]

    (res / "summary.json").write_text(json.dumps(S, indent=2, default=str), encoding="utf-8")
    keys = sorted({k for r in rows for k in r})
    with open(res / "per_page.csv", "w", encoding="utf-8") as fh:
        fh.write(",".join(keys) + "\n")
        for r in rows:
            fh.write(",".join(str(r.get(k, "")) for k in keys) + "\n")
    print(json.dumps(S, indent=1, default=str)[:6000])


if __name__ == "__main__":
    main()
