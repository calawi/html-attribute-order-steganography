"""Retest on fresh pages (review comments 17 and 30).

The code is unchanged from the main run. Key file and web norms come from the
original 194 calibration pages; the fresh pages (Tranco ranks 1,501 to 3,000)
were never used while building or fixing the tool.

Usage: python fresh_run.py <orig_pages_dir> <fresh_pages_dir> <results_dir>
"""
import json
import os
import random
import statistics as st
import sys
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

import re

import experiments as ex
import extra_analyses as xa
import htmlstego as hs

# The checking script (not the hiding tool) failed on pages that start with an XML
# declaration, which lxml refuses in a str. Strip it before the DOM comparison only;
# the same is done to the original and the stego page.
_XMLDECL = re.compile(r"^\s*<\?xml[^>]*\?>")
_dom = ex.dom_signature
ex.dom_signature = lambda h: _dom(_XMLDECL.sub("", h, count=1))


def main():
    orig, fresh, res = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    pages = sorted(orig.glob("*.html"))
    rnd = random.Random(ex.SEED)
    calib = set(rnd.sample(range(len(pages)), k=round(0.3 * len(pages))))
    cal = [p for i, p in enumerate(pages) if i in calib]
    tf, to = Counter(), defaultdict(lambda: [0, 0])
    for p in cal:
        tags = hs.start_tags(p.read_text(encoding="utf-8"))
        for s in hs.slots(tags, "auto"):
            tf[ex.pair_type(s)] += 1
            to[ex.pair_type(s)][hs.read_bit(tags[s.tag], s)] += 1
    key20 = [t for t, _ in tf.most_common(20)]
    norms = {t: (0 if c0 >= c1 else 1) for t, (c0, c1) in to.items() if c0 + c1 >= 20}

    fp = sorted(fresh.glob("*.html"))
    with ProcessPoolExecutor(max_workers=max(2, (os.cpu_count() or 4) - 1)) as exr:
        rows = list(exr.map(ex.analyse_page, [(str(p), key20, norms, True) for p in fp], chunksize=2))
    heavy = [r for r in rows if "ok_reveal" in r]
    S = {"pages": len(rows),
         "pages_with_xml_declaration": sum(bool(_XMLDECL.match(p.read_text(encoding="utf-8"))) for p in fp), "median_bytes": st.median(r["bytes"] for r in rows),
         "median_cap_auto": st.median(r["cap_auto"] for r in rows),
         "median_msg_auto": st.median(max(r["msg_auto"], 0) for r in rows),
         "share_hold_1B": sum(r["msg_auto"] >= 1 for r in rows) / len(rows),
         "share_hold_100B": sum(r["msg_auto"] >= 100 for r in rows) / len(rows),
         "pages_tested": len(heavy), "reveal_ok": sum(r["ok_reveal"] for r in heavy),
         "size_ok": sum(r["ok_size"] for r in heavy), "dom_ok": sum(r["ok_dom"] for r in heavy),
         "reveal_errors": dict(Counter(r.get("reveal_error") for r in heavy if not r["ok_reveal"])),
         "robustness": {n: sum(r.get(f"robust_{n}", False) for r in heavy) / len(heavy) for n in ex.TRANSFORMS}}
    neg = [r["clean_cons"] for r in rows]
    for rate in ex.RATES:
        S[f"auc_cons_{rate}"] = xa.boot_auc(neg, [r[f"stego{rate}_cons"] for r in rows])
    (res / "fresh_summary.json").write_text(json.dumps(S, indent=1), encoding="utf-8")
    keys = sorted({k for r in rows for k in r})
    with open(res / "fresh_per_page.csv", "w", encoding="utf-8") as fh:
        fh.write(",".join(keys) + "\n")
        for r in rows:
            fh.write(",".join(str(r.get(k, "")) for k in keys) + "\n")
    print(json.dumps(S, indent=1))


if __name__ == "__main__":
    main()
