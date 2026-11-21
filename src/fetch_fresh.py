"""Fetch a second, disjoint sample for retesting: Tranco ranks 1,501 to 3,000.
Same rules as fetch_corpus.py (one request per homepage, no login, same filters).
Usage: python -I fetch_fresh.py <tranco_zip> <out_dir>
"""
import csv, io, sys, time, zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import fetch_corpus as fc

zpath, out = sys.argv[1], Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(zpath) as z:
    rows = list(csv.reader(io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8")))[1500:3000]
kept, log, t0 = 0, [], time.time()
with ThreadPoolExecutor(max_workers=32) as ex:
    futs = [ex.submit(fc.fetch, int(r), d) for r, d in rows]
    for f in as_completed(futs):
        rank, domain, text, status = f.result()
        log.append((rank, domain, status))
        if text is not None:
            (out / f"{rank:05d}_{domain}.html").write_text(text, encoding="utf-8")
            kept += 1
log.sort()
with open(out.parent / "fresh_log.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["rank", "domain", "status"]); w.writerows(log)
print(f"tried {len(rows)}, kept {kept} in {time.time() - t0:.0f}s")
