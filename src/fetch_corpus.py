"""Build the test corpus: homepages of top-ranked websites (Tranco list).

Usage: python -I fetch_corpus.py <tranco_zip> <out_dir> [target_pages] [max_domains]
Saves each usable homepage as <rank>_<domain>.html and writes corpus_log.csv.
A page is kept if it is HTML, at least 5 KB, and has at least 50 start tags.
"""
import csv
import io
import re
import sys
import time
import zipfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

UA = "Mozilla/5.0 (compatible; html-stego-research/1.0)"
MAX_BYTES = 3_000_000
TIMEOUT = 12


def fetch(rank, domain):
    url = f"https://{domain}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            ctype = r.headers.get("Content-Type", "")
            if "html" not in ctype.lower():
                return rank, domain, None, f"not html ({ctype[:40]})"
            raw = r.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                return rank, domain, None, "too large"
            charset = r.headers.get_content_charset() or "utf-8"
            try:
                text = raw.decode(charset, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            ntags = len(re.findall(r"<[a-zA-Z][^\s/>]*", text))
            if len(raw) < 5000 or ntags < 50:
                return rank, domain, None, f"too small ({len(raw)} B, {ntags} tags)"
            return rank, domain, text, f"ok ({len(raw)} B, {ntags} tags)"
    except Exception as e:  # network errors are expected for many CDN/API domains
        return rank, domain, None, f"error: {type(e).__name__}"


def main():
    zpath, out = sys.argv[1], Path(sys.argv[2])
    target = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    max_domains = int(sys.argv[4]) if len(sys.argv) > 4 else 1500
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zpath) as z:
        name = z.namelist()[0]
        rows = list(csv.reader(io.TextIOWrapper(z.open(name), encoding="utf-8")))[:max_domains]
    kept, log = 0, []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = [ex.submit(fetch, int(r), d) for r, d in rows]
        for f in as_completed(futs):
            rank, domain, text, status = f.result()
            log.append((rank, domain, status))
            if text is not None:
                (out / f"{rank:05d}_{domain}.html").write_text(text, encoding="utf-8")
                kept += 1
    log.sort()
    with open(out.parent / "corpus_log.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rank", "domain", "status"])
        w.writerows(log)
    print(f"tried {len(rows)} domains, kept {kept} pages in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
