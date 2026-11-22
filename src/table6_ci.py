"""Bootstrap intervals for Table 6, from results/per_page.csv.

Usage: python src/table6_ci.py results
"""
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import extra_analyses as xa  # noqa: E402

res = Path(sys.argv[1])
rows = list(csv.DictReader(open(res / "per_page.csv", encoding="utf-8")))
out = {}
for stat in ("cons", "norm"):
    clean = [float(r[f"clean_{stat}"]) for r in rows]
    cols = [(f"{stat}_{x}", f"stego{x}_{stat}") for x in ("0.1", "0.25", "0.5", "1.0")] + [(f"{stat}_type", f"type_{stat}")]
    for name, col in cols:
        m = xa.boot_auc(clean, [float(r[col]) for r in rows])
        out[name] = [m["auc"], m["lo"], m["hi"]]
(res / "table6_ci.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
for k, v in out.items():
    print(k, " ".join(f"{x:.3f}" for x in v))
