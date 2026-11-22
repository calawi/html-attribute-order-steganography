"""Head-to-head comparison of attribute-permutation detectors on the same pages.

Detectors (all scored so that a higher value means "more likely stego"):
  W      Polak & Kotulski (2010) as described in Sedeeq et al. (2017a): share of
         attribute pairs, per tag name, that occur in a non-predominant order.
  SD     Sedeeq et al. (2016), equations 2 to 5: square root of the sum, over all
         attributes, of the variance of the attribute's positions in tags with two
         or more attributes. The original method monitors one page over time; here
         it is used on single pages, as Sedeeq et al. (2017a) did.
  APCC   Sedeeq et al. (2017a): Attribute Position Changes Count (their Algorithm 1)
         as a feature vector over the K most frequent attributes, with the three
         classifiers they used (MLP, SVM, Naive Bayes).
  OC     order consistency (this paper)
  WN     web norm (this paper)

Protocol: calibration pages (194) fix thresholds, norms and the training sets;
the 454 evaluation pages are used only for testing. Stego pages come from two
embedding models, each at 10, 25, 50 and 100% of capacity with random bits:
  pair   this paper's pairwise attribute order (auto key)
  perm   permutation coding: a random permutation of all attributes of a tag
         (what Deogol/Huang-style schemes produce for a random message)

Usage: python head_to_head.py <pages_dir> <results_dir> [limit]
"""
import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
from scipy.stats import rankdata
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

import experiments as ex
import htmlstego as hs

SEED = ex.SEED
RATES = [0.1, 0.25, 0.5, 1.0]
KS = [5, 20]
BOOT = 1000

# --------------------------------------------------------------------- detector statistics

def stat_W(tags):
    cnt = defaultdict(lambda: [0, 0])
    for t in tags:
        n = len(t.names)
        if n < 2:
            continue
        head = t.head.lower()
        nm = t.names
        for i in range(n):
            for j in range(i + 1, n):
                a, b = nm[i], nm[j]
                key = (head, a, b) if a < b else (head, b, a)
                cnt[key][0 if a < b else 1] += 1
    total = sum(c0 + c1 for c0, c1 in cnt.values())
    if not total:
        return 0.0
    return 1.0 - sum(max(c0, c1) for c0, c1 in cnt.values()) / total


def stat_SD(tags):
    pos = defaultdict(list)
    for t in tags:
        if len(t.names) < 2:
            continue
        for k, a in enumerate(t.names):
            pos[a].append(k)
    return math.sqrt(sum(float(np.var(v)) for v in pos.values()))


def stat_APCC(tags):
    last, cnt = {}, Counter()
    for t in tags:
        if len(t.names) < 2:
            continue
        for k, a in enumerate(t.names):
            if a in last and last[a] != k:
                cnt[a] += 1
            last[a] = k
    return dict(cnt)


def occurrences(tags):
    c = Counter()
    for t in tags:
        if len(t.names) >= 2:
            c.update(t.names)
    return dict(c)

# --------------------------------------------------------------------- stego models

def stego_pair(tags, rate, rnd):
    t2 = ex.copy_tags(tags)
    sl = hs.slots(t2, "auto")
    for s in sl[: int(rate * len(sl))]:
        hs.set_bit(t2[s.tag], s, rnd.getrandbits(1))
    return t2


def stego_perm(tags, rate, rnd):
    t2 = ex.copy_tags(tags)
    eligible = [i for i, t in enumerate(t2) if len(t.names) >= 2]
    for i in rnd.sample(eligible, int(rate * len(eligible))):
        t = t2[i]
        order = list(range(len(t.names)))
        rnd.shuffle(order)
        t.tokens = [t.tokens[k] for k in order]
        t.names = [t.names[k] for k in order]
    return t2


MODELS = {"pair": stego_pair, "perm": stego_perm}


def page_stats(tags, norms):
    sl = hs.slots(tags, "auto")
    counts = ex.order_counts(tags, sl)
    return {"W": stat_W(tags), "SD": stat_SD(tags), "OC": ex.score_consistency(counts),
            "WN": ex.score_norm(counts, norms), "APCC": stat_APCC(tags), "occ": occurrences(tags)}


def worker(args):
    path, norms = args
    html = Path(path).read_text(encoding="utf-8")
    tags = hs.start_tags(html)
    rnd = random.Random(f"{SEED}-h2h-{Path(path).name}")
    out = {"clean": page_stats(tags, norms)}
    for model, fn in MODELS.items():
        for rate in RATES:
            out[f"{model}@{rate}"] = page_stats(fn(tags, rate, rnd), norms)
    return Path(path).name, out

# --------------------------------------------------------------------- evaluation helpers

def roc_auc(neg, pos):
    """AUC = probability that a stego page scores above a clean page (ties count half)."""
    neg, pos = np.asarray(neg, float), np.asarray(pos, float)
    r = rankdata(np.r_[neg, pos])
    return (r[len(neg):].sum() - len(pos) * (len(pos) + 1) / 2) / (len(neg) * len(pos))


def best_acc_threshold(neg, pos):
    vals = sorted(set(neg) | set(pos))
    best, bt = -1, 0
    for v in vals:
        acc = (sum(x <= v for x in neg) + sum(x > v for x in pos)) / (len(neg) + len(pos))
        if acc > best:
            best, bt = acc, v
    return bt


def metrics(cal_neg, cal_pos, ev_neg, ev_pos, labels_pred=None):
    ev_neg, ev_pos = np.asarray(ev_neg, float), np.asarray(ev_pos, float)
    auc = roc_auc(ev_neg, ev_pos)
    rs = np.random.RandomState(SEED)
    boots = []
    n = len(ev_neg)
    for _ in range(BOOT):
        idx = rs.randint(0, n, n)
        boots.append(roc_auc(ev_neg[idx], ev_pos[idx]))
    lo, hi = np.percentile(boots, [2.5, 97.5])
    thr = best_acc_threshold(list(cal_neg), list(cal_pos))
    acc = (np.sum(ev_neg <= thr) + np.sum(ev_pos > thr)) / (2 * n)
    thr1 = float(np.quantile(np.asarray(cal_neg, float), 0.99))
    return {"auc": float(auc), "lo": float(lo), "hi": float(hi), "acc": float(acc),
            "tpr1": float(np.mean(ev_pos > thr1)), "fpr1": float(np.mean(ev_neg > thr1))}


def classifiers():
    return {
        "MLP": make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(10,), max_iter=3000, random_state=SEED)),
        "SVM": make_pipeline(StandardScaler(), SVC(kernel="linear", random_state=SEED)),
        "NB": GaussianNB(),
    }


def vec(apcc, attrs):
    return [apcc.get(a, 0) for a in attrs]


def main():
    pages_dir, res = Path(sys.argv[1]), Path(sys.argv[2])
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else None
    pages = sorted(pages_dir.glob("*.html"))
    rnd = random.Random(SEED)
    calib_idx = set(rnd.sample(range(len(pages)), k=round(0.3 * len(pages))))
    cal = [p for i, p in enumerate(pages) if i in calib_idx]
    ev = [p for i, p in enumerate(pages) if i not in calib_idx]
    if limit:
        cal, ev = cal[: limit // 3], ev[:limit]
    # web norms from the calibration pages (same procedure as experiments.py)
    order = defaultdict(lambda: [0, 0])
    for p in cal:
        tags = hs.start_tags(p.read_text(encoding="utf-8"))
        for s in hs.slots(tags, "auto"):
            order[ex.pair_type(s)][hs.read_bit(tags[s.tag], s)] += 1
    norms = {t: (0 if c0 >= c1 else 1) for t, (c0, c1) in order.items() if c0 + c1 >= 20}
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=max(2, (os.cpu_count() or 4) - 1)) as exr:
        got = dict(exr.map(worker, [(str(p), norms) for p in cal + ev], chunksize=2))
    print(f"features for {len(got)} pages in {time.time() - t0:.0f}s | calibration {len(cal)} | evaluation {len(ev)}")
    cal_n, ev_n = [p.name for p in cal], [p.name for p in ev]

    # most frequent attributes in the calibration pages (feature space of APCC)
    occ = Counter()
    for n in cal_n:
        occ.update(got[n]["clean"]["occ"])
    top = {K: [a for a, _ in occ.most_common(K)] for K in KS}

    rows = []
    for key in [f"{m}@{r}" for m in MODELS for r in RATES]:
        model, rate = key.split("@")
        for det in ("W", "SD", "OC", "WN"):
            m = metrics([got[n]["clean"][det] for n in cal_n], [got[n][key][det] for n in cal_n],
                        [got[n]["clean"][det] for n in ev_n], [got[n][key][det] for n in ev_n])
            # share of stego pages that score above their own clean version (an ideal
            # case of the page-over-time monitoring the W and SD methods were made for)
            m["above_own"] = float(np.mean([got[n][key][det] > got[n]["clean"][det] for n in ev_n]))
            rows.append({"model": model, "rate": float(rate), "detector": det, **m})
        for K in KS:
            Xc = [vec(got[n]["clean"]["APCC"], top[K]) for n in cal_n]
            Xs = [vec(got[n][key]["APCC"], top[K]) for n in cal_n]
            Xtr, ytr = np.array(Xc + Xs, float), np.r_[np.zeros(len(Xc)), np.ones(len(Xs))]
            Ec = np.array([vec(got[n]["clean"]["APCC"], top[K]) for n in ev_n], float)
            Es = np.array([vec(got[n][key]["APCC"], top[K]) for n in ev_n], float)
            for cname, clf in classifiers().items():
                clf.fit(Xtr, ytr)
                sc = (lambda X: clf.decision_function(X)) if cname == "SVM" else (lambda X: clf.predict_proba(X)[:, 1])
                m = metrics(sc(Xtr[: len(Xc)]), sc(Xtr[len(Xc):]), sc(Ec), sc(Es))
                m["acc"] = float((np.sum(clf.predict(Ec) == 0) + np.sum(clf.predict(Es) == 1)) / (2 * len(ev_n)))
                rows.append({"model": model, "rate": float(rate), "detector": f"APCC-{cname}-K{K}", **m})
        print("done", key, flush=True)
    res.mkdir(parents=True, exist_ok=True)
    (res / "head_to_head.json").write_text(json.dumps({"rows": rows, "top_attributes": top, "n_cal": len(cal), "n_eval": len(ev),
                                                      "boot": BOOT, "seed": SEED}, indent=1), encoding="utf-8")
    with open(res / "head_to_head.csv", "w", encoding="utf-8") as fh:
        fh.write("model,rate,detector,auc,ci_lo,ci_hi,accuracy,tpr_at_cal_1pct,fpr_at_cal_1pct,above_own_clean_page\n")
        for r in rows:
            fh.write(f"{r['model']},{r['rate']},{r['detector']},{r['auc']:.4f},{r['lo']:.4f},{r['hi']:.4f},{r['acc']:.4f},{r['tpr1']:.4f},{r['fpr1']:.4f},{('%.4f' % r['above_own']) if 'above_own' in r else ''}\n")
    print("saved", len(rows), "rows")


if __name__ == "__main__":
    main()
