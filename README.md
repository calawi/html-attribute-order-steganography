# HTML attribute-order steganography: code and results

Code and experimental results for the paper:

> Hanafi, A. A. (2026). *Hiding Encrypted Text in the Order of HTML Attributes:
> Capacity, Robustness and Detectability on Popular Homepages.*

The embedding is the pairwise attribute-order method of Garg (2011), *A Novel Text
Steganography Technique Based on Html Documents*, IJAST 35, 129-138. This repository
replaces its Playfair cipher with AES and evaluates it on real pages.

The method hides data in the order of the attributes inside HTML tags, after
encrypting the message with AES. Because a browser builds the same page no matter
how the attributes are ordered, the change is invisible on screen and the file
size does not change. This repository lets anyone reproduce the paper's
measurements of capacity, robustness and detectability.

## What is here

```
src/
  htmlstego.py       the method: AES encryption + attribute-order hiding
  test_basic.py      12 quick checks of the tool, no downloads needed
  hide_text_app.py   a small app (window + command line) to hide/reveal text
  explain_steps.py   prints each step of hiding and revealing, for teaching
  fetch_corpus.py    downloads homepages of top Tranco sites into data/pages/
  experiments.py     runs the capacity, correctness, robustness, detection tests
  figures.py         draws the two figures from the results
  head_to_head.py    compares the detectors of earlier work on the same pages (Tables 8, 9)
  extra_analyses.py  real messages with and without encryption (Table 10), detection on
                     pages that can hold a message, bit survival and failure causes
  table6_ci.py       bootstrap intervals for Table 6
  fetch_fresh.py     downloads the fresh retest sample (Tranco ranks 1,501 to 3,000)
  fresh_run.py       reruns the unchanged code on the fresh sample
results/
  per_page.csv       one row per evaluation page (all per-page measurements)
  summary.json       the summary statistics reported in the paper
  key_top20.txt      the 20 most frequent attribute pairs (the key file)
  head_to_head.*     detector comparison with bootstrap intervals
  table6_ci.json     bootstrap intervals for Table 6
  extra.json         results of extra_analyses.py
  fresh_summary.json, fresh_per_page.csv   results of the fresh retest
  fig1_capacity.png  Figure 1
  fig2_detectability.png  Figure 2
```

The 648 web pages themselves are **not** included, because they are copyrighted
content from real websites. `fetch_corpus.py` rebuilds an equivalent corpus from
the public Tranco list, and `results/` contains the derived statistics, which
are what the paper reports.

## Reproduce the results

```bash
pip install -r requirements.txt

# 0. Check that the tool works
python src/test_basic.py

# 1. Build the corpus (downloads homepages into data/pages/)
#    Pass the Tranco top-1m CSV zip, which you can get from https://tranco-list.eu
python src/fetch_corpus.py tranco_top1m.zip data/pages 300 1500

# 2. Run all experiments (writes results/summary.json and results/per_page.csv)
python src/experiments.py data/pages results

# 3. Draw the figures
python src/figures.py results

# 4. Detector comparison and extra analyses
python src/table6_ci.py results
python src/head_to_head.py data/pages results
python src/extra_analyses.py data/pages results

# 5. Retest on fresh pages
python src/fetch_fresh.py tranco_top1m.zip data_fresh/pages
python src/fresh_run.py data/pages data_fresh/pages results
```

A fixed random seed makes every run reproducible; two full runs produced
identical numbers.

## Try the tool

```bash
# as a window app
python src/hide_text_app.py

# or from the command line
python src/hide_text_app.py capacity page.html
python src/hide_text_app.py hide page.html out.html "secret message" mypassword
python src/hide_text_app.py reveal out.html mypassword
```

## Note on use

This code is for research and education. As the paper shows, the hidden data can
be detected with a simple statistical test and is destroyed by common tools that
sort or repair HTML, so the method is not suitable for protecting real secrets.

## License

MIT License. See [LICENSE](LICENSE).
