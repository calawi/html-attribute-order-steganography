# HTML attribute-order steganography: code and results

Code and experimental results for the paper:

> Hanafi, A. A. (2026). *Hiding Encrypted Text in the Order of HTML Attributes:
> Capacity, Robustness and Detectability on Popular Web Pages.*

The method hides data in the order of the attributes inside HTML tags, after
encrypting the message with AES. Because a browser builds the same page no matter
how the attributes are ordered, the change is invisible on screen and the file
size does not change. This repository lets anyone reproduce the paper's
measurements of capacity, robustness and detectability.

## What is here

```
src/
  htmlstego.py       the method: AES encryption + attribute-order hiding
  hide_text_app.py   a small app (window + command line) to hide/reveal text
  explain_steps.py   prints each step of hiding and revealing, for teaching
  fetch_corpus.py    downloads homepages of top Tranco sites into data/pages/
  experiments.py     runs the capacity, correctness, robustness, detection tests
  figures.py         draws the two figures from the results
results/
  per_page.csv       one row per evaluation page (all per-page measurements)
  summary.json       the summary statistics reported in the paper
  key_top20.txt      the 20 most frequent attribute pairs (the key file)
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

# 1. Build the corpus (downloads homepages into data/pages/)
#    Pass the Tranco top-1m CSV zip, which you can get from https://tranco-list.eu
python -I src/fetch_corpus.py tranco_top1m.zip data/pages 300 1500

# 2. Run all experiments (writes results/summary.json and results/per_page.csv)
python -I src/experiments.py data/pages results

# 3. Draw the figures
python src/figures.py results
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
