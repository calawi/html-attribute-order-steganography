"""Quick checks of the hiding tool. Run:  python src/test_basic.py   (about 10 seconds)

No web pages or downloads are needed; a small page is built inside the script.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import htmlstego as hs  # noqa: E402

PAGE = ("<!doctype html><html lang='en' dir='ltr'><head><title>Test</title></head><body>"
        + "".join(f'<a href="/p{i}" class="nav" id="a{i}" title="Page {i}">link</a>\n'
                  f'<img src="i{i}.png" alt="Image {i}" width="10" height="20" class="pic" loading="lazy">\n'
                  for i in range(200)) + "</body></html>")
MESSAGE = "Meet at the old market at nine. Salaan! مرحبا"
PASSWORD = "correct horse"
passed = failed = 0


def check(name, ok):
    global passed, failed
    print(("PASS  " if ok else "FAIL  ") + name)
    passed, failed = passed + ok, failed + (not ok)


def raises(fn, *a):
    try:
        fn(*a)
        return False
    except Exception:
        return True


def dom(html):
    import lxml.html
    return [(e.tag, sorted(e.attrib.items()), e.text, e.tail) for e in lxml.html.document_fromstring(html).iter()]


stego = hs.hide(PAGE, MESSAGE, PASSWORD)
check("message comes back exactly (with accents and Arabic)", hs.reveal(stego, PASSWORD) == MESSAGE)
check("the page really changed", stego != PAGE)
check("file size is exactly the same", len(stego.encode()) == len(PAGE.encode()))
check("lxml builds the same document", dom(stego) == dom(PAGE))
check("the message text is not readable in the page", MESSAGE not in stego and "market" not in stego)
check("the same message hidden twice gives different pages (random salt and IV)", hs.hide(PAGE, MESSAGE, PASSWORD) != stego)
check("a page without a message reports an error", raises(hs.reveal, "<p>hello</p>", PASSWORD))
check("a message that is too long is refused", raises(hs.hide, PAGE, "x" * 5000, PASSWORD))

# A wrong password must never give the message. CBC padding catches most wrong
# passwords but not all of them, so "error or different text" is the real promise.
wrong = []
for k in range(20):
    try:
        wrong.append(hs.reveal(stego, f"wrong {k}"))
    except Exception:
        wrong.append(None)
check(f"20 wrong passwords never reveal the message ({sum(w is None for w in wrong)} gave an error)", MESSAGE not in wrong)

key = [("href", "class"), ("src", "alt"), ("width", "height"), ("id", "title")]
check("the key-file mode also works", hs.reveal(hs.hide(PAGE, "short", PASSWORD, key), PASSWORD, key) == "short")
check("AES blocks: 1 to 15 bytes need 50 bytes, 16 bytes need 66", [hs.blob_size(n) for n in (1, 15, 16)] == [50, 50, 66])
check("unsafe tags are skipped (duplicate attribute, unquoted value before />)",
      hs.capacity('<a href="x" href="y" id="z">') == 0 and hs.capacity('<path fill=#fff d="m0"/>') == 0)
print(f"\n{passed} passed, {failed} failed")
sys.exit(failed > 0)
