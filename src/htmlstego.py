"""HTML attribute-order steganography with AES encryption.

Implements the pairwise attribute-order technique of Garg (2011), with AES in
place of the Playfair cipher:

  1. The secret message is encrypted with AES-256-CBC (PKCS7 padding).
     The key comes from a password through PBKDF2-HMAC-SHA256.
  2. The ciphertext (with a 2-byte length header) is turned into bits.
  3. Each usable pair of attributes in an HTML start tag carries one bit:
     primary attribute before secondary = 1, otherwise 0.
     The page renders the same, because attribute order has no effect on
     the DOM that a browser builds.
  4. The receiver scans the stego page with the same key (list of attribute
     pairs), reads the bits, and decrypts them with the password.

Two kinds of key are supported:
  * a key file: an ordered list of (primary, secondary) attribute pairs, as in
    Garg (2011);
  * "auto": in every tag the attribute names are sorted alphabetically and
    split into consecutive disjoint pairs. The receiver can rebuild this key
    from the stego page, because reordering does not change which attributes
    a tag has.
Swapping two attributes never changes the file size, because only the
attribute tokens move; the separators between them stay where they were.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from html.parser import HTMLParser

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LEN, IV_LEN, KDF_ITER = 16, 16, 200_000
HEADER_BYTES = 2  # length of the encrypted blob, big endian

# ---------------------------------------------------------------- crypto

def _key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITER)
    return kdf.derive(password.encode("utf-8"))


def encrypt(message: str, password: str, rng=os.urandom) -> bytes:
    salt, iv = rng(SALT_LEN), rng(IV_LEN)
    padder = padding.PKCS7(128).padder()
    data = padder.update(message.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(_key(password, salt)), modes.CBC(iv)).encryptor()
    return salt + iv + enc.update(data) + enc.finalize()


def decrypt(blob: bytes, password: str) -> str:
    salt, iv, ct = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + IV_LEN], blob[SALT_LEN + IV_LEN:]
    dec = Cipher(algorithms.AES(_key(password, salt)), modes.CBC(iv)).decryptor()
    data = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(data) + unpadder.finalize()).decode("utf-8")


def blob_size(message_bytes: int) -> int:
    """Bytes needed on the page for a message of this many UTF-8 bytes."""
    return HEADER_BYTES + SALT_LEN + IV_LEN + 16 * (message_bytes // 16 + 1)


def max_message_bytes(capacity_bits: int) -> int:
    room = capacity_bits // 8 - HEADER_BYTES - SALT_LEN - IV_LEN
    if room < 16:
        return -1
    return 16 * (room // 16) - 1

# ---------------------------------------------------------------- parsing

ATTR_RE = re.compile(r"""([^\s"'>/=]+)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?""")


@dataclass
class Tag:
    start: int            # offset of "<" in the document
    end: int              # offset after ">"
    head: str             # "<tagname"
    seps: list            # separators before each token, then the tail
    tokens: list          # raw attribute tokens, e.g. 'href="x"'
    names: list           # lower-case attribute names

    def text(self) -> str:
        out = [self.head]
        for s, t in zip(self.seps, self.tokens):
            out.append(s)
            out.append(t)
        out.append(self.seps[-1])
        return "".join(out)


class _StartTags(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=False)
        self.html = html
        self.line_starts = [0]
        for m in re.finditer("\n", html):
            self.line_starts.append(m.end())
        self.tags: list[Tag] = []

    def _offset(self):
        line, col = self.getpos()
        return self.line_starts[line - 1] + col

    def handle_starttag(self, tag, attrs):
        raw = self.get_starttag_text()
        start = self._offset()
        if raw is None or self.html[start:start + len(raw)] != raw:
            return
        parsed = _split_tag(raw)
        if parsed is None:
            return
        head, seps, tokens, names = parsed
        self.tags.append(Tag(start, start + len(raw), head, seps, tokens, names))

    handle_startendtag = handle_starttag


def _split_tag(raw: str):
    m = re.match(r"<[^\s/>]+", raw)
    if not m:
        return None
    head, pos, body_end = m.group(0), m.end(), len(raw) - 1  # before ">"
    if raw.endswith("/>"):
        body_end = len(raw) - 2
    seps, tokens, names = [], [], []
    for a in ATTR_RE.finditer(raw, pos, body_end):
        gap = raw[pos:a.start()]
        if gap.strip() not in ("", "/"):
            return None  # something unusual inside the tag; leave it alone
        if not gap:  # attributes must be separated by whitespace
            return None
        seps.append(gap)
        tokens.append(a.group(0))
        names.append(a.group(1).lower())
        pos = a.end()
    seps.append(raw[pos:])
    if len(set(names)) != len(names):
        return None  # duplicate attribute names: order would matter to the DOM
    if seps[-1].startswith("/") and any(_unquoted(t) for t in tokens):
        # In "<x a=1 b="2"/>" moving a=1 to the end would give "a=1/>",
        # and the slash would become part of the value. Leave such tags alone.
        return None
    if any(_unquoted(t) and t.endswith("/") for t in tokens):
        # "href=https://x.org/" moved to the end would give ".../>", which
        # looks like a self-closing tag to the reader. Leave such tags alone.
        return None
    return head, seps, tokens, names


def _unquoted(token: str) -> bool:
    if "=" not in token:
        return False
    value = token.split("=", 1)[1].lstrip()
    return not value.startswith(('"', "'"))


def start_tags(html: str) -> list[Tag]:
    p = _StartTags(html)
    p.feed(html)
    p.close()
    return p.tags

# ---------------------------------------------------------------- slots

@dataclass
class Slot:
    tag: int          # index in the tag list
    primary: str
    secondary: str


def slots(tags: list[Tag], key="auto") -> list[Slot]:
    """Carrier positions in document order. Each slot holds one bit."""
    out = []
    for ti, t in enumerate(tags):
        present = set(t.names)
        if key == "auto":
            names = sorted(present)
            for i in range(0, len(names) - 1, 2):
                out.append(Slot(ti, names[i], names[i + 1]))
        else:
            used = set()
            for p, s in key:
                if p in present and s in present and p not in used and s not in used:
                    out.append(Slot(ti, p, s))
                    used.update((p, s))
    return out


def read_bit(tag: Tag, slot: Slot) -> int:
    return 1 if tag.names.index(slot.primary) < tag.names.index(slot.secondary) else 0


def set_bit(tag: Tag, slot: Slot, bit: int) -> None:
    if read_bit(tag, slot) != bit:
        i, j = tag.names.index(slot.primary), tag.names.index(slot.secondary)
        tag.tokens[i], tag.tokens[j] = tag.tokens[j], tag.tokens[i]
        tag.names[i], tag.names[j] = tag.names[j], tag.names[i]


def capacity(html: str, key="auto") -> int:
    return len(slots(start_tags(html), key))

# ---------------------------------------------------------------- bits

def to_bits(data: bytes) -> list[int]:
    return [(b >> (7 - k)) & 1 for b in data for k in range(8)]


def from_bits(bits: list[int]) -> bytes:
    return bytes(sum(bit << (7 - k) for k, bit in enumerate(bits[i:i + 8])) for i in range(0, len(bits) - 7, 8))


def write_bits(html: str, bits: list[int], key="auto") -> str:
    tags = start_tags(html)
    sl = slots(tags, key)
    if len(bits) > len(sl):
        raise ValueError(f"message needs {len(bits)} bits, page holds {len(sl)}")
    for b, s in zip(bits, sl):
        set_bit(tags[s.tag], s, b)
    out, pos = [], 0
    for t in tags:
        out.append(html[pos:t.start])
        out.append(t.text())
        pos = t.end
    out.append(html[pos:])
    return "".join(out)


def read_bits(html: str, n: int | None = None, key="auto") -> list[int]:
    tags = start_tags(html)
    sl = slots(tags, key)
    sl = sl if n is None else sl[:n]
    return [read_bit(tags[s.tag], s) for s in sl]

# ---------------------------------------------------------------- public API

def hide(html: str, message: str, password: str, key="auto", rng=os.urandom) -> str:
    """rng is only replaced in experiments, to make runs reproducible."""
    blob = encrypt(message, password, rng)
    framed = len(blob).to_bytes(HEADER_BYTES, "big") + blob
    return write_bits(html, to_bits(framed), key)


def reveal(html: str, password: str, key="auto") -> str:
    bits = read_bits(html, key=key)
    n = int.from_bytes(from_bits(bits[:8 * HEADER_BYTES]), "big")
    need = 8 * (HEADER_BYTES + n)
    if n < SALT_LEN + IV_LEN + 16 or need > len(bits):
        raise ValueError("no hidden message found")
    return decrypt(from_bits(bits[8 * HEADER_BYTES:need]), password)


def load_key(path: str) -> list[tuple[str, str]]:
    pairs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                p, s = line.split(",")
                pairs.append((p.strip().lower(), s.strip().lower()))
    return pairs
