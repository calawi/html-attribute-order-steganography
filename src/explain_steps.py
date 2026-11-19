"""Show, step by step, how a message is hidden in (or read from) an HTML page.

Hide and explain:   python explain_steps.py hide <page.html> <output.html> "<message>" <password>
Read and explain:   python explain_steps.py reveal <stego.html> <password>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import htmlstego as hs  # noqa: E402

LINE = "-" * 70


def hexs(b, n=16):
    s = b[:n].hex(" ")
    return s + (" ..." if len(b) > n else "")


def show_pairs(html, n=5, label="First carrier pairs in the page"):
    tags = hs.start_tags(html)
    sl = hs.slots(tags)
    print(f"{label}:")
    for s in sl[:n]:
        t = tags[s.tag]
        bit = hs.read_bit(t, s)
        order = f"{s.primary} before {s.secondary}" if bit else f"{s.secondary} before {s.primary}"
        print(f"   {t.text()[:70]:72s} -> {order:28s} = bit {bit}")
    return sl


def hide(page, out, message, password):
    html = Path(page).read_text(encoding="utf-8")
    print(LINE)
    print("STEP 1  The secret message")
    raw = message.encode("utf-8")
    print(f"   Text   : {message}")
    print(f"   Length : {len(raw)} bytes (each letter is 1 byte in UTF-8)")
    print(f"   Bytes  : {hexs(raw)}")

    print(LINE)
    print("STEP 2  Turn the password into an AES key (PBKDF2, 200,000 rounds)")
    salt, iv = hs.os.urandom(16), hs.os.urandom(16)
    key = hs._key(password, salt)
    print(f"   Random salt : {hexs(salt)}")
    print(f"   AES-256 key : {hexs(key)}   (32 bytes, never stored in the page)")

    print(LINE)
    print("STEP 3  Encrypt with AES-256-CBC")
    values = iter([salt, iv])  # use the same salt and IV that were shown above
    blob = hs.encrypt(message, password, rng=lambda n: next(values))
    ct = blob[32:]
    print(f"   Random IV   : {hexs(iv)}")
    print(f"   Padding     : {len(raw)} bytes padded to {len(ct)} bytes (AES works in 16-byte blocks)")
    print(f"   Ciphertext  : {hexs(ct)}   <- looks like random noise")

    print(LINE)
    print("STEP 4  Build the block that goes into the page")
    framed = len(blob).to_bytes(2, "big") + blob
    print(f"   2-byte length header ({len(blob)}) + 16-byte salt + 16-byte IV + {len(ct)}-byte ciphertext")
    print(f"   Total: {len(framed)} bytes = {len(framed) * 8} bits")
    bits = hs.to_bits(framed)
    print(f"   First 32 bits: {''.join(map(str, bits[:32]))} ...")

    print(LINE)
    print("STEP 5  Write one bit into each pair of attributes")
    sl = show_pairs(html, label="   Before (original page)")
    print(f"   The page has {len(sl)} pairs; the message uses the first {len(bits)}.")
    stego = hs.write_bits(html, bits)
    show_pairs(stego, label="   After (stego page)")
    swapped = sum(a != b for a, b in zip(hs.read_bits(html), hs.read_bits(stego)))
    Path(out).write_text(stego, encoding="utf-8")
    print(f"   {swapped} pairs were swapped; the others already had the right order.")
    print(f"   File size before {len(html.encode())} bytes, after {len(stego.encode())} bytes.")
    print(f"   Saved: {out}")
    print(LINE)


def reveal(stego_path, password):
    html = Path(stego_path).read_text(encoding="utf-8")
    print(LINE)
    print("STEP 1  Read the order of every attribute pair")
    sl = show_pairs(html)
    bits = hs.read_bits(html)
    print(f"   {len(bits)} bits read in total.")

    print(LINE)
    print("STEP 2  The first 16 bits are the length header")
    n = int.from_bytes(hs.from_bits(bits[:16]), "big")
    print(f"   {''.join(map(str, bits[:16]))} = {n} bytes of hidden data follow")
    if n < 48 or 16 + 8 * n > len(bits):
        print("   That length is impossible for this page: there is no hidden message here.")
        return
    blob = hs.from_bits(bits[16:16 + 8 * n])

    print(LINE)
    print("STEP 3  Split the hidden block")
    print(f"   Salt       : {hexs(blob[:16])}")
    print(f"   IV         : {hexs(blob[16:32])}")
    print(f"   Ciphertext : {hexs(blob[32:])}  ({len(blob) - 32} bytes)")

    print(LINE)
    print("STEP 4  Rebuild the key from the password and the salt, then decrypt")
    try:
        msg = hs.decrypt(blob, password)
        print(f"   Hidden message: {msg}")
    except Exception:
        print("   Decryption failed: the password is wrong (or the page was changed).")
    print(LINE)


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 5 and a[0] == "hide":
        hide(*a[1:])
    elif len(a) == 3 and a[0] == "reveal":
        reveal(*a[1:])
    else:
        print(__doc__)
