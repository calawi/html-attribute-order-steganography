"""Hide encrypted text inside an HTML web page (attribute-order steganography).

Window app:      python hide_text_app.py
Command line:    python hide_text_app.py capacity <page.html>
                 python hide_text_app.py hide <page.html> <output.html> "<message>" <password>
                 python hide_text_app.py reveal <stego.html> <password>
  From a Notepad file:
                 python hide_text_app.py hide-file <page.html> <output.html> <secret.txt> <password>
                 python hide_text_app.py reveal-file <stego.html> <password> <recovered.txt>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import htmlstego as hs  # noqa: E402


def read(path):
    return Path(path).read_bytes().decode("utf-8")  # keeps the line endings of the page


def read_text_file(path):
    """Read a Notepad file: UTF-8 (with or without BOM), or the older Windows encoding."""
    data = Path(path).read_bytes()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("cp1252")
    return text.replace("\r\n", "\n")


def size_check(html, text):
    need = len(text.encode("utf-8"))
    room = hs.max_message_bytes(hs.capacity(html))
    if need <= room:
        return None
    return (f"The text has {need} characters, but this page can hide at most {max(room, 0)}.\n"
            f"Use a shorter text or a bigger web page.")


def capacity_text(html):
    bits = hs.capacity(html)
    chars = hs.max_message_bytes(bits)
    if chars < 1:
        return f"This page has {bits} carrier bits. It needs at least 400 to hide a message, so it cannot hide any text."
    return f"This page has {bits} carrier bits and can hide up to {chars} characters (letters and numbers)."


# ------------------------------------------------------------------ command line

def cli(args):
    cmd = args[0].lower()
    if cmd == "capacity" and len(args) == 2:
        print(capacity_text(read(args[1])))
    elif cmd in ("hide", "hide-file") and len(args) == 5:
        page, out, msg, pw = args[1:]
        html = read(page)
        if cmd == "hide-file":
            msg = read_text_file(msg)
            problem = size_check(html, msg)
            if problem:
                print(problem)
                return
        try:
            stego = hs.hide(html, msg, pw)
        except ValueError:
            print("The message is too long for this page.")
            print(capacity_text(html))
            return
        Path(out).write_bytes(stego.encode("utf-8"))
        swapped = sum(a != b for a, b in zip(hs.read_bits(html), hs.read_bits(stego)))
        print(f"Hidden. Saved to {out}")
        print(f"Original size: {len(html.encode('utf-8'))} bytes | New size: {len(stego.encode('utf-8'))} bytes | "
              f"attribute pairs swapped: {swapped}")
    elif cmd == "reveal" and len(args) == 3:
        try:
            print("Hidden message:", hs.reveal(read(args[1]), args[2]))
        except Exception:
            print("No message found, or the password is wrong.")
    elif cmd == "reveal-file" and len(args) == 4:
        try:
            msg = hs.reveal(read(args[1]), args[2])
        except Exception:
            print("No message found, or the password is wrong.")
            return
        Path(args[3]).write_text(msg, encoding="utf-8")
        print(f"Hidden text recovered ({len(msg)} characters) and saved to {args[3]}")
    else:
        print(__doc__)


# ------------------------------------------------------------------ window app

def gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox

    root = tk.Tk()
    root.title("Hide Encrypted Text Inside HTML Web Page")
    root.geometry("660x540")
    state = {"html": None, "path": None}

    frm = tk.Frame(root, padx=12, pady=12)
    frm.pack(fill="both", expand=True)

    tk.Label(frm, text="1. Choose an HTML web page", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    row = tk.Frame(frm)
    row.pack(fill="x", pady=(2, 8))
    file_var = tk.StringVar(value="No file chosen")
    tk.Label(row, textvariable=file_var, anchor="w", width=60).pack(side="left")

    info_var = tk.StringVar(value="")

    def choose():
        p = filedialog.askopenfilename(filetypes=[("HTML files", "*.html *.htm"), ("All files", "*.*")])
        if not p:
            return
        try:
            state["html"], state["path"] = read(p), p
        except UnicodeDecodeError:
            messagebox.showerror("Error", "This file is not UTF-8 text. Save it as UTF-8 and try again.")
            return
        file_var.set(Path(p).name)
        info_var.set(capacity_text(state["html"]))
        update_count()

    tk.Button(row, text="Browse...", command=choose).pack(side="right")
    tk.Label(frm, textvariable=info_var, fg="#1a5e20", wraplength=600, justify="left").pack(anchor="w", pady=(0, 8))

    tk.Label(frm, text="2. Secret message (only needed to hide)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    msg_box = tk.Text(frm, height=6, wrap="word")
    msg_box.pack(fill="x", pady=(2, 2))
    count_var = tk.StringVar(value="0 characters")

    def update_count(_event=None):
        n = len(msg_box.get("1.0", "end").rstrip("\n").encode("utf-8"))
        room = hs.max_message_bytes(hs.capacity(state["html"])) if state["html"] else None
        count_var.set(f"{n} characters" + (f" (this page holds up to {max(room, 0)})" if room is not None else ""))

    msg_box.bind("<KeyRelease>", update_count)

    def load_txt():
        p = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if p:
            msg_box.delete("1.0", "end")
            msg_box.insert("1.0", read_text_file(p))
            update_count()

    def save_txt():
        text = msg_box.get("1.0", "end").rstrip("\n")
        if not text:
            return messagebox.showwarning("Save", "The message box is empty.")
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="recovered_message.txt",
                                         filetypes=[("Text files", "*.txt")])
        if p:
            Path(p).write_text(text, encoding="utf-8")
            messagebox.showinfo("Save", f"Saved to:\n{p}")

    trow = tk.Frame(frm)
    trow.pack(fill="x", pady=(0, 8))
    tk.Label(trow, textvariable=count_var, fg="#555").pack(side="left")
    tk.Button(trow, text="Save message to file...", command=save_txt).pack(side="right")
    tk.Button(trow, text="Load text from file...", command=load_txt).pack(side="right", padx=6)

    tk.Label(frm, text="3. Password", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    pw_var = tk.StringVar()
    tk.Entry(frm, textvariable=pw_var, show="*").pack(fill="x", pady=(2, 10))

    def do_hide():
        if not state["html"]:
            return messagebox.showwarning("Hide", "Choose an HTML page first.")
        msg = msg_box.get("1.0", "end").rstrip("\n")
        if not msg or not pw_var.get():
            return messagebox.showwarning("Hide", "Write a message and a password.")
        try:
            stego = hs.hide(state["html"], msg, pw_var.get())
        except ValueError:
            return messagebox.showerror("Hide", "The message is too long for this page.\n\n" + capacity_text(state["html"]))
        src = Path(state["path"])
        out = filedialog.asksaveasfilename(initialdir=src.parent, initialfile=src.stem + "_stego.html",
                                           defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if out:
            Path(out).write_bytes(stego.encode("utf-8"))
            messagebox.showinfo("Hide", f"Message hidden and saved to:\n{out}\n\n"
                                        f"File size is unchanged: {len(stego.encode('utf-8'))} bytes.")

    def do_reveal():
        if not state["html"]:
            return messagebox.showwarning("Reveal", "Choose the stego HTML page first.")
        if not pw_var.get():
            return messagebox.showwarning("Reveal", "Write the password.")
        try:
            msg = hs.reveal(state["html"], pw_var.get())
        except Exception:
            return messagebox.showerror("Reveal", "No message found, or the password is wrong.")
        msg_box.delete("1.0", "end")
        msg_box.insert("1.0", msg)
        update_count()
        messagebox.showinfo("Reveal", "The hidden message is shown in the message box.\n"
                                      "Use 'Save message to file...' to save it as a Notepad file.")

    btns = tk.Frame(frm)
    btns.pack(fill="x")
    tk.Button(btns, text="Hide message", width=18, command=do_hide).pack(side="left")
    tk.Button(btns, text="Reveal message", width=18, command=do_reveal).pack(side="left", padx=10)

    if "--selftest" in sys.argv:  # opens and closes the window, used only for testing
        root.after(1500, root.destroy)
    root.mainloop()


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--selftest"]
    if args:
        cli(args)
    else:
        gui()
