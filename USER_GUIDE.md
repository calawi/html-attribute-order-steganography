# User guide: download and test the tool

This guide is for a reader who wants to try the tool from the paper. Parts 1 to 5 take
about 15 minutes. The commands are for Windows PowerShell. On macOS or Linux, write
`python3` instead of `python` and `/` instead of `\`.

Use test messages and test passwords only. The method can be detected and its data is
easily lost, so it must not be used to protect real secrets.

## 1. Download the code

1. Open <https://github.com/calawi/html-attribute-order-steganography>
2. Click the green **Code** button, then **Download ZIP**.
3. Right-click the ZIP file, choose **Extract All**, and open the extracted folder. It
   must show `README.md`, `src` and `examples`.

## 2. Install

1. Install Python 3.10 or newer from <https://www.python.org/downloads/>. On the first
   screen of the installer, tick **Add python.exe to PATH**. (The results in the paper
   were made with Python 3.13.)
2. In the extracted folder, click the address bar of File Explorer, type `powershell`
   and press Enter.
3. Install the libraries:

```powershell
python -m pip install -r requirements.txt
```

## 3. Check that the tool works

```powershell
python src\test_basic.py
```

The last line should be `12 passed, 0 failed`. The 12 checks include: the message comes
back exactly, the page keeps its size, a parser builds the same document, and wrong
passwords never show the message.

## 4. Hide and reveal a message

### 4a. With a window

```powershell
python src\hide_text_app.py
```

1. Click **Browse...** and choose `examples\sample_page.html`.
2. Write a message and a password.
3. Click **Hide message** and save the new page.
4. Click **Browse...** again and choose the **new** page.
5. Clear the message box, write the same password and click **Reveal message**.

### 4b. With commands

How much can the sample page hold?

```powershell
python src\hide_text_app.py capacity examples\sample_page.html
```

Hide a message:

```powershell
python src\hide_text_app.py hide examples\sample_page.html stego.html "Meeting on Thursday" test123
```

Reveal it:

```powershell
python src\hide_text_app.py reveal stego.html test123
```

Try a wrong password:

```powershell
python src\hide_text_app.py reveal stego.html wrong
```

A wrong password nearly always gives an error. In rare cases it gives meaningless text,
because CBC mode does not authenticate the message (Section 3.4 of the paper). It does
not give the real message.

Hide a whole text file and get it back:

```powershell
python src\hide_text_app.py hide-file examples\sample_page.html stego2.html examples\secret_note.txt test123
```

```powershell
python src\hide_text_app.py reveal-file stego2.html test123 recovered.txt
```

### 4c. Compare the two pages

Open `examples\sample_page.html` and `stego.html` in a browser. They look the same.
Their sizes are also the same:

```powershell
Get-Item examples\sample_page.html, stego.html | Select-Object Name, Length
```

The code is different: some attributes have changed places.

## 5. See every step

This prints each step: the encryption, the bits, the attribute pairs before and after.

```powershell
python src\explain_steps.py hide examples\sample_page.html stego3.html "Hello" test123
```

```powershell
python src\explain_steps.py reveal stego3.html test123
```

## 6. Test on your own page

Save a page from your browser with **Ctrl+S** and the type **Webpage, HTML only**. Use
its file name in the commands of part 4. The file must be UTF-8. If the page has fewer
than 400 attribute pairs, the tool says that it cannot hold a message, as the paper
reports for 37% of the evaluation pages.

To see how fragile the hidden data is, process the stego page with BeautifulSoup, which
sorts attributes, and try to reveal the message again. It should fail:

```powershell
python -c "from bs4 import BeautifulSoup as B; h=open('stego.html','rb').read().decode('utf-8'); open('processed.html','wb').write(B(h,'lxml').decode(formatter='html').encode('utf-8'))"
```

```powershell
python src\hide_text_app.py reveal processed.html test123
```

## 7. Check the numbers in the paper

| What | Needs the web pages? | Where |
|---|---|---|
| Per-page results of the 454 evaluation pages | No | `results\per_page.csv` |
| Summary numbers (Sections 5.1 to 5.4) | No | `results\summary.json` |
| Table 6 intervals | No | run `table6_ci.py`, below |
| Figures 1 and 2 | No | run `figures.py`, below |
| Tables 8 and 9 | Yes, to run again | results in `results\head_to_head.csv` |
| Table 10 | Yes, to run again | results in `results\extra.json` |
| Table 11 | Yes, to run again | results in `results\overhead.json` |
| Fresh sample (Section 5.2) | Yes, to run again | results in `results\fresh_summary.json` |

These two commands work without the pages. They write their output into `results`:

```powershell
python src\table6_ci.py results
```

```powershell
python src\figures.py results
```

The 648 and 637 web pages are not included, because they belong to their owners.
`README.md` gives the commands that download new samples and run every experiment.
Websites change every day, so a new download gives similar numbers, not the same ones.

## 8. If something goes wrong

| Message | What to do |
|---|---|
| `python` is not recognized | Install Python again and tick **Add python.exe to PATH**, or write `py` instead of `python` |
| `No module named ...` | Run the command in part 2, step 3 again |
| `can't open file` | Open PowerShell inside the folder that shows `src` and `README.md` |
| The message is too long for this page | Use a shorter message or a bigger page |
| No message found, or the password is wrong | Check the password, and that you chose the new page and did not edit it |
