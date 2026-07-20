# 🔐 Credential Checker

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white) ![Tests](https://img.shields.io/badge/tests-15%20passing-brightgreen?style=flat) ![License](https://img.shields.io/badge/license-MIT-green?style=flat) ![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-lightgrey?style=flat)

**▶️ [Try the live demo](https://antwnakys.github.io/credential-checker/)** — runs entirely in your browser.

A privacy-preserving tool that rates how strong a password is **and** checks
whether it has already leaked in a real data breach — *without ever sending the
password over the network*.

It comes in two forms:

- **A command-line tool** (`python -m pwcheck`) for local and scripted use.
- **A single-file web app** (`web/index.html`) that runs entirely in the
  browser and can be hosted for free on GitHub Pages.

> Built as a learning project to demonstrate secure-by-design thinking:
> hashing, the k-anonymity privacy model, graceful failure, and testing.

---

## Why breached passwords matter

A password can *look* strong (`Summer2019!`) and still be worthless, because it
has already been captured in a previous breach and sits on every attacker's
guessing list. Real-world attacks (credential stuffing) mostly reuse passwords
that have leaked before — so "has this leaked?" is often a more important
question than "does this look random?".

This tool answers both.

---

## The privacy model (the interesting part) 🕵️

Checking a password against a breach database sounds like it requires *sending*
the password somewhere — which would be dangerous. It doesn't. This project uses
the **k-anonymity range API** from [Have I Been Pwned](https://haveibeenpwned.com/):

1. Hash the password with **SHA-1** locally → `5BAA61E4C9B9…`
2. Send **only the first 5 characters** of the hash to the API.
3. The API returns *every* leaked hash suffix beginning with those 5 characters
   — typically several hundred candidates.
4. Compare locally to see whether the full hash is in that list.

```
password  ──SHA-1──▶  5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
                       └─┬─┘ └──────────────┬───────────────┘
                    sent to API        never sent — compared locally
```

The server only ever learns a 5-character prefix that maps to thousands of
possible passwords, and never learns which one you asked about. Your password —
and even its full hash — never leaves your machine.

---

## Strength analysis

The offline analyzer estimates **entropy** (bits of randomness) from the size of
the character pool and the password length, then applies penalties for patterns
that cracking tools try first:

| Signal checked            | Example flagged            |
| ------------------------- | -------------------------- |
| Common / breached shape   | `password`, `qwerty123`    |
| Keyboard walks            | `asdfgh`                   |
| Numeric sequences         | `12345`                    |
| Repeated character runs   | `aaaa`                     |
| Character-class variety   | lower/upper/digit/symbol   |

It reports a verdict (very weak → very strong), the entropy in bits, an
estimated offline crack time, and concrete suggestions.

---

## Usage

### Command line

```bash
# Prompts for a hidden password, checks strength + breaches:
python -m pwcheck

# Read from a pipe (useful in scripts); exits non-zero if weak:
echo "hunter2" | python -m pwcheck --stdin

# Fully offline — skip the breach lookup:
python -m pwcheck --no-breach
```

Example output:

```
Strength report
----------------------------------------
  Verdict      : VERY WEAK
  Entropy      : 8.0 bits
  Char pool    : 26 possible characters
  Crack time   : ~less than a second (offline, fast GPU)

  Warnings:
    ! This is one of the most commonly used passwords.

  Checking breach database (only a 5-char hash prefix is sent)...
    X FOUND in breaches 52,372,427 times — do NOT use this password.
```

### Web app

Open `web/index.html` in any browser, or host it on GitHub Pages. It has no
dependencies and no backend — the strength check and SHA-1 hashing run in the
browser via the Web Crypto API.

---

## Running the tests

```bash
pip install pytest
pytest
```

The breach tests **mock the network**, so they run offline and deterministically
while still verifying the k-anonymity contract (only a 5-char prefix is ever
sent).

---

## Project layout

```
credential-checker/
├── pwcheck/            # Python package
│   ├── strength.py     # offline entropy + pattern analysis
│   ├── breach.py       # k-anonymity breach lookup
│   └── cli.py          # command-line interface
├── tests/              # pytest suite (network mocked)
└── web/index.html      # standalone client-side web app
```

---

## Security notes & limitations

- SHA-1 is used **only** because the Have I Been Pwned range API requires it —
  not for password storage. Never store passwords with SHA-1; use a slow,
  salted hash like Argon2 or bcrypt.
- The entropy estimate is a heuristic, not a guarantee. A dedicated tool like
  [zxcvbn](https://github.com/dropbox/zxcvbn) uses a much larger dictionary.
- This tool is for **checking your own passwords**. Do not use it against
  accounts or credentials that are not yours.

---

## License

[MIT](LICENSE) — free to use, learn from, and build on.
