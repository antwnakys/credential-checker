"""Password strength analysis.

This module estimates how hard a password is to *guess* offline. It does not
talk to the network — it only reasons about the password's own structure.

The two ideas that matter:

1. **Entropy** — a rough measure of randomness in bits. We estimate it from the
   size of the character pool the password draws from and its length. More bits
   means exponentially more guesses for an attacker.

2. **Pattern penalties** — real passwords are rarely random. Dictionary words,
   keyboard walks (``qwerty``), and simple sequences (``1234``) are tried first
   by cracking tools, so a password built from them is far weaker than its raw
   entropy suggests. We detect a few of the most common patterns and warn.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum


# A tiny sample of the most-guessed passwords. A production tool would load a
# large wordlist (e.g. rockyou.txt); we keep a representative slice so the
# project stays self-contained and the intent is clear.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "qwerty", "abc123",
    "password1", "111111", "123123", "admin", "letmein", "welcome",
    "monkey", "dragon", "iloveyou", "sunshine", "princess", "football",
    "qwerty123", "000000", "1234567890", "qazwsx", "trustno1",
}

# Keyboard sequences used to detect "keyboard walks".
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


class Verdict(str, Enum):
    """Human-facing rating buckets, derived from the entropy estimate."""

    VERY_WEAK = "very weak"
    WEAK = "weak"
    FAIR = "fair"
    STRONG = "strong"
    VERY_STRONG = "very strong"


@dataclass
class StrengthResult:
    """The outcome of analysing a single password."""

    entropy_bits: float
    verdict: Verdict
    pool_size: int
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    @property
    def crack_time_estimate(self) -> str:
        """A friendly estimate of offline cracking time.

        Assumes an attacker who already has the password hash and can try
        10 billion guesses per second (a realistic figure for a fast hash on
        modern GPUs). We use half the keyspace as the average number of
        guesses needed.
        """
        guesses = 2 ** self.entropy_bits / 2
        seconds = guesses / 10_000_000_000
        return _humanize_seconds(seconds)


def _character_pool(password: str) -> int:
    """Estimate the size of the alphabet the password draws from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33  # printable ASCII symbols and space
    return pool


def _has_keyboard_walk(password: str) -> bool:
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for size in range(4, len(row) + 1):
            for start in range(len(row) - size + 1):
                chunk = row[start:start + size]
                if chunk in lowered or chunk[::-1] in lowered:
                    return True
    return False


def _has_repeat_run(password: str) -> bool:
    return re.search(r"(.)\1{2,}", password) is not None


def _has_numeric_sequence(password: str) -> bool:
    for seq in ("0123456789", "9876543210"):
        for size in range(4, len(seq) + 1):
            for start in range(len(seq) - size + 1):
                if seq[start:start + size] in password:
                    return True
    return False


def analyze(password: str) -> StrengthResult:
    """Analyse ``password`` and return a :class:`StrengthResult`.

    The entropy estimate starts from ``length * log2(pool_size)`` and is then
    reduced when we spot patterns that make the password easier to guess than
    its raw keyspace implies.
    """
    warnings: list[str] = []
    suggestions: list[str] = []

    if password == "":
        return StrengthResult(
            entropy_bits=0.0,
            verdict=Verdict.VERY_WEAK,
            pool_size=0,
            warnings=["Empty password."],
            suggestions=["Use at least 12 characters."],
        )

    pool = _character_pool(password)
    entropy = len(password) * math.log2(pool) if pool else 0.0

    # Pattern penalties. Each detected weakness discounts the effective entropy,
    # because attackers try these shapes long before brute force.
    if password.lower() in COMMON_PASSWORDS:
        warnings.append("This is one of the most commonly used passwords.")
        entropy = min(entropy, 8.0)  # effectively instant to guess
    if _has_keyboard_walk(password):
        warnings.append("Contains a keyboard pattern (e.g. 'qwerty').")
        entropy *= 0.6
    if _has_numeric_sequence(password):
        warnings.append("Contains a numeric sequence (e.g. '1234').")
        entropy *= 0.7
    if _has_repeat_run(password):
        warnings.append("Contains a repeated character run (e.g. 'aaaa').")
        entropy *= 0.8

    # Constructive suggestions.
    if len(password) < 12:
        suggestions.append("Make it at least 12 characters long.")
    if pool < 62:
        missing = []
        if not re.search(r"[a-z]", password):
            missing.append("lowercase")
        if not re.search(r"[A-Z]", password):
            missing.append("uppercase")
        if not re.search(r"[0-9]", password):
            missing.append("digits")
        if not re.search(r"[^a-zA-Z0-9]", password):
            missing.append("symbols")
        if missing:
            suggestions.append("Add " + ", ".join(missing) + ".")
    if not suggestions:
        suggestions.append(
            "Even better: use a unique passphrase of random words per site, "
            "stored in a password manager."
        )

    return StrengthResult(
        entropy_bits=round(entropy, 1),
        verdict=_verdict_for(entropy),
        pool_size=pool,
        warnings=warnings,
        suggestions=suggestions,
    )


def _verdict_for(entropy: float) -> Verdict:
    if entropy < 28:
        return Verdict.VERY_WEAK
    if entropy < 36:
        return Verdict.WEAK
    if entropy < 60:
        return Verdict.FAIR
    if entropy < 128:
        return Verdict.STRONG
    return Verdict.VERY_STRONG


def _humanize_seconds(seconds: float) -> str:
    """Turn a raw seconds count into a readable duration."""
    if seconds < 1:
        return "less than a second"
    minute, hour, day, year = 60, 3600, 86400, 31_536_000
    units = [
        (100 * year, "centuries"),
        (year, "years"),
        (day, "days"),
        (hour, "hours"),
        (minute, "minutes"),
        (1, "seconds"),
    ]
    for size, name in units:
        if seconds >= size:
            value = seconds / size
            if name == "centuries" and value > 1000:
                return "millions of years"
            return f"{value:,.0f} {name}"
    return "less than a second"
