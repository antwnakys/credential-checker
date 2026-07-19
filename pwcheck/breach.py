"""Check whether a password has appeared in known data breaches.

This talks to the `Have I Been Pwned <https://haveibeenpwned.com/>`_ Pwned
Passwords service, which holds hundreds of millions of passwords exposed in
real breaches. If a password is in there, attackers already have it on their
guessing lists — so it is unsafe no matter how "strong" it looks.

The important design goal: **never send the password, or its full hash, over
the network.** We achieve this with the service's *k-anonymity* range API:

1. Compute the SHA-1 hash of the password locally.
2. Send only the **first 5 hex characters** of that hash to the API.
3. The API returns every breached hash suffix that shares those 5 characters
   (typically a few hundred candidates).
4. We compare locally to see if our full hash is among them.

The server therefore learns a 5-character prefix that maps to thousands of
possible passwords, and never learns which one we asked about.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen

API_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "pwcheck-credential-checker (educational project)"


@dataclass
class BreachResult:
    """Outcome of a breach lookup."""

    checked: bool           # False if the lookup could not be performed
    found: bool             # True if the password appears in a breach
    count: int              # how many times it was seen across breaches
    error: str | None = None


def sha1_hex(password: str) -> str:
    """Return the uppercase SHA-1 hex digest of ``password``."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_password(password: str, *, timeout: float = 10.0) -> BreachResult:
    """Look up ``password`` in the Pwned Passwords database via k-anonymity.

    Only the first five characters of the SHA-1 hash ever leave this machine.
    Network or service failures return ``checked=False`` with an ``error``
    rather than raising, so callers can degrade gracefully.
    """
    if password == "":
        return BreachResult(checked=True, found=False, count=0)

    full_hash = sha1_hex(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    try:
        candidates = _fetch_range(prefix, timeout=timeout)
    except (URLError, TimeoutError, OSError) as exc:
        return BreachResult(
            checked=False, found=False, count=0,
            error=f"Could not reach the breach database: {exc}",
        )

    count = candidates.get(suffix, 0)
    return BreachResult(checked=True, found=count > 0, count=count)


def _fetch_range(prefix: str, *, timeout: float) -> dict[str, int]:
    """Fetch all breached hash suffixes for a 5-char prefix.

    Returns a mapping of ``suffix -> breach count``.
    """
    request = Request(API_URL + prefix, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 (https URL)
        body = response.read().decode("utf-8")

    results: dict[str, int] = {}
    for line in body.splitlines():
        if ":" not in line:
            continue
        suffix, count = line.split(":", 1)
        try:
            results[suffix.strip().upper()] = int(count.strip())
        except ValueError:
            continue
    return results
