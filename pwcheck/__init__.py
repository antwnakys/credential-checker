"""pwcheck — a privacy-preserving credential checker.

Combines local password-strength analysis with a k-anonymity breach lookup
against Have I Been Pwned. Passwords never leave the machine in a recoverable
form.
"""

from .breach import BreachResult, check_password, sha1_hex
from .strength import StrengthResult, Verdict, analyze

__version__ = "1.0.0"

__all__ = [
    "analyze",
    "StrengthResult",
    "Verdict",
    "check_password",
    "BreachResult",
    "sha1_hex",
]
