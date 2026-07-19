"""Command-line interface for pwcheck.

Usage::

    python -m pwcheck                 # prompts for a hidden password
    python -m pwcheck --no-breach     # skip the online breach lookup
    echo "hunter2" | python -m pwcheck --stdin

The password is read with :func:`getpass.getpass` so it is never echoed to the
terminal or stored in shell history.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from . import __version__
from .breach import check_password
from .strength import Verdict, analyze

# ANSI colours; disabled automatically when output is not a terminal.
_COLORS = {
    Verdict.VERY_WEAK: "\033[91m",   # red
    Verdict.WEAK: "\033[91m",        # red
    Verdict.FAIR: "\033[93m",        # yellow
    Verdict.STRONG: "\033[92m",      # green
    Verdict.VERY_STRONG: "\033[92m",  # green
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pwcheck",
        description="Check a password's strength and whether it has been breached.",
    )
    parser.add_argument(
        "--no-breach", action="store_true",
        help="skip the online Have I Been Pwned lookup (fully offline).",
    )
    parser.add_argument(
        "--stdin", action="store_true",
        help="read the password from standard input instead of prompting.",
    )
    parser.add_argument(
        "--version", action="version", version=f"pwcheck {__version__}",
    )
    return parser.parse_args(argv)


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Password (input hidden): ")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    use_color = sys.stdout.isatty()

    password = _read_password(args.stdin)
    if not password:
        print("No password provided.", file=sys.stderr)
        return 2

    result = analyze(password)
    color = _COLORS[result.verdict]

    print()
    print(f"{_BOLD if use_color else ''}Strength report{_RESET if use_color else ''}")
    print("-" * 40)
    print(f"  Verdict      : {_color(result.verdict.value.upper(), color, use_color)}")
    print(f"  Entropy      : {result.entropy_bits} bits")
    print(f"  Char pool    : {result.pool_size} possible characters")
    print(f"  Crack time   : ~{result.crack_time_estimate} (offline, fast GPU)")

    if result.warnings:
        print("\n  Warnings:")
        for w in result.warnings:
            print(f"    ! {w}")

    if result.suggestions:
        print("\n  Suggestions:")
        for s in result.suggestions:
            print(f"    - {s}")

    if not args.no_breach:
        print("\n  Checking breach database (only a 5-char hash prefix is sent)...")
        breach = check_password(password)
        if not breach.checked:
            print(f"    ? {breach.error}")
        elif breach.found:
            msg = f"FOUND in breaches {breach.count:,} times — do NOT use this password."
            print(f"    {_color('X ' + msg, _COLORS[Verdict.VERY_WEAK], use_color)}")
        else:
            print(f"    {_color('OK — not found in any known breach.', _COLORS[Verdict.STRONG], use_color)}")

    print()
    # Exit non-zero if the password is weak or breached, so the tool is usable
    # in scripts and CI checks.
    weak = result.verdict in (Verdict.VERY_WEAK, Verdict.WEAK)
    return 1 if weak else 0


if __name__ == "__main__":
    raise SystemExit(main())
