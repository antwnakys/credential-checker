"""Tests for the offline strength analyzer."""

from pwcheck.strength import Verdict, analyze


def test_empty_password_is_very_weak():
    result = analyze("")
    assert result.verdict is Verdict.VERY_WEAK
    assert result.entropy_bits == 0.0


def test_common_password_is_flagged_and_weak():
    result = analyze("password")
    assert result.verdict is Verdict.VERY_WEAK
    assert any("commonly used" in w for w in result.warnings)


def test_keyboard_walk_is_flagged():
    result = analyze("qwertyuiop")
    assert any("keyboard" in w.lower() for w in result.warnings)


def test_numeric_sequence_is_flagged():
    result = analyze("abc12345def")
    assert any("numeric sequence" in w.lower() for w in result.warnings)


def test_repeat_run_is_flagged():
    result = analyze("aaaa1B!xyz")
    assert any("repeated" in w.lower() for w in result.warnings)


def test_long_random_password_is_strong():
    result = analyze("7Gq!vZ2m#Lp9wRt&Xe4")
    assert result.verdict in (Verdict.STRONG, Verdict.VERY_STRONG)
    assert result.entropy_bits > 100


def test_pool_size_grows_with_character_classes():
    lower_only = analyze("abcdefgh").pool_size
    mixed = analyze("abcDEF12!@").pool_size
    assert mixed > lower_only


def test_short_password_gets_length_suggestion():
    result = analyze("aB3!")
    assert any("12 characters" in s for s in result.suggestions)


def test_crack_time_is_a_readable_string():
    result = analyze("7Gq!vZ2m#Lp9wRt&Xe4")
    assert isinstance(result.crack_time_estimate, str)
    assert result.crack_time_estimate
