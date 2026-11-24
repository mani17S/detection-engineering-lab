"""Tests for the regex and windash modifiers."""
import pytest

from detlab.engine import _windash, matches


def rule(detection):
    return {"detection": detection}


@pytest.mark.parametrize("cmd", ["x.exe -enc AAA", "x.exe /enc AAA", "x.exe \u2013enc AAA", "x.exe \u2014enc AAA"])
def test_windash_matches_all_dash_forms(cmd):
    r = rule({"s": {"CommandLine|windash|contains": " -enc "}, "condition": "s"})
    assert matches(r, {"CommandLine": cmd})


def test_windash_only_touches_flag_dashes_not_inner_hyphens():
    assert " /my-tool " in _windash(" -my-tool ")
    assert not any("my/tool" in v for v in _windash(" -my-tool "))


def test_windash_does_not_match_other_text():
    r = rule({"s": {"CommandLine|windash|contains": " -enc "}, "condition": "s"})
    assert not matches(r, {"CommandLine": "x.exe encode"})


def test_windash_with_all_requires_each_value():
    r = rule({"s": {"CommandLine|windash|contains|all": [" -a ", " -b "]}, "condition": "s"})
    assert matches(r, {"CommandLine": "t /a -b x"})
    assert not matches(r, {"CommandLine": "t /a x"})


def test_regex_modifier_is_case_insensitive_search():
    r = rule({"s": {"CommandLine|re": r"\bwhoami\s+/all\b"}, "condition": "s"})
    assert matches(r, {"CommandLine": "cmd /c WHOAMI /all"})
    assert not matches(r, {"CommandLine": "cmd /c whoami"})
