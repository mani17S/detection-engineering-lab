"""Unit tests for the evaluator itself."""
import pytest

from detlab.engine import matches


def rule(detection):
    return {"detection": detection}


EVENT = {"Image": "C:\\Windows\\System32\\CMD.EXE", "CommandLine": "cmd.exe /c whoami /all"}


def test_endswith_is_case_insensitive():
    assert matches(rule({"s": {"Image|endswith": "\\cmd.exe"}, "condition": "s"}), EVENT)


def test_value_list_is_or_and_all_modifier_is_and():
    any_rule = rule({"s": {"CommandLine|contains": ["nope", "whoami"]}, "condition": "s"})
    all_rule = rule({"s": {"CommandLine|contains|all": ["whoami", "nope"]}, "condition": "s"})
    assert matches(any_rule, EVENT)
    assert not matches(all_rule, EVENT)


def test_missing_field_never_matches():
    assert not matches(rule({"s": {"ParentImage|endswith": "x.exe"}, "condition": "s"}), EVENT)


def test_not_and_precedence():
    det = {"a": {"Image|endswith": "cmd.exe"}, "b": {"CommandLine|contains": "whoami"},
           "f": {"CommandLine|contains": "/all"}}
    assert matches(rule({**det, "condition": "a and b"}), EVENT)
    assert not matches(rule({**det, "condition": "a and b and not f"}), EVENT)
    # `and` binds tighter than `or`: false or (true and true)
    assert matches(rule({**det, "condition": "f and not f or a and b"}), EVENT)
    assert matches(rule({**det, "condition": "not (f and not f)"}), EVENT)


def test_one_of_and_all_of_patterns():
    det = {"sel_a": {"Image|endswith": "cmd.exe"}, "sel_b": {"Image|endswith": "nope.exe"}}
    assert matches(rule({**det, "condition": "1 of sel_*"}), EVENT)
    assert not matches(rule({**det, "condition": "all of sel_*"}), EVENT)
    assert matches(rule({**det, "condition": "1 of them"}), EVENT)


def test_list_of_maps_is_or():
    sel = [{"Image|endswith": "nope.exe"}, {"CommandLine|contains": "whoami"}]
    assert matches(rule({"s": sel, "condition": "s"}), EVENT)


@pytest.mark.parametrize("cond", ["unknown", "a and", "(a", "a b", "1 of zzz*"])
def test_bad_conditions_raise(cond):
    with pytest.raises(ValueError):
        matches(rule({"a": {"Image|endswith": "cmd.exe"}, "condition": cond}), EVENT)
