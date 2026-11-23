"""Minimal evaluator for the Sigma subset used in this repository.

Supported
  * field modifiers: contains, startswith, endswith, all (combine with the others)
  * plain equality with ``*`` wildcards; matching is case-insensitive
  * a list of values is OR'd (AND'd with ``|all``); a list of maps is OR'd
  * conditions: and / or / not / parentheses, ``1 of <name>*``, ``all of <name>*``,
    ``1 of them``, ``all of them``

Not supported (use pySigma / sigma-cli for these): regex, CIDR, base64 modifiers,
aggregations (``count() by``), temporal correlation, field mappings.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any, Iterable, Iterator

import yaml

Event = dict[str, Any]
_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _norm(value: Any) -> str:
    return str(value).lower()


def _match_one(actual: Any, modifiers: list[str], expected: Any) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    a, e = _norm(actual), _norm(expected)
    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    return fnmatch.fnmatchcase(a, e) if "*" in e else a == e


def _match_field(event: Event, key: str, expected: Any) -> bool:
    field, *modifiers = key.split("|")
    values = expected if isinstance(expected, list) else [expected]
    results = (_match_one(event.get(field), modifiers, v) for v in values)
    return all(results) if "all" in modifiers else any(results)


def match_selection(event: Event, selection: Any) -> bool:
    if isinstance(selection, list):
        return any(match_selection(event, item) for item in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    raise ValueError(f"Unsupported selection type: {type(selection).__name__}")


class _Condition:
    """Recursive-descent parser/evaluator for a Sigma condition string."""

    def __init__(self, text: str, names: list[str], results: dict[str, bool]):
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.names = names
        self.results = results

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("Unexpected end of condition")
        self.pos += 1
        return token

    def parse(self) -> bool:
        value = self._or()
        if self._peek() is not None:
            raise ValueError(f"Unexpected token in condition: {self._peek()!r}")
        return value

    def _or(self) -> bool:
        value = self._and()
        while (self._peek() or "").lower() == "or":
            self._next()
            rhs = self._and()  # always consume the right operand
            value = value or rhs
        return value

    def _and(self) -> bool:
        value = self._not()
        while (self._peek() or "").lower() == "and":
            self._next()
            rhs = self._not()
            value = value and rhs
        return value

    def _not(self) -> bool:
        if (self._peek() or "").lower() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        token = self._next()
        if token == "(":
            value = self._or()
            if self._next() != ")":
                raise ValueError("Missing closing parenthesis")
            return value
        if token.lower() in ("1", "all") and (self._peek() or "").lower() == "of":
            self._next()
            pattern = self._next()
            matched = self._of(pattern)
            return any(matched) if token == "1" else bool(matched) and all(matched)
        if token not in self.results:
            raise ValueError(f"Condition references unknown selection {token!r}")
        return self.results[token]

    def _of(self, pattern: str) -> list[bool]:
        names = self.names if pattern.lower() == "them" else fnmatch.filter(self.names, pattern)
        if not names:
            raise ValueError(f"No selections match {pattern!r}")
        return [self.results[n] for n in names]


def matches(rule: dict[str, Any], event: Event) -> bool:
    detection = rule["detection"]
    names = [k for k in detection if k != "condition"]
    results = {n: match_selection(event, detection[n]) for n in names}
    conditions = detection["condition"]
    conditions = conditions if isinstance(conditions, list) else [conditions]
    return any(_Condition(c, names, results).parse() for c in conditions)


def load_rule(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_rules(directory: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    for path in sorted(Path(directory).rglob("*.yml")):
        yield path, load_rule(path)


def scan(rules: Iterable[dict[str, Any]], events: Iterable[Event]) -> Iterator[tuple[int, dict[str, Any]]]:
    rules = list(rules)
    for index, event in enumerate(events):
        for rule in rules:
            if matches(rule, event):
                yield index, rule
