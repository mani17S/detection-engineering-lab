# Contributing

Thanks for helping improve these detections. The bar is simple: **a rule is only done when its tests prove it.**

## Add or change a rule

1. Create or edit `rules/<platform>/<name>.yml`. Required fields: `title`, `id` (new UUID v4), `status`,
   `description`, `author`, `date`, `tags` (with at least one `attack.tNNNN[.NNN]`), `logsource`,
   `detection`, `falsepositives`, `level`.
2. Create or edit `tests/events/<name>.json`:
   - `positive`: realistic attack events that must match, including flag-spelling variants where relevant.
   - `negative`: benign look-alikes that must **not** match (same binary, harmless arguments).
3. If the rule should never fire on normal admin work, add an example to `tests/benign/benign_events.json`.
4. Run `pytest -q`. CI runs the same checks on Python 3.10-3.13.

## Rule guidelines

- Prefer behaviour over tool names where you can, but name the tool when the behaviour is not observable.
- Use `windash` for Windows command-line flags so `-flag` and `/flag` both match.
- Document realistic false positives; do not claim a rule is "low noise" without data.
- Keep sample events safe: use `example.invalid` and reserved IP ranges (RFC 5737), never working payloads.
- Defensive use only. Contributions that add offensive tooling will not be merged.

## Evaluator changes

Add tests in `tests/test_engine*.py`. Keep the evaluator small; features beyond the documented subset belong in pySigma.
