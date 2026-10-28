# Building reac-tools

Nothing is built or packaged: reac-tools is source only (the [README](README.md)
says why), and everything runs from a checkout with Python 3's standard library.
This page holds the developer steps.

## Tests

```sh
make test               # or: python3 -m unittest discover tests -v
```

The suite is round-trip: `reac.simulator` injects a known fault and asserts the
analyzer reports exactly it. `tests/test_no_dependencies.py` keeps the
standard-library-only rule: an import outside the standard library fails it.

## API reference

```sh
make docs               # python3 -m pdoc -o site reac
```

Needs [pdoc](https://pdoc.dev); the HTML lands in `site/`. CI publishes it to
GitHub Pages on each `v*` tag (`.github/workflows/docs.yml`).

## History hygiene

`tools/history_drop.py check` confirms the public history carries no internal
material; its docstring describes the rewrite it serves.
