# Contributing to Nexus Toolkit

Thanks for your interest in improving Nexus.

## Development setup

```bash
git clone <your-fork-url> nexus && cd nexus
python -m pip install -e ".[dev]"
```

On Windows: `powershell -ExecutionPolicy Bypass -File .\install.ps1`.

## Before opening a PR

```bash
ruff check osint_toolkit tests    # lint
pytest                            # tests must pass on Python 3.10–3.13
```

## Guidelines

- Every scan module returns a `ScanResult` (see `osint_toolkit/models.py`).
- **OSINT** modules must stay 100% passive (no traffic to the subject).
- **PENTEST** modules are detection-only: they discover and report, they do
  not exploit. Pull requests that add exploitation, payloads or brute-forcing
  to the core modules will not be merged — such capability belongs behind the
  user-installed EXTERNAL tool wrappers, subject to the authorisation notice.
- Add a test for new logic (offline/deterministic where possible).
- Keep user-facing strings in `osint_toolkit/i18n.py` so they can be translated.
- Run `ruff` and keep the existing code style.
