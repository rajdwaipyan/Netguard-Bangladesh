# Contributing to NetGuard Bangladesh

## Development environment

Use Windows with the tested Python interpreter and a virtual environment:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

The core application uses the standard library. Optional NumPy, Matplotlib,
and scikit-learn integrations are not required for tests.

## Coding expectations

- Preserve evidence boundaries; never fabricate telemetry or findings.
- Keep active network actions authorized, bounded, cancellable, and documented.
- Keep Tkinter access on the main thread.
- Use explicit errors rather than silent fallbacks.
- Prefer focused changes over architectural rewrites.
- Update relevant documentation and tests with behavior changes.

## Verification

```powershell
python -m unittest discover -s tests -v
python -m py_compile netguard_bangladesh.py tests\test_discovery_engine.py tests\test_runtime_probes.py
ruff check netguard_bangladesh.py tests
```

Tests must not require internet access, real network devices, credentials, or
attack traffic. Mock Windows commands and external APIs.

## Pull requests

Describe the user-visible behavior, evidence source, authorization boundary,
tests executed, and remaining limitations. Do not include private network
captures, credentials, API keys, generated caches, or unredacted screenshots.
Documentation must not claim a phase or feature is complete beyond its tested
scope.

## Reporting bugs

Open an issue in the configured project repository once one exists. Include
the operating system, Python version, reproducible steps, sanitized logs, and
the expected versus observed behavior. Do not publish sensitive security
details publicly; follow the repository's `SECURITY.md` process instead.
