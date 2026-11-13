# Project Potato

[![CI](https://github.com/mehmetalitarin/project-potato/actions/workflows/ci.yml/badge.svg)](https://github.com/mehmetalitarin/project-potato/actions/workflows/ci.yml)

A local-first, voice-controlled personal assistant for macOS, designed
security-first. The language model runs on your own machine through
[Ollama](https://ollama.com), and it is never allowed to control the computer
on its own: every action it proposes must pass an independent permission
manager.

## Status

**Pre-alpha: foundations only.** Nothing in the feature list below is
implemented yet. This repository currently contains the package structure,
tooling configuration, security documentation, validated settings and tests.

| Area | State |
| --- | --- |
| Project setup, linting, typing, tests | Done |
| Continuous integration, dependency audit, secret scanning | Done |
| Threat model and security documentation | Done |
| Validated settings, with a loopback-only model address | Done |
| Logging with redaction, and the audit log | Next |
| Everything else | Not started |

This README is updated as each milestone lands. It will never describe a
feature as working before it is.

## Planned for version 1.0

- Local LLM through Ollama, bound to `127.0.0.1` only
- Wake-word activation on "Potato", local speech-to-text and text-to-speech
- Automatic sleep, with the model unloaded from memory when idle
- Stock portfolio tracking (no trading, no brokerage credentials)
- Read-only calendar access with homework and deadline summaries
- Launching applications from a fixed allowlist
- Defensive security tools: macOS security posture, process and network
  monitoring, dependency vulnerability scanning, phishing URL analysis
- Security dashboard and audit log

## Deliberately out of scope for 1.0

Email, messaging and calls; reading, scanning, modifying or deleting personal
files; arbitrary shell or Python execution; administrator commands; remote
control; any public-facing API; any cloud AI service.

## Security design goals

These are goals the code will be tested against, not claims that the
application is secure.

- **The model proposes, it never executes.** Model output is treated as
  untrusted data and validated against strict schemas.
- **One gate.** Every tool call passes through the permission manager:
  allowlists, argument validation, rate limits, timeouts and audit logging.
- **Physical approval for anything sensitive.** A click or key press in the
  desktop interface, never a voice command.
- **Least privilege.** No administrator rights, no shell, no inbound network
  listener.
- **External content is data.** Calendar text, API responses and anything
  else from outside can never become instructions.

No software is impossible to attack. The known limits of this design are
written down in the [threat model](docs/threat_model.md), including what is
deliberately out of scope.

## Documentation

| Document | What it covers |
| --- | --- |
| [Threat model](docs/threat_model.md) | What Potato defends against, what it does not, and the status of each defence |
| [Architecture](docs/architecture.md) | Components, trust boundaries and the rules CI will enforce |
| [Permissions](docs/permissions.md) | What the permission manager guarantees, risk levels and physical approval |
| [Security policy](SECURITY.md) | How to report a vulnerability privately |
| [Contributing](CONTRIBUTING.md) | Branch, pull request and merge workflow, and the security rules for changes |

These are design documents. Each one marks clearly what exists today and
what is planned.

## Requirements

- macOS on Apple silicon
- Python 3.12 or newer

Ollama is not needed yet.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pre-commit install     # run secret scanning and linting on every commit
```

No administrator rights are required for any of this. The first commit after
`pre-commit install` takes a minute while the hooks are set up. If
`python3 --version` reports something older than 3.12, use `python3.12` in
the first line instead.

## Checks

```bash
ruff check .            # lint, including security rules
ruff format --check .   # formatting
mypy                    # strict static typing
pytest                  # tests
pip-audit --skip-editable   # known vulnerabilities in installed packages
pre-commit run --all-files  # every hook, including Gitleaks
```

## Repository security

- CI runs on Ubuntu and on Apple silicon macOS, for Python 3.12 and 3.13.
- Workflows have read-only permissions, and every third-party action is
  pinned to a full commit SHA. Tests in `tests/test_repository_security.py`
  fail if either protection is removed.
- Gitleaks scans every commit locally (pre-commit) and the full history in CI.
- Dependabot proposes updates for Python packages and for the pinned actions.
- `main` is protected: changes arrive through pull requests only, and all
  six CI checks must pass before a merge.

Run the scaffold itself:

```bash
python -m potato --version
python -m potato --check-settings
```

## Settings

Potato runs on built-in defaults. An optional file at
`~/Library/Application Support/Potato/settings.toml` can adjust them:

```toml
[ollama]
host = "127.0.0.1"             # loopback IP addresses only; host names are refused
port = 11434
model = "qwen3:8b"             # must be on the allowlist in the source code
request_timeout_seconds = 60
context_length = 8192

[assistant]
idle_timeout_seconds = 300

[security]
approval_lifetime_seconds = 30
```

Every number has a fixed minimum and maximum, and an unknown setting is an
error. `python -m potato --check-settings` validates the file and reports
the result. Nothing uses these settings yet; the components that will are
built in later milestones.

## Project layout

```text
src/potato/
    core/           state machine, configuration, turn orchestration
    security/       permission manager, approvals, audit log
    modules/        the tools: launcher, portfolio, calendar, monitors
    integrations/   the only code that talks to the outside world
    voice/          microphone, wake word, speech-to-text, text-to-speech
    storage/        local SQLite database
    ui/             PySide6 desktop interface
docs/               threat model, architecture, permissions
tests/
```

Each package's docstring states the boundary it must respect.
