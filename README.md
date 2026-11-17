# Project Potato 🥔

[![CI](https://github.com/mehmetalitarin/project-potato/actions/workflows/ci.yml/badge.svg)](https://github.com/mehmetalitarin/project-potato/actions/workflows/ci.yml)

Potato is a voice assistant for my Mac that runs completely locally. The
language model runs on my own machine through [Ollama](https://ollama.com),
so nothing I say goes to a cloud service.

I'm a Computer Science (Cyber Security) student at Royal Holloway, and I
wanted to build something useful while learning how to make an AI assistant
that can't be easily turned against its owner. The main idea is simple: **the
model can only suggest actions, never do them itself.** Every action it
suggests has to get past a separate permission manager (I call it "the
gate") that the model can't talk its way around.

## Where it's at

**Pre-alpha.** You can start Potato and type to it: it answers using the
local model and can use its tools. It can read its replies aloud, but it
can't listen yet, so for now you type. Everything that's there is tested.

| Part | State |
| --- | --- |
| Project setup: linting, strict typing, tests, CI on Ubuntu and macOS | Done |
| Threat model and security docs | Done |
| Settings validation, logging with secrets removed, tamper-evident audit log | Done |
| Local database for portfolio holdings | Done |
| Assistant states (voice can't wake Potato from sleep) | Done |
| The gate: allowlist, strict arguments, origin limits, rate and time limits | Done |
| Physical approvals: single-use tokens tied to one exact action | Done |
| Attack tests for the gate, and import rules checked in CI | Done |
| Local model client (Ollama, this Mac only) | Done |
| Conversations in two passes, so outside text can't trigger a tool | Done |
| Portfolio tools (typed only, not by voice) | Done |
| Phishing link checker (reads the link as text, never opens it) | Done |
| App launcher (Apple's own apps only, checked before opening) | Done |
| Calendar and homework deadlines from Apple Calendar, read-only | Done |
| Security posture: FileVault, firewall, Gatekeeper, SIP | Done |
| Process overview (never reads command lines) | Done |
| Network overview (never shows remote addresses) | Done |
| Security update check (lists only, never installs) | Done |
| Desktop window: typed chat and Potato's state, plain text only | Done |
| Approval dialog: shows the exact action, Deny by default, real clicks only | Done |
| Starting Potato as an app: `python -m potato` opens the window, connected to the model and tools | Done |
| Model unloaded from memory when idle | Done |
| Conversation memory, without letting outside text choose a tool | Done |
| The orb: an animated status indicator, in the window or floating above other apps, with smooth changes | Done |
| A potato mascot, drawn in code, in the window, the dashboard and the app icon | Done |
| Security dashboard: protections, programs, network and updates on one screen, with "Show all" | Done |
| Reading replies aloud with the Mac's own voice (off until you turn it on; private results are shown, not spoken) | Done |
| Voice input: push-to-talk and local speech-to-text | Next |
| Dependency scan | Not started |
| Live stock prices (needs a Finnhub key) | Set aside |

I only mark something as done once it's built and tested.

## What it'll do (version 1.0)

- Wake on "Potato", with speech handled locally
- Go to sleep when idle and unload the model from memory
- Track a stock portfolio (no trading, no brokerage logins)
- Read my calendar and summarise homework deadlines
- Open apps from a fixed list
- Security tools: posture check, process and network overviews, update
  check, dependency scanning, phishing link analysis
- A security dashboard and audit log

Things I'm deliberately **not** building: email, messaging, calls, touching
personal files, running shell commands, admin commands, remote control, any
public API or any cloud AI.

## How I'm trying to keep it safe

These are goals I test against, not a promise that it can't be attacked.

- **The model proposes, it never executes.** Anything it outputs is treated
  as untrusted data and checked against strict rules.
- **One gate for everything.** Allowlists, argument checks, rate limits,
  timeouts and audit logging all happen in one place.
- **A real click for anything sensitive.** Approving something risky needs a
  click or key press in the app. Voice can't approve anything.
- **Least privilege.** No admin rights, no shell, nothing listening on the
  network.
- **Outside text is just data.** Calendar entries, web data and anything
  else from outside can never become instructions.

The [threat model](docs/threat_model.md) lists what I defend against, what's
left over and what's out of scope.

## Docs

| Document | What's in it |
| --- | --- |
| [Threat model](docs/threat_model.md) | What Potato defends against, the leftover risk, and the status of each defence |
| [Architecture](docs/architecture.md) | Components, trust boundaries and the rules CI enforces |
| [Permissions](docs/permissions.md) | What the gate guarantees, risk levels and physical approval |
| [Security policy](SECURITY.md) | How to report a vulnerability privately |
| [Contributing](CONTRIBUTING.md) | The branch and pull request workflow, and the security rules for changes |

## How I built it

I built Potato with help from an AI assistant (Claude) for writing and
reviewing code. The design, the security requirements and the testing
approach are mine, and I review and run every change myself before it's
merged. Every change goes through a pull request and has to pass all the CI
checks.

## Running it yourself

You'll need macOS on Apple silicon and Python 3.12 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.txt
python -m pip install -e ".[dev]"
pre-commit install     # secret scanning and linting on every commit
```

No admin rights needed. If `python3 --version` shows something older than
3.12, use `python3.12` in the first line instead.

Quick check that it works:

```bash
python -m potato --version
python -m potato --check-settings
```

Then start it:

```bash
python -m potato
```

Type a request and press Return. Potato starts asleep and wakes when you
type. Closing the window shuts everything down.

For conversations you also need Ollama and the model (one download):

```bash
ollama pull qwen3:14b
```

It needs about 16 GB of memory. On a Mac with less, use the smaller
`qwen3:8b` instead (`ollama pull qwen3:8b`, then set `model = "qwen3:8b"` in
the settings below): it's quicker but not as clever.

If Ollama isn't running or the model isn't there, Potato just says so.

## Checks

```bash
ruff check .                # lint, including security rules
ruff format --check .       # formatting
mypy                        # strict typing
pytest                      # tests
pip-audit --skip-editable   # known vulnerabilities in installed packages
pre-commit run --all-files  # every hook, including Gitleaks
```

CI runs all of this on Ubuntu and Apple silicon macOS, with Python 3.12 and
3.13. A few other things protect the repo itself:

- Workflows have read-only permissions, and every third-party action is
  pinned to a full commit hash. Tests fail if either is removed.
- Gitleaks scans every commit locally and the whole history in CI.
- Dependabot suggests updates for packages and actions.
- `main` is protected: changes only arrive through pull requests, and all
  six CI checks have to pass.

## Settings

Potato works with built-in defaults. If you want to change them, create
`~/Library/Application Support/Potato/settings.toml`:

```toml
[ollama]
host = "127.0.0.1"             # loopback IP addresses only; host names are refused
port = 11434
model = "qwen3:14b"            # "qwen3:14b" or "qwen3:8b"; others are refused
request_timeout_seconds = 60
context_length = 8192

[assistant]
idle_timeout_seconds = 300

[security]
approval_lifetime_seconds = 30
```

Every number has a fixed minimum and maximum, and an unknown setting is an
error. `python -m potato --check-settings` checks the file for you.

## Stock prices

There's a tested client for [Finnhub](https://finnhub.io) that only ever
sends one ticker symbol per request, over verified TLS. I've set live prices
aside for now, so nothing uses it and Potato stores no credentials at all.

## Project layout

```text
src/potato/
    core/           states, settings, conversation turns
    security/       the gate, approvals, audit log
    modules/        the tools: launcher, portfolio, calendar, monitors
    integrations/   the only code that talks to anything outside Potato
    voice/          reading replies aloud; microphone coming next
    storage/        local SQLite database
    ui/             PySide6 desktop window
docs/               threat model, architecture, permissions
tests/
```

Each package's docstring says what it is and isn't allowed to do.
