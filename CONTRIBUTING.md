# Contributing

Potato is a personal portfolio project, so changes mostly come from its
author. Issues and pull requests are still welcome; replies may be slow.

**Found a security problem?** Do not open an issue. Follow
[SECURITY.md](SECURITY.md).

## Set-up

Requires macOS on Apple silicon and Python 3.12 or newer. No administrator
rights are needed.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pre-commit install
```

If `python3 --version` reports something older than 3.12, use `python3.12`
in the first line instead.

## How a change reaches `main`

Nothing is pushed to `main` directly. A ruleset on GitHub enforces this.

1. **Branch** from an up-to-date `main`:

   ```bash
   git switch main && git pull
   git switch -c docs/short-description
   ```

   Branch prefixes match the commit types below: `feat/`, `fix/`, `docs/`,
   `test/`, `ci/`, `chore/`.

2. **Commit** small, single-purpose changes. Messages follow this pattern:

   ```text
   feat: add Ollama client
   fix: reject empty application name
   docs: document threat model
   test: add permission security tests
   ci: add lint, type and test workflow
   chore: initialise Python project
   ```

3. **Check** locally before pushing:

   ```bash
   ruff check .
   ruff format --check .
   mypy
   pytest
   pre-commit run --all-files
   ```

4. **Push** the branch and open a pull request.

5. **Wait for all six checks**: tests on Ubuntu and macOS for Python 3.12 and
   3.13, the dependency audit and the secret scan.

6. **Merge with "Create a merge commit".** Not squash, not rebase. Every
   commit stays in the history, so any single one can be found and reverted
   later.

## Security rules for every change

These come from the [threat model](docs/threat_model.md) and the
[architecture rules](docs/architecture.md). A pull request that breaks one
is not merged, however useful the feature.

- **No shell, no `eval`, no `exec`.** Not even "just for now".
- **No new place that starts a process.** One module may do so, with fixed
  arguments.
- **No listening socket.** Potato accepts no inbound connections.
- **Nothing from the model or from outside is trusted.** Validate it against
  a strict schema before use.
- **A new tool** needs a row in [docs/permissions.md](docs/permissions.md),
  a risk level, and tests for bad arguments and the wrong origin.
- **A new outbound connection** needs a row in the network table in
  [docs/architecture.md](docs/architecture.md).
- **A new dependency** needs a reason in the pull request. Prefer the
  standard library.
- **A new tool, integration or data store** updates the threat model in the
  same pull request.
- **Tests use mocked services.** No test contacts a real external system or
  needs a real credential.
- **Never weaken the CI protections**: pinned actions, read-only
  permissions, secret scanning. Tests guard them.

## What must never be committed

- Credentials of any kind: API keys, tokens, passwords, `.env` files.
- Personal information: real calendar entries, real holdings, recordings.
- Virtual environments, databases, logs and model files.

The `.gitignore` and the secret scanner catch most of these. They are a
safety net, not a substitute for looking at `git status` before committing.

**If a secret is committed anyway:** revoke it first, at the service that
issued it. Removing it from the history comes second, because a pushed
secret must be treated as already copied.

## Documentation rules

- The README and the documents in `docs/` never describe a feature as
  working before it is. A *Status* of `Done` is set in the commit that adds
  the tests, not before.
- Nothing in this repository claims the application cannot be attacked.
- `tests/test_documentation.py` checks links, identifiers and status values,
  so run `pytest` after editing a document.
