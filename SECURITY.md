# Security policy

Potato is a personal, pre-alpha project. It has not been audited, and it
makes no claim to be secure. Its design goals and known limits are written
down in the [threat model](docs/threat_model.md).

## Supported versions

Only the latest commit on `main` is supported. There are no releases yet.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability**.

Direct link:
<https://github.com/mehmetalitarin/project-potato/security/advisories/new>

Helpful things to include:

- What you found, and where (file, function or document).
- Steps to reproduce it, or a short proof of concept.
- What an attacker could gain.
- The threat ID from the threat model, if one applies (for example
  `T-LLM-1`).

## What to expect

This project is maintained by one student, so there is no guaranteed
response time. I aim to reply within a week, to agree a fix and a disclosure
date with you, and to credit you in the fix unless you prefer otherwise.

## In scope

- Any way for model output or external content to cause an action that the
  permission rules in [docs/permissions.md](docs/permissions.md) should have
  denied.
- Prompt injection that triggers a tool call.
- Forging, replaying or altering a physical approval.
- A secret or private content written to a log, the database or an error
  message.
- Any network listener, or any connection not listed in
  [docs/architecture.md](docs/architecture.md).
- Weaknesses in this repository's CI, dependency or secret-scanning
  configuration.
- A place where the documentation says a defence exists and it does not.

## Out of scope

These are excluded by the threat model, which explains why:

- Attacks that need malware already running as the user, administrator
  rights or physical access to an unlocked Mac.
- Vulnerabilities in macOS, Python, Ollama or a third-party package. Please
  report those to their own maintainers. A report that Potato *uses* a
  vulnerable version is welcome.
- Wrong or unhelpful answers from the language model that do not cause an
  action.
- Social engineering of the maintainer.

## Rules for testing

- Test only on your own computer and your own copy of the code.
- Do not test against anyone else's systems, accounts or networks.
- No real credentials are needed. Every test in this repository uses mocked
  services.
