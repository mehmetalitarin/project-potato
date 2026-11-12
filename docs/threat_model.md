# Threat model

> **Status: design document.** Potato is pre-alpha. This file describes what
> the finished application must defend against, and how. The *Status* column
> in each table says whether a defence exists yet. Nothing here is a claim
> that Potato is secure.

Last reviewed: 2026-11-12. Applies to: planned version 1.0.

Related documents: [architecture](architecture.md),
[permissions](permissions.md), [security policy](../SECURITY.md).

## The short version

1. **The language model is treated as an untrusted component.** It can be
   wrong, and it can be manipulated. It only ever *proposes* an action.
2. **One gate decides.** Every proposed action passes an independent
   permission manager that the model cannot influence.
3. **Anything from outside is data, never instructions.** Calendar text, API
   responses and web content cannot choose a tool.
4. **Voice is convenient, not trusted.** Potato cannot tell who is speaking,
   so voice reaches only low-risk actions and can never approve anything.
5. **The dangerous abilities do not exist.** There is no tool for running
   commands, reading files, changing settings, sending messages or trading.
   A defence that does not exist cannot be bypassed.

## How to read this

- Every threat has a stable ID such as `T-LLM-1`. Tests name the threat they
  cover, so a threat can be traced to the code that defends against it.
- **STRIDE** is the standard set of threat categories: **S**poofing,
  **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of
  service, **E**levation of privilege.
- **Status** is one of:
  - `Done`: the defence is in the repository and tested.
  - `Partly done`: some of the defence exists; the rest is planned.
  - `Planned (M3)`: arrives in that milestone.
- **What remains** is the risk left over after the defence. It is never empty
  on purpose: every defence has a limit.

Milestones: M0 foundations, M1 core, M2 security gate, M3 local model,
M4 first tools, M5 calendar, M6 security monitors, M7 voice, M8 interface,
M9 release.

## What we protect

| Asset | Why it matters |
| --- | --- |
| Control of the Mac | Anything Potato can do, an attacker who steers Potato can do. |
| Microphone audio | Private speech of the user and of anyone else in the room. |
| Calendar contents | Where the user will be, and when. |
| Portfolio holdings | Personal financial information. |
| Market data API key | A credential, even if a low-value one. |
| Audit log | The record of what Potato did. Worthless if it can be silently changed. |
| Potato's own code, dependencies and model files | If these are replaced, every other defence is void. |
| The truthfulness of what Potato tells the user | A security tool that can be made to lie is worse than none. |

## Who we defend against

| Who | What they can do | What they cannot do |
| --- | --- | --- |
| **Content author.** Anyone who can put text in front of Potato: a calendar invitation, an API response, a web page title. | Write any text, including text aimed at the model. | Run code on the Mac. |
| **Network attacker.** Someone on the same Wi-Fi or on the path to an API. | Read, block or alter unencrypted traffic; attempt connections to the Mac. | Break correctly validated TLS. |
| **Nearby sound source.** A person in the room, a video, a speaker. | Say "Potato" and any command. | Touch the keyboard or mouse. |
| **Upstream compromise.** A malicious or hijacked Python package, GitHub Action, API provider or model file. | Deliver hostile code or data through a channel we chose to trust. | Nothing is beyond it once its code runs. The aim is to keep it from running. |
| **The model itself.** Not malicious, but unreliable. | Invent tools, arguments and facts; follow injected instructions. | Act without passing the gate. |
| **The user, by mistake.** | Ask for something dangerous or misspeak. | Reach an ability that was never built. |
| **A contributor.** Anyone who opens a pull request on the public repository. | Propose any change. | Merge without the checks passing. |

## Trust boundaries

A trust boundary is a place where data moves from something we trust less to
something we trust more. Each one needs a check. The component diagram is in
[architecture.md](architecture.md).

| ID | Boundary | What crosses it | Rule |
| --- | --- | --- | --- |
| TB1 | Microphone to voice pipeline | Sound from anyone or anything nearby | Audio alone never causes an action. |
| TB2 | User's words to the model | Typed text or a transcript, possibly misheard, pasted or spoken by someone else | Treated as intent, and only for the tools that origin may reach. |
| TB3 | Model to permission manager | A proposed tool call | Always untrusted. Parsed and validated, never executed as written. |
| TB4 | Permission manager to tools | A validated call | The only way a tool runs. |
| TB5 | Integrations to the outside | Requests to Ollama, the market data API, Calendar and macOS | Typed arguments go out. Everything that comes back is untrusted data. |
| TB6 | Tool results to the model | External data | Sent as data, in a pass where the model has no tools. |
| TB7 | Interface to approvals | A physical click or key press | The only source of an approval. |
| TB8 | Potato to the disk | Database, logs, configuration | Other software running as the same user can read these, so no secret is stored there. |
| TB9 | Repository to the world | Contributions, dependencies, CI | Changes arrive by pull request with checks; third-party code is pinned. |

## Assumptions

The model only holds if these are true. If one fails, see
[Out of scope](#out-of-scope).

- macOS, the hardware and the user's account are not already compromised.
- The Ollama program is the genuine one, installed by the user.
- Python packages are installed from the project's pinned list.
- No attacker has hands on the unlocked Mac.
- The user reads an approval dialog before clicking it.

## Threats

### Model and prompt injection

| ID | Threat | STRIDE | Defence | Status | What remains |
| --- | --- | --- | --- | --- | --- |
| T-LLM-1 | Text hidden in external content (a calendar description, an API response) makes the model call a tool. | T, E | Two-pass turns. The model chooses tools in a pass that contains only the fixed system prompt, the tool list and the user's own words. Tool results, and earlier replies built from them, are never in that pass. Results are summarised in a second pass with tools switched off. See R6 in [architecture.md](architecture.md). | Planned (M3) | Text the user pastes or speaks is the user's own words, so it can reach low-risk tools. Follow-up requests cannot refer to an earlier reply when choosing a tool. |
| T-LLM-2 | The model proposes a tool that does not exist, or arguments nobody allowed: a path, a command, an extra field. | E | Tools come from a list defined in code (P2). Arguments are checked against a strict schema that rejects unknown fields (P3). No tool accepts a command, code or a file path (P4). | Planned (M2) | The model can still choose the wrong *allowed* tool, for example open the wrong approved application. |
| T-LLM-3 | Model output is passed to something that interprets it: a shell, SQL, `eval`, HTML rendering, speech control codes. | T, E | No shell and no `eval` or `exec` anywhere, enforced by lint rules. SQL uses parameters only. The interface shows model text as plain text. Speech uses the synthesis API with control sequences stripped. | Partly done | The lint rules are active today. The other sinks do not exist yet; each gets its own test when it is built. |
| T-LLM-4 | Injected text distorts the reply: the summary states something false or omits a deadline. | T | The interface shows the underlying data (events, prices, findings) from code, next to the model's summary. Security findings are explained with fixed, reviewed text, not model-written text. | Planned (M3, M8) | A spoken summary heard without looking at the screen can still be wrong. |
| T-LLM-5 | The model loops, floods the gate with calls or produces enormous output. | D | A small fixed limit on tool calls per turn, rate limits (P8), timeouts (P9) and output size caps. | Planned (M2, M3) | A turn can still be slow or fail. It cannot run without bound. |
| T-LLM-6 | Prompts leave the machine: a cloud model is used, or the endpoint is not local. | I | Potato accepts only a loopback address for Ollama and only model names on an allowlist; cloud-tagged models are rejected. There is no fallback to any other service. | Planned (M1, M3) | Potato checks its own configuration. It cannot control how Ollama itself is configured, so it warns when Ollama's settings look wrong. |
| T-LLM-7 | Ollama is not running, or another local program answers on its port. | D, S, I | A health check and a clear "AI engine offline" state; every other feature keeps working. Responses are untrusted whoever sent them, so an impostor gains no more than the real model has. | Planned (M3) | A program already running as the user could receive prompts by sitting on that port. That is same-user malware, which is out of scope. |
| T-LLM-8 | The model weights themselves are poisoned or backdoored. | T | None that detects it. The design limits the damage instead: a hostile model has exactly the abilities of an honest one, and those stop at the gate. | Planned (M2) | A hostile model can give bad answers and choose allowed low-risk tools at the wrong moment. |

### Voice

| ID | Threat | STRIDE | Defence | Status | What remains |
| --- | --- | --- | --- | --- | --- |
| T-VOICE-1 | A video, a visitor or a recording says "Potato" and gives a command. | S | Voice reaches only low-risk tools (P6), with rate limits. The wake word must also appear in the transcript before anything happens. The current state is always visible. | Planned (M2, M7) | Potato does not identify the speaker. Anyone in earshot can use the low-risk tools, for example open an approved application. |
| T-VOICE-2 | Speech recognition mishears a command and the wrong thing happens. | T | No destructive tool exists. Changes to stored data are not available by voice at all (P6). | Planned (M2) | The wrong low-risk action can run, and is easy to see and undo. |
| T-VOICE-3 | Voice is used to approve a sensitive action. | S, E | Approvals can only be created by the interface from a physical input event (P7, R4). The voice code has no path to create one, and a test proves it. | Planned (M2, M7) | Software the user has granted control of the computer can imitate a click. See T-APPR-4. |
| T-VOICE-4 | Potato listens to, or keeps, more audio than the user expects. | I | In standby only the wake-word detector runs; nothing is transcribed. Audio is never written to disk. Mute closes the microphone stream completely. The microphone state is shown at all times. | Planned (M7) | In standby the microphone stream is open, because the wake-word detector needs it. The interface says so. |
| T-VOICE-5 | Private data is read aloud to whoever asks: portfolio value, calendar details. | I | A setting chooses, per category, whether results are spoken or only shown. Portfolio figures default to shown only. | Planned (M7) | Calendar reminders are spoken by design, so a visitor who asks can hear them. |

### Approvals

No version 1.0 tool is sensitive enough to need approval. The mechanism is
still built and tested, so that it is ready before any such tool is added.
The protocol is described in [permissions.md](permissions.md).

| ID | Threat | STRIDE | Defence | Status | What remains |
| --- | --- | --- | --- | --- | --- |
| T-APPR-1 | An old approval is used again, or used after it expired. | S, E | Each approval carries a random nonce and a short expiry. It is accepted once and marked used before the action runs. | Planned (M2) | Within its lifetime an approval can be used once, for exactly what it names. |
| T-APPR-2 | The action or its arguments change after the user approved. | T | The approval is a keyed hash over the tool name and the exact validated arguments. Any change makes it invalid. | Planned (M2) | None known in the design. The implementation must hash exactly what is executed. |
| T-APPR-3 | An approval is forged. | S, E | The signing key is random, made at start-up, kept in memory only and never logged. Comparison is constant-time. | Planned (M2) | Code running inside Potato's own process could read the key. That is why only the interface package may create approvals (R4). |
| T-APPR-4 | The user is tricked or rushed into approving, or a program clicks for them. | S | The dialog text is built by code from the validated arguments. Model-written text never appears in it. The default button is "Deny". | Planned (M2, M8) | A user who clicks without reading, and software the user has allowed to control the computer, are both outside what Potato can prevent. |

### Tools

| ID | Threat | STRIDE | Defence | Status | What remains |
| --- | --- | --- | --- | --- | --- |
| T-TOOL-1 | The application launcher starts something that was never approved, or a fake with a familiar name. | E, S | The model picks from a fixed list of names. Code maps the name to an application identifier, resolves its location and requires a standard applications folder. Nothing is passed to the application: no arguments, files or links. | Planned (M4) | An approved application that has itself been replaced on disk would still be opened. Replacing it needs the user's own rights, which is out of scope. |
| T-TOOL-2 | Calendar events are changed or deleted, although access is meant to be read-only. | T | macOS grants calendar access as all-or-nothing, so read-only is enforced in Potato's code. The calendar integration contains only fetch functions, and a test fails if a save or remove call appears. | Planned (M5) | The operating-system permission is wider than Potato needs. |
| T-TOOL-3 | The ability to start system tools, needed for security status checks, is abused to run something else. | E | One module may start a process (R3). It uses absolute paths and fixed arguments, never a shell, with a timeout and an output cap. Nothing from the model or from external data reaches it. | Planned (M6) | The fixed commands are trusted to be Apple's own. |
| T-TOOL-4 | The process and network monitors collect or reveal more than they should. | I | They record names, identifiers, resource use and program locations. They do not record command-line arguments or environment variables, which often contain secrets. They inspect this Mac only and never scan. | Planned (M6) | Without administrator rights the view is partial. It is labelled as partial, never presented as complete. |
| T-TOOL-5 | Checking a suspicious link contacts the link, or sends it to a third party. | I | The link analyser only examines text. It makes no network request of any kind. | Planned (M6) | Text analysis misses things a live check would catch. The result says what was and was not checked. |
| T-TOOL-6 | The user, or the model on the user's behalf, asks for something outside the safe scope: delete a file, run a command, send a message, place a trade. | E | No such tool exists, so the request has nowhere to go. The reply is a fixed refusal. Adding a tool requires an entry in [permissions.md](permissions.md) and an update to this file in the same change. | Planned (M2) | Scope can grow in future versions. Each addition must be threat-modelled first. |

### Network

| ID | Threat | STRIDE | Defence | Status | What remains |
| --- | --- | --- | --- | --- | --- |
| T-NET-1 | Someone on the network reads or alters the market data connection. | T, I | TLS with certificate validation that is never switched off. The API key travels in a header, never in the address. Timeouts on every request. | Planned (M4) | If the provider itself sends wrong prices, Potato shows wrong prices. It only displays them and never acts on them. |
| T-NET-2 | An API response is oversized, malformed or carries text aimed at the model. | T, D | A response size cap and a strict schema. Numbers are parsed as numbers. Text fields are length-capped and treated as data (T-LLM-1). | Planned (M4) | None known in the design. |
| T-NET-3 | Potato or Ollama can be reached from the network. | E, I | Potato opens no listening socket at all. Ollama must be on a loopback address, or Potato refuses to use it. Ollama's own protections against web pages calling it are left at their defaults. | Planned (M1) | Other programs on the same Mac can talk to Ollama. That is how Ollama is designed. |
| T-NET-4 | Lookups reveal the user's holdings to the data provider. | I | Only ticker symbols are sent. Quantities, prices paid and totals never leave the Mac. | Planned (M4) | The provider learns which symbols are watched, and from which address. |

### Stored data and secrets

| ID | Threat | STRIDE | Defence | Status | What remains |
| --- | --- | --- | --- | --- | --- |
| T-DATA-1 | A secret ends up in source code, a log, the database or an error message. | I | The one credential lives in the macOS Keychain. Every log handler has a redaction filter, and a test plants a known secret and searches the logs for it. Secret scanning runs on every commit. | Partly done | Secret scanning is active today. Redaction relies on recognising a secret's shape or value, so an unusual format could slip through. |
| T-DATA-2 | Other software running as the same user reads the database or logs. | I | Files are readable by the owner only. No credential is stored in them. | Planned (M1) | The data is not separately encrypted. Disk encryption protects it when the Mac is off, not from software running as the user. This is accepted. |
| T-DATA-3 | The audit log is altered or erased to hide an action. | R, T | Each entry includes a hash of the one before, so an edit breaks the chain and is detectable. | Planned (M1) | Tamper-evident, not tamper-proof. Someone who can rewrite the whole file can rebuild the chain. |
| T-DATA-4 | Private content is written to logs: conversations, calendar text. | I | The audit log records what kind of event happened, which tool and what was decided. It stores a digest of the arguments, not the arguments. Conversations are not logged. | Planned (M1) | Tool names and timing alone reveal something about the user's activity. |
| T-DATA-5 | Crafted text changes a database query. | T | Parameterised queries only. A lint rule flags any query built from strings. | Partly done | The lint rule is active today. The database does not exist yet. |
| T-DATA-6 | Editing a settings file weakens security: a longer allowlist, a remote model address. | T, E | Allowlists and risk levels live in code, not in settings (R7). Settings are validated, and the security-relevant ones can only be set within fixed bounds. | Planned (M1) | Anyone who can edit the code can change anything. That is same-user access, which is out of scope. |

### Supply chain and repository

| ID | Threat | STRIDE | Defence | Status | What remains |
| --- | --- | --- | --- | --- | --- |
| T-SUPPLY-1 | A Python dependency is vulnerable or malicious. | T, E | Few dependencies, each justified. Known vulnerabilities are checked in CI, and updates are proposed automatically. A lock file with hashes pins exactly what is installed. | Partly done | The vulnerability check and update proposals are active. The lock file arrives with the first runtime dependency. A brand-new malicious release can still pass every check. |
| T-SUPPLY-2 | A GitHub Action used in CI is hijacked. | T, E | Every action is pinned to a full commit hash. Workflows have read-only permission and no secrets. Tests in `tests/test_repository_security.py` fail if this is weakened. | Done | A pinned commit that was already malicious when pinned. |
| T-SUPPLY-3 | A secret is committed to the public repository. | I | Gitleaks runs before every commit and again in CI over the whole history. Local data, keys and environment files are ignored by Git. | Done | A secret in a format no scanner recognises. If one is ever committed it is revoked first; rewriting history comes second. |
| T-SUPPLY-4 | An unreviewed or failing change reaches `main`. | T | A ruleset on `main` requires a pull request and six passing checks, and blocks force pushes and deletion. | Done | The repository owner can change the ruleset. |
| T-SUPPLY-5 | A downloaded model file (wake word, speech) has been tampered with. | T | Model files are checked against a recorded SHA-256 hash before loading. Formats that can run code when loaded are not used. Model files are never committed. | Planned (M7) | The hash proves the file is the one that was chosen, not that the one chosen is trustworthy. |

## The five that matter most

Ranked by how likely each is and how much it would cost.

1. **T-LLM-1, injected text triggering a tool.** The standard attack on
   assistants that read external content. The two-pass design exists
   because of it.
2. **T-VOICE-1 and T-VOICE-5, anyone in the room.** Likely in shared
   accommodation. The cost is kept low by what voice is allowed to do and
   to say.
3. **T-LLM-2, trusting model output as an action.** The reason the
   permission manager is built before any tool.
4. **T-SUPPLY-1, a bad dependency.** It would bypass every other defence, so
   the dependency list stays short.
5. **T-DATA-2, local data readable by same-user software.** Accepted rather
   than solved. It is listed here so that nobody assumes otherwise.

## Out of scope

Potato does not defend against the following. They are stated so that the
limits are clear, not because they are unimportant.

- **Malware already running as the user.** It can read Potato's files and
  memory, imitate input and replace Potato's code.
- **An attacker with administrator rights, or with hands on the unlocked
  Mac.**
- **A compromised operating system, Python interpreter or Ollama program.**
- **Detecting a backdoored model.** The design limits what such a model
  could do (T-LLM-8); it cannot detect one.
- **Knowing who is speaking.** There is no speaker verification.
- **Protecting other devices or networks.** Potato inspects this Mac only.
- **Staying available under attack.** A local attacker can always stop
  Potato. The aim is that it fails safe, not that it cannot be stopped.

## Tests the specification requires

The project specification lists fourteen things that tests must prove. This
table connects each one to a threat and to the milestone where the test
lands. None of these tests exists yet.

| # | Tests must prove that | Threat | Lands in |
| --- | --- | --- | --- |
| 1 | The model cannot execute shell commands. | T-LLM-2, T-LLM-3 | M2 |
| 2 | The model cannot execute Python code. | T-LLM-2, T-LLM-3 | M2 |
| 3 | Unknown tools are rejected. | T-LLM-2 | M2 |
| 4 | Invalid tool arguments are rejected. | T-LLM-2 | M2 |
| 5 | External content cannot override system instructions. | T-LLM-1 | M3 |
| 6 | Voice confirmation cannot approve sensitive actions. | T-VOICE-3 | M2 |
| 7 | Expired approvals are rejected. | T-APPR-1 | M2 |
| 8 | Modified approvals are rejected. | T-APPR-2 | M2 |
| 9 | The application launcher rejects unknown applications. | T-TOOL-1 | M4 |
| 10 | The Ollama endpoint is not configured for network exposure. | T-NET-3, T-LLM-6 | M1 |
| 11 | Secrets are not written to logs. | T-DATA-1 | M1 |
| 12 | The application functions safely when Ollama is unavailable. | T-LLM-7 | M3 |
| 13 | The application enters standby correctly. | T-VOICE-4 | M1 |
| 14 | The model unloads after the idle timeout. | None: a resource requirement, tested all the same | M7 |

## Keeping this document true

- A change that adds a tool, an integration, a network connection or a data
  store updates this file in the same pull request.
- When a defence is built, its *Status* changes to `Done` in the commit that
  adds its tests, not before.
- `tests/test_documentation.py` checks that every threat ID mentioned
  anywhere in the documentation is defined here, and that every row has a
  valid status.
- The whole document is re-read at each milestone.
