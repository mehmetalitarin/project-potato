# Permissions

> **Status: design document.** The permission manager is built in milestone 2
> and nothing below exists in code yet. This file is the specification that
> code will be tested against.

Related documents: [threat model](threat_model.md),
[architecture](architecture.md).

## The idea

The model can ask. It cannot decide.

Every action Potato takes starts as a *proposal*: a tool name and some
arguments. The permission manager, called "the gate" here, checks the
proposal against rules written in code and either runs the tool or refuses.
The model has no way to change those rules, skip the gate or mark its own
request as approved.

## What the gate guarantees

Each guarantee has a stable ID. Tests name the guarantee they prove.

| ID | Guarantee | Threats |
| --- | --- | --- |
| P1 | **Single entry.** No tool runs except through the gate. | T-LLM-2 |
| P2 | **Allowlist.** Only tools in a list defined in code can run. Anything else is denied. | T-LLM-2, T-TOOL-6 |
| P3 | **Strict arguments.** Arguments must match the tool's schema exactly. Unknown fields, wrong types and out-of-range values are denied. Nothing is guessed or silently converted. | T-LLM-2 |
| P4 | **No execution inputs.** No tool accepts a command, source code or a file path. The link analyser accepts a link as text to examine and never opens it. | T-LLM-2, T-LLM-3, T-TOOL-5 |
| P5 | **Risk is fixed in code.** Every tool has a risk level set where the tool is defined. A request cannot raise or lower it. | T-DATA-6 |
| P6 | **Origin limits reach.** Every request records where it came from: voice, typed text or the interface. Voice reaches low-risk tools only. | T-VOICE-1, T-VOICE-2 |
| P7 | **Sensitive needs a physical approval.** A sensitive tool runs only with a valid approval: created by a click or key press, bound to the exact tool and arguments, unexpired and unused. | T-VOICE-3, T-APPR-1, T-APPR-2, T-APPR-3 |
| P8 | **Rate limits.** Each tool, and the gate as a whole, accepts a bounded number of calls per period. | T-LLM-5, T-VOICE-1 |
| P9 | **Timeouts.** Every tool runs under a time limit. | T-LLM-5 |
| P10 | **Default deny, fail closed.** A request is denied unless every check passes. If a check raises an error, the answer is no. | T-LLM-2 |
| P11 | **No action without a record.** The decision is written to the audit log before the tool runs. If the record cannot be written, the tool does not run. | T-DATA-3 |
| P12 | **Decisions are not model fields.** Risk level, origin and approval are never read from the model's output. | T-LLM-2, T-VOICE-3 |
| P13 | **Safe refusals.** A denial returns a fixed message and a reason code. It never contains a secret or internal detail. | T-DATA-1 |
| P14 | **Results are data.** Tool output is typed, size-capped and summarised with tools switched off. | T-LLM-1, T-NET-2 |

## The checks, in order

1. **Parse.** The proposal must be well-formed. Otherwise deny.
2. **Allowlist.** The tool name must be in the list (P2).
3. **Arguments.** Validate against the tool's schema (P3).
4. **Origin.** The tool's risk level must be reachable from this origin (P6).
5. **Approval.** If the tool is sensitive, verify the approval (P7).
6. **Rate limit.** Check the tool's and the global limit (P8).
7. **Audit.** Write the decision (P11).
8. **Run.** Call the tool with the validated arguments, under a timeout (P9).
9. **Audit again.** Record the outcome and how long it took.

A failure at any step stops the sequence, and the denial is itself written
to the audit log.

## Risk levels

| Level | Meaning | Voice | Typed or clicked | Physical approval |
| --- | --- | --- | --- | --- |
| **Low** | Reads information, or does something visible and easily undone. | Yes | Yes | No |
| **Medium** | Changes Potato's own stored data, or starts something slow that contacts an outside service. | No | Yes | No |
| **Sensitive** | Anything with an effect that is hard to undo or reaches beyond Potato. | No | Only with approval | Yes |

Some things have no level because no tool for them exists or will exist in
version 1.0: running commands or code, reading or changing files,
administrator actions, changing system settings, installing software,
sending messages, making calls, trading and remote control.

**Version 1.0 has no sensitive tool.** The approval mechanism is built and
tested with a tool that exists only in the test suite, so it is proven
before anything depends on it.

## Planned tools for version 1.0

Names are provisional. This table is updated in the commit that adds each
tool, and a tool that is not in this table must not be in the code.

| Tool | What it does | Arguments from the model | Risk |
| --- | --- | --- | --- |
| `open_app` | Opens an approved application | One name from a fixed list | Low |
| `portfolio_summary` | Shows holdings, value, profit and loss | None | Low |
| `portfolio_add_holding` | Records a holding | Symbol (strict pattern), quantity, average price (bounded numbers) | Medium |
| `portfolio_remove_holding` | Removes a holding | Symbol (strict pattern) | Medium |
| `calendar_upcoming` | Lists upcoming events | Number of days, bounded | Low |
| `homework_deadlines` | Lists upcoming deadlines | Number of days, bounded | Low |
| `security_posture` | Reads disk encryption, firewall and Gatekeeper status | None | Low |
| `process_overview` | Lists running processes and unusual resource use | None | Low |
| `network_overview` | Lists this Mac's connections and listening ports | None | Low |
| `analyse_link` | Examines a link's text for signs of phishing | The link as text, length-capped; never opened | Low |
| `check_security_updates` | Asks Apple's tool whether updates are available | None | Medium |
| `dependency_scan` | Reports known vulnerabilities in Potato's own packages | None | Medium |

Going to sleep and muting can be requested by voice, because they only
reduce what Potato can do. Leaving sleep or un-muting cannot.

The model is offered only the tools its current origin may use. This is a
convenience that reduces mistakes. It is not the defence: the gate checks
the origin again whatever the model was offered.

## Physical approval

Voice confirmation is never accepted. An approval works like this:

1. The gate receives a valid proposal for a sensitive tool and has no
   approval for it. It denies the request with the reason
   `APPROVAL_REQUIRED` and hands the interface a description of the exact
   tool and validated arguments.
2. The interface shows a dialog. Its text is built by code from those
   validated arguments. Nothing written by the model appears in it. The
   default button is "Deny".
3. If the user clicks "Approve" or presses the matching key, the interface
   creates an approval token: a keyed hash (HMAC-SHA-256) over the tool
   name, the arguments in a canonical form, a random nonce and an expiry
   time.
4. The request is submitted again with the token. The gate recomputes the
   hash over the arguments it is about to execute and compares in constant
   time. It checks the expiry and that the nonce has not been seen, marks
   the nonce as used, and only then runs the tool.

| Requirement | How it is met |
| --- | --- |
| Started from the interface or keyboard | Only the `ui` package can create a token (R4 in [architecture.md](architecture.md)). |
| Clearly describes the action | Dialog text comes from validated arguments, not from the model. |
| Tied to the exact action and arguments | The hash covers the tool name and canonical arguments. |
| Expires quickly | An expiry inside the hash; planned default 30 seconds, adjustable only within fixed bounds. |
| Invalid if any argument changes | A changed argument gives a different hash. |
| Rejects duplicates and replays | Each nonce is accepted once. |

The signing key is 32 random bytes, generated when Potato starts, held in
memory only and never written anywhere.

**Why a keyed hash inside one process?** It does not protect against code
running inside Potato, which could read the key. What it does is make the
binding between "what the user saw" and "what runs" a single check that
cannot be half-implemented: if anything differs, verification fails.

**Known limits.** Software that the user has allowed to control the
computer can imitate a click. A user can approve without reading. Neither
can be prevented from inside Potato (T-APPR-4).

## Reason codes

A request that does not complete carries exactly one of these. The user and
the model see only the code and a fixed sentence.

| Code | Meaning |
| --- | --- |
| `MALFORMED_REQUEST` | The proposal could not be parsed. |
| `UNKNOWN_TOOL` | The tool is not in the allowlist. |
| `INVALID_ARGUMENTS` | The arguments do not match the schema. |
| `ORIGIN_NOT_ALLOWED` | This tool cannot be used from this origin. |
| `APPROVAL_REQUIRED` | A sensitive tool was requested without an approval. |
| `APPROVAL_INVALID` | The approval does not match, has expired or was already used. |
| `RATE_LIMITED` | Too many calls. |
| `TIMED_OUT` | The tool exceeded its time limit. |
| `INTERNAL_ERROR` | A check failed unexpectedly. Treated as a denial. |

`APPROVAL_INVALID` deliberately does not say which of the three reasons
applied. The audit log does.

## What the audit log records

For every decision: the time, the tool name, the origin, allow or deny, the
reason code, a digest of the arguments, the duration and the hash that
links the entry to the one before it.

It does not record the arguments themselves, the conversation, calendar
text or any credential (T-DATA-4).

## Adding a tool

A new tool needs, in the same pull request:

1. A row in the table above, with its risk level and arguments.
2. A schema that accepts as little as possible.
3. Tests for unknown fields, wrong types, boundary values and the wrong
   origin.
4. A review of [threat_model.md](threat_model.md), and a new threat entry if
   the tool touches anything new.
