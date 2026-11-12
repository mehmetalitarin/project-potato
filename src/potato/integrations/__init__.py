"""Integrations: the only code that talks to anything outside the process.

Planned: the local Ollama HTTP client, the market data API, Apple Calendar,
application launching, the macOS Keychain and read-only system probes.

Boundary: integrations accept typed, validated arguments only. They never
accept free-form text from the model, and everything they return is treated
as untrusted data.

No code yet.
"""
