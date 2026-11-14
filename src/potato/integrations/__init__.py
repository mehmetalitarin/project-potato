"""Integrations: the only code that talks to anything outside the process.

So far: ``ollama``, the client for the local model server, and
``market_data``, the client for market prices.

Planned: Apple Calendar, application launching, the macOS Keychain and
read-only system probes.

Boundary: integrations accept typed, validated arguments only. They never
accept free-form text from the model, and everything they return is treated
as untrusted data.
"""
