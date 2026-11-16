"""Integrations: the only code that talks to anything outside the process.

So far: ``ollama``, the client for the local model server; ``market_data``,
the client for market prices; ``processes``, the only code allowed to start
another program (it opens checked applications and runs a fixed list of
read-only system commands); and ``calendar``, which reads Apple
Calendar, read-only.

Boundary: integrations accept typed, validated arguments only. They never
accept free-form text from the model, and everything they return is treated
as untrusted data.
"""
