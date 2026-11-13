"""Security gate: permission manager, approvals, audit log and log redaction.

Boundary: every tool call passes through this package. It never takes a
decision from model output; model output is only the *request* being judged.

So far: ``redaction``, ``logs``, ``audit``, ``private_files``, ``tools`` (how a
tool is described), ``gate`` (the permission manager) and ``approvals``
(physical approvals).
"""
