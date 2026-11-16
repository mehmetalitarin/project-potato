"""Desktop interface (PySide6).

Boundary: presentation only, with no business logic. This is the one place a
physical approval can start.

So far: ``window``, the main window, for typed conversations and Potato's
state; and ``text``, which makes untrusted text safe to show. Everything is
shown as plain text.

Planned: the approval dialog and the security dashboard.
"""
