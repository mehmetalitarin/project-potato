"""Desktop interface (PySide6).

Boundary: presentation only, with no business logic. This is the one place a
physical approval can start.

So far: ``window``, the main window, for typed conversations and Potato's
state; ``orb``, the animated picture of what Potato is doing, which can also
float above other applications; ``approval``, the dialog that is the only way
to approve a sensitive action; ``dashboard``, the security dashboard; and
``text``, which makes untrusted text safe to show. Everything is shown as
plain text.
"""
