"""Assistant core: state machine, configuration and turn orchestration.

Boundary: this package decides *what should happen next* but never touches the
operating system or calls a tool itself. Every action it wants goes through
``potato.security``.

So far: ``config``, the validated settings.
"""
