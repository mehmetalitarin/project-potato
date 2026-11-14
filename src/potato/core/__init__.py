"""Assistant core: state machine, configuration and turn orchestration.

Boundary: this package decides *what should happen next* but never touches the
operating system or calls a tool itself. Every action it wants goes through
``potato.security``.

So far: ``config``, the validated settings; ``state``, the assistant's
states and the rules for moving between them; and ``turns``, which runs one
conversation turn in two passes.
"""
