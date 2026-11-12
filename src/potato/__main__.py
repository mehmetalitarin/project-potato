"""Command-line entry point for Potato.

Run with ``python -m potato`` or the ``potato`` console script.

At this stage the entry point only reports the version and the project
status. It starts no assistant, opens no microphone and makes no network
connections.
"""

import argparse
import sys
from collections.abc import Sequence

from potato import __version__

STATUS_MESSAGE = (
    f"Potato {__version__} - project scaffold.\n"
    "No assistant features are implemented yet. See README.md for the roadmap."
)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser.

    Returns:
        A parser that understands ``--help`` and ``--version`` only.
    """
    parser = argparse.ArgumentParser(
        prog="potato",
        description="Potato: a local-first personal assistant (project scaffold).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"potato {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Arguments to parse. Defaults to ``sys.argv[1:]`` when ``None``.

    Returns:
        The process exit code: ``0`` on success.
    """
    build_parser().parse_args(argv)
    print(STATUS_MESSAGE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
