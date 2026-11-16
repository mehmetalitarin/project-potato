"""Command-line entry point for Potato.

Run with ``python -m potato`` or the ``potato`` console script.

With no arguments it starts Potato and opens its window. ``--version`` and
``--check-settings`` report and exit without starting anything.
"""

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from potato import __version__
from potato.app import run
from potato.core.config import ConfigError, parse_settings
from potato.storage.settings_file import (
    SettingsFileError,
    default_settings_path,
    read_settings_file,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser.

    Returns:
        A parser that understands ``--help``, ``--version`` and
        ``--check-settings``.
    """
    parser = argparse.ArgumentParser(
        prog="potato",
        description="Potato: a local-first personal assistant. Run without options to start it.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"potato {__version__}",
    )
    parser.add_argument(
        "--check-settings",
        action="store_true",
        help="validate the settings file, show the result and exit",
    )
    return parser


def check_settings(path: Path) -> int:
    """Read and validate the settings file, and report the result.

    Args:
        path: Location of the settings file. It does not have to exist.

    Returns:
        ``0`` if the settings are valid, ``2`` if they are not.
    """
    try:
        text = read_settings_file(path)
        settings = parse_settings(text or "")
    except (SettingsFileError, ConfigError) as error:
        # These messages name the setting and the rule, never the bad value.
        print(f"Settings problem: {error}", file=sys.stderr)
        return 2

    source = "no settings file found, using the built-in defaults" if text is None else str(path)
    print(f"Settings are valid ({source}).")
    print(f"Model address: {settings.ollama.base_url}")
    print(f"Model: {settings.ollama.model}")
    return 0


def main(argv: Sequence[str] | None = None, *, start: Callable[[], int] = run) -> int:
    """Run the command-line interface.

    Args:
        argv: Arguments to parse. Defaults to ``sys.argv[1:]`` when ``None``.
        start: Starts Potato and returns when its window closes. Tests
            replace it.

    Returns:
        The process exit code: ``0`` on success, ``2`` for invalid settings,
        ``3`` if Potato could not start safely.
    """
    arguments = build_parser().parse_args(argv)
    if arguments.check_settings:
        return check_settings(default_settings_path())
    return start()


if __name__ == "__main__":
    sys.exit(main())
