"""Command-line entry point for Potato.

Run with ``python -m potato`` or the ``potato`` console script.

At this stage the entry point reports the version and the project status,
and can check the settings file. It starts no assistant, opens no microphone
and makes no network connections.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from potato import __version__
from potato.core.config import ConfigError, parse_settings
from potato.storage.settings_file import (
    SettingsFileError,
    default_settings_path,
    read_settings_file,
)

STATUS_MESSAGE = (
    f"Potato {__version__} - project scaffold.\n"
    "No assistant features are implemented yet. See README.md for the roadmap."
)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser.

    Returns:
        A parser that understands ``--help``, ``--version`` and
        ``--check-settings``.
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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Arguments to parse. Defaults to ``sys.argv[1:]`` when ``None``.

    Returns:
        The process exit code: ``0`` on success, ``2`` for invalid settings.
    """
    arguments = build_parser().parse_args(argv)
    if arguments.check_settings:
        return check_settings(default_settings_path())
    print(STATUS_MESSAGE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
