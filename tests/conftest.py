"""Shared test settings.

Qt is told to draw into memory instead of onto a screen, so the interface
tests run anywhere, including CI machines that have no display.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
