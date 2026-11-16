"""Shared test settings.

Qt is told to draw into memory instead of onto a screen, so the interface
tests run anywhere, including CI machines that have no display.

Qt objects are also cleaned up in a fixed order after every test. Left to
Python's garbage collector, a window from an earlier test could be destroyed
at a random moment while a later test had a request running on another
thread, which crashed the test run on macOS.
"""

import gc
import os
import threading
from collections.abc import Iterator

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Background threads that Potato's own code starts.
_POTATO_THREADS = ("potato-turn", "potato-unload", "potato-dashboard")


def _wait_for_potato_threads(seconds: float) -> bool:
    """Wait for Potato's background threads. Returns whether there were any."""
    found = False
    for thread in threading.enumerate():
        if thread.name.startswith(_POTATO_THREADS):
            found = True
            thread.join(seconds)
    return found


@pytest.fixture(autouse=True)
def clean_up_qt_objects() -> Iterator[None]:
    """Collect garbage only between tests, after Qt objects are deleted properly."""
    gc.disable()
    try:
        yield
    finally:
        used_threads = _wait_for_potato_threads(10.0)
        try:
            from PySide6.QtCore import QCoreApplication, QEvent
            from PySide6.QtWidgets import QApplication
        except ImportError:  # pragma: no cover - PySide6 is a dependency
            application = None
        else:
            application = QApplication.instance()
        used_qt = False
        if isinstance(application, QApplication):
            application.processEvents()
            for widget in application.topLevelWidgets():
                used_qt = True
                widget.close()
                widget.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            application.processEvents()
        gc.enable()
        if used_qt or used_threads:
            gc.collect()
