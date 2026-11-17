"""Download Potato's speech model once. Run it yourself; Potato never does.

    python scripts/download_speech_model.py

It fetches a pinned version of Whisper small.en (about 490 MB) from Hugging
Face over verified HTTPS, checks the SHA-256 of the model file against the
value pinned in Potato's code, and only then moves the folder into place.
Nothing half-downloaded is ever left where Potato looks.
"""

import hashlib
import shutil
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path

from potato.app import default_speech_model_folder
from potato.voice.transcriber import (
    MODEL_FILES,
    MODEL_REPOSITORY,
    MODEL_REVISION,
    MODEL_SHA256,
    check_model_folder,
)

BASE_URL = f"https://huggingface.co/{MODEL_REPOSITORY}/resolve/{MODEL_REVISION}/"
MAX_BYTES = {"model.bin": 600 * 1024 * 1024}
DEFAULT_MAX_BYTES = 10 * 1024 * 1024


def _context() -> ssl.SSLContext:
    try:
        import truststore  # Uses the Mac's own certificate store when present.

        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:
        return ssl.create_default_context()


def _download(name: str, target: Path, context: ssl.SSLContext) -> str:
    limit = MAX_BYTES.get(name, DEFAULT_MAX_BYTES)
    digest = hashlib.sha256()
    total = 0
    if name not in MODEL_FILES:
        raise SystemExit(f"Refused: {name} is not one of the model's files.")
    url = BASE_URL + name
    if not url.startswith("https://huggingface.co/"):
        raise SystemExit("Refused: the download address is not Hugging Face over HTTPS.")
    # A fixed https:// address built from pinned constants, checked above.
    request = urllib.request.Request(url, headers={"User-Agent": "potato-setup"})  # noqa: S310
    with urllib.request.urlopen(request, context=context, timeout=60) as response:  # noqa: S310 - fixed https URL
        if not response.geturl().startswith("https://"):
            raise SystemExit(f"Refused: {name} was redirected away from HTTPS.")
        with target.open("wb") as file:
            while piece := response.read(1024 * 1024):
                total += len(piece)
                if total > limit:
                    raise SystemExit(f"Refused: {name} is larger than expected.")
                digest.update(piece)
                file.write(piece)
                if name == "model.bin":
                    print(f"\r  model.bin: {total // (1024 * 1024)} MB", end="", flush=True)
    if name == "model.bin":
        print()
    return digest.hexdigest()


def main() -> int:
    """Download, check and install the model. Returns the exit code."""
    destination = default_speech_model_folder()
    try:
        check_model_folder(destination)
        print(f"The speech model is already installed and checked: {destination}")
        return 0
    except Exception:  # noqa: S110 - missing or wrong: download it again
        pass
    destination.parent.mkdir(parents=True, exist_ok=True)
    context = _context()
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        folder = Path(temporary) / "model"
        folder.mkdir()
        print(f"Downloading {MODEL_REPOSITORY} at {MODEL_REVISION[:7]}...")
        hashes = {name: _download(name, folder / name, context) for name in MODEL_FILES}
        if hashes["model.bin"] != MODEL_SHA256:
            print("Refused: model.bin does not match the checksum pinned in Potato.")
            return 1
        check_model_folder(folder)
        if destination.exists():
            shutil.rmtree(destination)
        folder.rename(destination)
    for name, value in hashes.items():
        print(f"  {name}  sha256 {value}")
    print(f"Installed: {destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
