## attachment_reader.py under io_manager.py
"""PhishGuard I/O: AttachmentReader definition."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional
from .input_validator import InputValidator
from .io_config import MAX_IMAGE, MAX_FILE

class AttachmentReader:
    """Accept a filename or a real file; never open/execute attachments."""
    TYPES = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp",
             "GIF": "image/gif", "BMP": "image/bmp"}

    @staticmethod
    def _hash(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    def _image_info(cls, path: Path) -> Optional[str]:
        """Return the MIME type of a supported image, else None (not an error:
        the file is then simply treated as a normal, non-image attachment)."""
        from PIL import Image, UnidentifiedImageError
        try:
            with Image.open(path) as image:
                if image.format not in cls.TYPES or image.width * image.height > 30_000_000:
                    return None
                image.verify()
                return cls.TYPES[image.format]
        except (UnidentifiedImageError, Image.DecompressionBombError, OSError, SyntaxError):
            return None

    def inspect(self, raw: str, image_only: bool = False) -> Dict:
        raw = raw.strip().strip('"').strip("'")
        path = Path(raw).expanduser()
        if not path.is_file():
            if image_only or "/" in raw or "\\" in raw or raw.startswith("~"):
                raise ValueError("File not found. Check the path.")
            if not InputValidator.filename(raw):
                raise ValueError("Enter a filename with an extension, e.g. invoice.pdf")
            return {"name": raw, "size_bytes": None, "sha256": None,
                    "path": None, "is_image": False, "file_provided": False}
        try:
            size = path.stat().st_size
            limit = MAX_IMAGE if image_only else MAX_FILE
            if not 0 < size <= limit:
                raise ValueError(f"File must be 1 byte to {limit // 1048576} MB")
            mime = self._image_info(path)
            if image_only and not mime:
                raise ValueError("Screenshot must be a valid PNG, JPEG or WEBP")
            return {"name": path.name, "size_bytes": size, "sha256": self._hash(path),
                    "path": str(path.resolve()), "is_image": bool(mime),
                    "file_provided": True, "mime_type": mime}
        except OSError as exc:
            raise ValueError(f"Unable to inspect file: {exc}") from exc

