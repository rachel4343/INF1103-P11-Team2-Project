## image_evidence_store.py under io_manager.py
"""Optional image-attachment storage (NOT used for screenshot OCR submissions)."""
from pathlib import Path
from typing import Dict
import hashlib
import os
import shutil
from PIL import Image, UnidentifiedImageError


class ImageEvidenceStore:
    """Save real image attachments when the employee explicitly consents."""
    FORMATS = {"PNG": ".png", "JPEG": ".jpg", "WEBP": ".webp", "GIF": ".gif", "BMP": ".bmp"}

    def __init__(self, storage_dir: str = "evidence_images"):
        self._directory = Path(storage_dir).resolve()

    def save_image(self, input_path: str) -> Dict:
        source = Path(input_path).expanduser().resolve()
        if not source.is_file() or not 0 < source.stat().st_size <= 10 * 1024 * 1024:
            raise ValueError("Image missing or larger than 10 MB")
        try:
            with Image.open(source) as image:
                fmt = image.format
                if fmt not in self.FORMATS or image.width * image.height > 30_000_000:
                    raise ValueError("Unsupported image")
                image.verify()
        except (OSError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
            raise ValueError("Invalid image") from exc
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self._directory.mkdir(parents=True, exist_ok=True)
        target = self._directory / (digest + self.FORMATS[fmt])
        if not target.exists():
            shutil.copyfile(source, target)
        return {"filename": source.name,
                "stored_path": target.relative_to(self._directory.parent).as_posix(),
                "sha256": digest, "size_bytes": source.stat().st_size,
                "mime_type": "image/jpeg" if fmt == "JPEG" else "image/" + fmt.lower()}
