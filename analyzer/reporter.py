import os
import stat
import datetime


def _get_file_timestamps(filepath: str) -> dict:
    """Extract filesystem-level timestamps."""
    try:
        s = os.stat(filepath)
        return {
            "created": datetime.datetime.fromtimestamp(s.st_ctime).isoformat(),
            "modified": datetime.datetime.fromtimestamp(s.st_mtime).isoformat(),
            "accessed": datetime.datetime.fromtimestamp(s.st_atime).isoformat(),
            "size_bytes": s.st_size,
            "permissions": oct(stat.S_IMODE(s.st_mode)),
        }
    except Exception as e:
        return {"error": str(e)}


def _extract_image_metadata(filepath: str) -> dict:
    """Extract EXIF and basic metadata from image files."""
    metadata = {}

    # Try exifread for detailed EXIF
    try:
        import exifread
        with open(filepath, "rb") as f:
            tags = exifread.process_file(f, stop_tag="EOF", details=False)
        exif = {}
        for tag, value in tags.items():
            exif[tag] = str(value)
        if exif:
            metadata["exif"] = exif
    except Exception:
        pass

    # Pillow for image dimensions and basic info
    try:
        from PIL import Image
        with Image.open(filepath) as img:
            metadata["dimensions"] = f"{img.width}x{img.height}"
            metadata["color_mode"] = img.mode
            metadata["format"] = img.format
            if hasattr(img, "info"):
                for k, v in img.info.items():
                    if isinstance(v, (str, int, float, tuple)):
                        metadata[f"pil_{k}"] = str(v)
    except Exception:
        pass

    # Flag if GPS data is present
    if "exif" in metadata:
        gps_keys = [k for k in metadata["exif"] if "GPS" in k]
        metadata["gps_present"] = len(gps_keys) > 0
        metadata["gps_fields"] = gps_keys if gps_keys else []

    return metadata


def _extract_pdf_metadata(filepath: str) -> dict:
    """Extract metadata from PDF files using PyMuPDF."""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(filepath)
        meta = doc.metadata
        info = {
            "page_count": doc.page_count,
            "encrypted": doc.is_encrypted,
        }
        for key, value in meta.items():
            if value:
                info[key] = value
        doc.close()
        return info
    except Exception as e:
        return {"error": str(e)}


def _extract_audio_video_metadata(filepath: str) -> dict:
    """Extract metadata from audio and video files using mutagen."""
    try:
        import mutagen
        audio = mutagen.File(filepath, easy=True)
        if audio is None:
            return {"error": "mutagen could not read file"}
        info = {}
        # Tags
        for key, value in audio.items():
            info[key] = str(value)
        # Stream info
        if hasattr(audio, "info"):
            stream = audio.info
            if hasattr(stream, "length"):
                info["duration_seconds"] = round(stream.length, 2)
            if hasattr(stream, "bitrate"):
                info["bitrate_kbps"] = stream.bitrate
            if hasattr(stream, "sample_rate"):
                info["sample_rate_hz"] = stream.sample_rate
            if hasattr(stream, "channels"):
                info["channels"] = stream.channels
        return info
    except Exception as e:
        return {"error": str(e)}


def extract_metadata(filepath: str, mime_type: str) -> dict:
    """
    Route to the correct extractor based on MIME type.
    Always includes filesystem timestamps.
    """
    result = {
        "filesystem": _get_file_timestamps(filepath),
    }

    if mime_type.startswith("image/"):
        result["image"] = _extract_image_metadata(filepath)
    elif mime_type == "application/pdf":
        result["pdf"] = _extract_pdf_metadata(filepath)
    elif mime_type.startswith("audio/") or mime_type.startswith("video/"):
        result["audio_video"] = _extract_audio_video_metadata(filepath)
    else:
        result["note"] = f"No specialized extractor for MIME type: {mime_type}"

    # Timestamp anomaly check: modified before created (possible tampering)
    fs = result.get("filesystem", {})
    created = fs.get("created")
    modified = fs.get("modified")
    if created and modified and not isinstance(created, dict):
        if modified < created:
            result["timestamp_anomaly"] = (
                "WARNING: File modified timestamp is earlier than created timestamp — possible clock manipulation."
            )

    return result
