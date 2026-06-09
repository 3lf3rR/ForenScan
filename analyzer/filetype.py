import magic
import os


# Map of true MIME types to their expected extensions
MIME_TO_EXTENSIONS = {
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "image/gif": [".gif"],
    "image/webp": [".webp"],
    "image/bmp": [".bmp"],
    "image/tiff": [".tif", ".tiff"],
    "application/pdf": [".pdf"],
    "application/zip": [".zip"],
    "application/x-tar": [".tar"],
    "application/gzip": [".gz", ".tgz"],
    "application/x-7z-compressed": [".7z"],
    "application/x-rar-compressed": [".rar"],
    "application/vnd.ms-excel": [".xls"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
    "application/msword": [".doc"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
    "video/mp4": [".mp4"],
    "video/x-msvideo": [".avi"],
    "video/quicktime": [".mov"],
    "audio/mpeg": [".mp3"],
    "audio/wav": [".wav"],
    "application/x-executable": [".exe"],
    "application/x-dosexec": [".exe", ".dll"],
    "text/plain": [".txt", ".log", ".csv"],
    "text/html": [".html", ".htm"],
    "application/json": [".json"],
    "application/x-sqlite3": [".db", ".sqlite", ".sqlite3"],
}


def detect_filetype(filepath: str) -> dict:
    """
    Detect the true file type using magic bytes.
    Returns MIME type, description, and whether the extension matches.
    """
    try:
        mime = magic.Magic(mime=True)
        description = magic.Magic()

        true_mime = mime.from_file(filepath)
        true_description = description.from_file(filepath)
        file_ext = os.path.splitext(filepath)[1].lower()

        expected_exts = MIME_TO_EXTENSIONS.get(true_mime, [])
        extension_match = (file_ext in expected_exts) if expected_exts else None
        spoofing_alert = False

        if extension_match is False:
            spoofing_alert = True

        return {
            "true_mime": true_mime,
            "true_description": true_description,
            "file_extension": file_ext if file_ext else "(none)",
            "expected_extensions": expected_exts,
            "extension_match": extension_match,
            "spoofing_alert": spoofing_alert,
        }
    except Exception as e:
        return {"error": str(e)}
