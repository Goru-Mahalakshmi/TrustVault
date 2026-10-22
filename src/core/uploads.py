import io, os, re, unicodedata, zipfile

ALLOWED = {".pdf", ".png", ".jpg", ".jpeg", ".webp", ".txt", ".csv", ".docx", ".xlsx"}
MIME = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".webp": "image/webp", ".txt": "text/plain", ".csv": "text/csv",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
_BAD_START = (b"MZ", b"\x7fELF", b"#!", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
_BAD_TEXT = (b"<!doctype html", b"<html", b"<svg", b"<?xml", b"<script")

def safe_filename(name: str) -> str:
    name = os.path.basename(name.replace("\\", "/"))
    name = unicodedata.normalize("NFKC", name)
    name = "".join(c for c in name if unicodedata.category(c)[0] != "C")
    return re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".")[:100] or "file"

def validate_upload(filename: str, data: bytes):
    """Returns an error message, or None when the upload is acceptable."""
    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED:
        return "File type not allowed"
    head = data[:4096]
    if head.startswith(_BAD_START) or head.lstrip().lower().startswith(_BAD_TEXT):
        return "File content not allowed"
    if ext in (".txt", ".csv"):
        ok = b"\x00" not in head
        try: head.decode("utf-8")
        except UnicodeDecodeError: ok = False
    else:
        ok = {".pdf": head.startswith(b"%PDF-"), ".png": head.startswith(b"\x89PNG\r\n\x1a\n"),
              ".jpg": head[:3] == b"\xff\xd8\xff", ".jpeg": head[:3] == b"\xff\xd8\xff",
              ".webp": head[:4] == b"RIFF" and head[8:12] == b"WEBP",
              ".docx": head[:4] == b"PK\x03\x04", ".xlsx": head[:4] == b"PK\x03\x04"}[ext]
    if not ok:
        return "File content does not match its extension"
    if ext in (".docx", ".xlsx"):
        try:
            infos = zipfile.ZipFile(io.BytesIO(data)).infolist()      # directory only, nothing extracted
        except zipfile.BadZipFile:
            return "Corrupt archive"
        total = sum(i.file_size for i in infos)
        if total > 100 * 1024 * 1024 or total > 100 * max(len(data), 1):
            return "Archive rejected (decompression bomb guard)"
    return None
