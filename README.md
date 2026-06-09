# ForenScan 🔍
**Digital Forensics Tool — File Analysis & Metadata Extraction**

---

## Installation

```bash
pip install -r requirements.txt
```

> On Linux, you may also need: `sudo apt install libmagic1`

---

## Usage

### Analyze a single file
```bash
python main.py --file suspicious.jpg
```

### Analyze with analyst name + JSON output
```bash
python main.py --file document.pdf --analyst "Jane Smith" --report json
```

### Save report to file
```bash
python main.py --file photo.jpg --output report.txt
```

### Verify file integrity against a known hash
```bash
python main.py --file evidence.zip --verify "abc123..." --algorithm sha256
```

### Scan an entire directory
```bash
python main.py --dir ./evidence_folder/
```

### Save combined directory scan report
```bash
python main.py --dir ./evidence_folder/ --output combined_report.json --report json
```

---

## What It Detects

| Check | Description |
|---|---|
| File Hashes | MD5, SHA-1, SHA-256 for integrity verification |
| True File Type | Magic byte detection (not just extension) |
| Extension Spoofing | Flags `.jpg` files that are actually `.exe` |
| EXIF Metadata | Camera model, timestamps, GPS coordinates |
| PDF Metadata | Author, software, creation date |
| Audio/Video Tags | Artist, duration, bitrate, sample rate |
| Timestamp Anomalies | Modified before created (possible tampering) |
| GPS Presence | Warns if location data is embedded in images |

---

## Risk Levels

- `CLEAN` — No anomalies found
- `LOW` — Minor flags (GPS present, etc.)
- `MEDIUM` — Multiple flags
- `HIGH` — Extension spoofing detected

---

## Project Structure

```
forensics_tool/
├── main.py              # CLI entry point
├── requirements.txt
├── README.md
└── analyzer/
    ├── __init__.py
    ├── hashing.py       # MD5/SHA1/SHA256 computation
    ├── filetype.py      # Magic byte detection
    ├── metadata.py      # EXIF, PDF, audio/video metadata
    └── reporter.py      # Report generation (JSON & text)
```
