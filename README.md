<h1 align="center">
  🔍 ForenScan
</h1>

<p align="center">
  <b>Digital Forensics Tool — File Analysis & Metadata Extraction</b><br/>
  Built for investigators, students, and security researchers.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square" />
</p>

---

## 📌 What is ForenScan?

**ForenScan** is a command-line digital forensics tool that helps you analyze files for hidden metadata, integrity issues, and suspicious anomalies. It computes cryptographic hashes, detects true file types via magic bytes, extracts EXIF/PDF/audio metadata, and generates detailed forensic reports — all from your terminal.

Whether you're investigating a suspicious file, validating evidence integrity, or learning digital forensics — ForenScan has you covered.

---

## 🖥️ Demo

### Tool Banner & Single File Analysis
> *Running ForenScan against a suspicious file and viewing the full forensic report*

<!-- SCREENSHOT: Run `python main.py --file suspicious.jpg --analyst "Your Name"` and paste a terminal screenshot here -->

```
[ screenshot coming soon ]
```

---

### Extension Spoofing Detection
> *ForenScan flagging a file whose extension doesn't match its true type*

<!-- SCREENSHOT: Rename a .exe or .pdf to .jpg and run it through ForenScan — show the HIGH risk flag output -->

```
[ screenshot coming soon ]
```

---

### Directory Scan Summary
> *Scanning a folder of mixed evidence files and viewing the summary*

<!-- SCREENSHOT: Run `python main.py --dir ./evidence/` and show the scan summary with flagged files -->

```
[ screenshot coming soon ]
```

---

### Hash Verification
> *Verifying a file's integrity against a known SHA-256 hash*

<!-- SCREENSHOT: Run `python main.py --file file.zip --verify "your_hash_here" --algorithm sha256` — show PASS or FAIL output -->

```
[ screenshot coming soon ]
```

---

### JSON Report Output
> *Exporting a structured forensic report to JSON*

<!-- SCREENSHOT: Run `python main.py --file photo.jpg --report json --output report.json` and show the saved JSON content -->

```
[ screenshot coming soon ]
```

---

## ⚙️ Installation

**Requirements:** Python 3.8+

```bash
# Clone the repo
git clone https://github.com/3lf3rR/ForenScan.git
cd ForenScan

# Install Python dependencies
pip install -r requirements.txt

# Linux only — install libmagic system dependency
sudo apt install libmagic1
```

---

## 🚀 Usage

### Analyze a single file
```bash
python main.py --file suspicious.jpg
```

### Analyze with analyst name
```bash
python main.py --file document.pdf --analyst "Jane Smith"
```

### Export report as JSON
```bash
python main.py --file photo.jpg --report json --output report.json
```

### Verify file integrity against a known hash
```bash
python main.py --file evidence.zip --verify "abc123..." --algorithm sha256
```

### Scan an entire directory
```bash
python main.py --dir ./evidence_folder/
```

### Save combined directory scan to file
```bash
python main.py --dir ./evidence_folder/ --report json --output combined.json
```

### All available flags
```
--file,      -f    Path to a single file to analyze
--dir,       -d    Path to a directory to scan
--analyst,   -a    Analyst name for the report (default: Unknown)
--report,    -r    Output format: text or json (default: text)
--output,    -o    Save report to a file
--verify,    -v    Known-good hash to verify file against
--algorithm        Hash algorithm for --verify: md5, sha1, sha256
--quiet,     -q    Suppress progress output
--help             Show help message
```

---

## 🔎 What ForenScan Detects

| Check | Description |
|---|---|
| 🔐 File Hashes | MD5, SHA-1, SHA-256 for integrity verification |
| 🧬 True File Type | Magic byte detection — not just the extension |
| ⚠️ Extension Spoofing | Flags `.jpg` files that are secretly `.exe` |
| 📷 EXIF Metadata | Camera model, timestamps, GPS coordinates |
| 📄 PDF Metadata | Author, software used, creation date |
| 🎵 Audio/Video Tags | Artist, duration, bitrate, sample rate |
| 🕐 Timestamp Anomalies | Modified before created — possible tampering |
| 📍 GPS Presence | Warns if location data is embedded in images |

---

## 🚦 Risk Levels

| Level | Meaning |
|---|---|
| ✅ `CLEAN` | No anomalies detected |
| 🟡 `LOW` | Minor flags (e.g. GPS data present) |
| 🟠 `MEDIUM` | Multiple flags found |
| 🔴 `HIGH` | Extension spoofing or serious anomaly detected |

---

## 📁 Project Structure

```
ForenScan/
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
├── README.md
└── analyzer/
    ├── __init__.py
    ├── hashing.py           # MD5 / SHA-1 / SHA-256 computation
    ├── filetype.py          # Magic byte detection & spoofing check
    ├── metadata.py          # EXIF, PDF, audio/video, filesystem metadata
    └── reporter.py          # Report builder — JSON & text output
```

---

## 👤 Author

Made by **[Your Name]** — feel free to open issues or contribute via pull requests.
