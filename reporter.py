import json
import datetime
import os


TOOL_VERSION = "1.0.0"


def build_report(filepath: str, hashes: dict, filetype: dict, metadata: dict, analyst: str = "Unknown") -> dict:
    """Assemble all findings into a structured forensic report."""
    flags = []

    if filetype.get("spoofing_alert"):
        flags.append(
            f"EXTENSION SPOOFING: File extension '{filetype.get('file_extension')}' "
            f"does not match true type '{filetype.get('true_mime')}'"
        )

    if metadata.get("timestamp_anomaly"):
        flags.append(metadata["timestamp_anomaly"])

    if hashes.get("error"):
        flags.append(f"HASHING ERROR: {hashes['error']}")

    gps = None
    img_meta = metadata.get("image", {})
    if img_meta.get("gps_present"):
        gps = img_meta.get("gps_fields", [])
        flags.append("GPS DATA PRESENT in image EXIF — location may be embedded.")

    return {
        "report_meta": {
            "tool": "ForensicsCLI",
            "version": TOOL_VERSION,
            "analyst": analyst,
            "generated_at": datetime.datetime.now().isoformat(),
            "target_file": os.path.abspath(filepath),
            "filename": os.path.basename(filepath),
        },
        "hashes": hashes,
        "filetype": filetype,
        "metadata": metadata,
        "flags": flags,
        "gps_fields_found": gps,
        "risk_level": _assess_risk(flags),
    }


def _assess_risk(flags: list) -> str:
    """Simple risk scoring based on number and type of flags."""
    if not flags:
        return "CLEAN"
    for f in flags:
        if "SPOOFING" in f:
            return "HIGH"
    if len(flags) >= 2:
        return "MEDIUM"
    return "LOW"


def output_json(report: dict, output_path: str = None) -> str:
    """Serialize report to JSON, optionally writing to file."""
    content = json.dumps(report, indent=2, default=str)
    if output_path:
        with open(output_path, "w") as f:
            f.write(content)
    return content


def output_text(report: dict, output_path: str = None) -> str:
    """Format report as a readable text summary."""
    sep = "=" * 60
    lines = [
        sep,
        "  DIGITAL FORENSICS REPORT",
        sep,
        f"  Tool        : {report['report_meta']['tool']} v{report['report_meta']['version']}",
        f"  Analyst     : {report['report_meta']['analyst']}",
        f"  Generated   : {report['report_meta']['generated_at']}",
        f"  Target File : {report['report_meta']['target_file']}",
        sep,
        "",
        "[ HASHES ]",
        f"  MD5    : {report['hashes'].get('md5', 'N/A')}",
        f"  SHA-1  : {report['hashes'].get('sha1', 'N/A')}",
        f"  SHA-256: {report['hashes'].get('sha256', 'N/A')}",
        "",
        "[ FILE TYPE ]",
        f"  True MIME   : {report['filetype'].get('true_mime', 'N/A')}",
        f"  Description : {report['filetype'].get('true_description', 'N/A')}",
        f"  Extension   : {report['filetype'].get('file_extension', 'N/A')}",
        f"  Match       : {'Yes' if report['filetype'].get('extension_match') else 'No' if report['filetype'].get('extension_match') is False else 'Unknown'}",
        "",
        "[ FILESYSTEM TIMESTAMPS ]",
    ]

    fs = report["metadata"].get("filesystem", {})
    lines += [
        f"  Created  : {fs.get('created', 'N/A')}",
        f"  Modified : {fs.get('modified', 'N/A')}",
        f"  Accessed : {fs.get('accessed', 'N/A')}",
        f"  Size     : {fs.get('size_bytes', 'N/A')} bytes",
        "",
    ]

    # Additional metadata sections
    for section in ["image", "pdf", "audio_video"]:
        section_data = report["metadata"].get(section)
        if section_data:
            lines.append(f"[ {section.upper()} METADATA ]")
            for k, v in section_data.items():
                if k == "exif":
                    lines.append("  EXIF Tags:")
                    for ek, ev in v.items():
                        lines.append(f"    {ek}: {ev}")
                elif not isinstance(v, (dict, list)):
                    lines.append(f"  {k}: {v}")
                elif isinstance(v, list) and v:
                    lines.append(f"  {k}: {', '.join(str(i) for i in v)}")
            lines.append("")

    # Flags
    lines.append("[ FLAGS & ANOMALIES ]")
    if report["flags"]:
        for flag in report["flags"]:
            lines.append(f"  ⚠  {flag}")
    else:
        lines.append("  ✓  No anomalies detected.")

    lines += [
        "",
        f"[ RISK LEVEL: {report['risk_level']} ]",
        sep,
    ]

    content = "\n".join(lines)
    if output_path:
        with open(output_path, "w") as f:
            f.write(content)
    return content
