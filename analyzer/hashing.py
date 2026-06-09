import hashlib


CHUNK_SIZE = 8192  # Read in 8KB chunks to handle large files efficiently


def compute_hashes(filepath: str) -> dict:
    """
    Compute MD5, SHA-1, and SHA-256 hashes for a file.
    Returns a dict with all three hash values.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
    except (OSError, IOError) as e:
        return {"error": str(e)}


def verify_hash(filepath: str, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Verify a file against a known-good hash.
    Returns True if it matches, False otherwise.
    """
    hashes = compute_hashes(filepath)
    if "error" in hashes:
        return False
    return hashes.get(algorithm, "").lower() == expected_hash.strip().lower()
