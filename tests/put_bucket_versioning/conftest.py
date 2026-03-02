"""Shared utilities for PutBucketVersioning tests."""


def build_versioning_xml(status: str, xmlns: bool = True) -> bytes:
    """Build PutBucketVersioning XML body."""
    ns = ' xmlns="http://s3.amazonaws.com/doc/2006-03-01/"' if xmlns else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<VersioningConfiguration{ns}>"
        f"<Status>{status}</Status>"
        "</VersioningConfiguration>"
    ).encode("utf-8")


def build_versioning_xml_padded(
    status: str = "Enabled", target_bytes: int = 1_100_000
) -> bytes:
    """Build valid PutBucketVersioning XML padded with XML comment to target size."""
    header = b'<?xml version="1.0" encoding="UTF-8"?>\n<!-- '
    trailer = b" -->\n"
    footer = (
        '<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Status>{status}</Status>"
        "</VersioningConfiguration>"
    ).encode("utf-8")
    fixed = len(header) + len(trailer) + len(footer)
    padding = b"x" * max(1, target_bytes - fixed)
    return header + padding + trailer + footer


def build_null_prefixed_xml(
    status: str = "Enabled", prefix_bytes: int = 1_100_000
) -> bytes:
    """Build XML with null-byte prefix (mimics check_before_delete/generate_huge_xml.py pattern)."""
    prefix = b"\x00" * prefix_bytes
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"<Status>{status}</Status>"
        "</VersioningConfiguration>"
    ).encode("utf-8")
    return prefix + xml
