import re


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by allowing only [a-zA-Z0-9.-_] characters.

    One or more consecutive characters outside of [a-zA-Z0-9.-] are
    replaced with a single '_'.

    Args:
        filename: The filename string to sanitize

    Returns:
        A sanitized filename string safe for filesystem use
    """
    return re.sub(r"[^a-zA-Z0-9.-]+", "_", filename)
