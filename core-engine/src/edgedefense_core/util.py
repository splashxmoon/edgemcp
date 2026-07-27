"""Small shared helpers used across the engine and its consumers."""

from __future__ import annotations


def human_bytes(count: float) -> str:
    """Format a byte count the way a person would say it."""
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB"):
        if abs(count) < step or unit == "GB":
            if unit == "B":
                return f"{int(count)} B"
            return f"{count:.1f} {unit}"
        count /= step
    return f"{count:.1f} GB"


def human_duration(seconds: float) -> str:
    """Format a duration in seconds as a short phrase."""
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    minutes, remainder = divmod(seconds, 60)
    if remainder == 0:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return f"{minutes}m {remainder}s"


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    """Return "1 device" / "3 devices" without callers repeating the ternary."""
    word = singular if count == 1 else (plural_form or f"{singular}s")
    return f"{count} {word}"
