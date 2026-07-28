"""Running local commands without blocking the event loop.

The performance checks lean on OS tools (``netsh``, ``ping``, ``netstat``,
``nmcli``) far more than discovery does, so the subprocess plumbing lives here
rather than being repeated five times.

Two things this handles that a bare ``create_subprocess_exec`` does not:

* **Decoding.** Windows console tools emit the active codepage, not UTF-8, and
  a German ``netsh`` will happily hand back cp1252. Decoding strictly would
  turn a locale difference into a crash.
* **Absence.** ``nmcli`` and ``airport`` are frequently not installed. A missing
  binary is an expected outcome here, not an error worth propagating.
"""

from __future__ import annotations

import asyncio
import locale
import subprocess
import sys
from typing import List, Optional

#: Suppress the console window that would otherwise flash on Windows.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0


def decode_console(raw: bytes) -> str:
    """Decode command output, preferring UTF-8 but tolerating a legacy codepage."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    encoding = locale.getpreferredencoding(False) or "latin-1"
    return raw.decode(encoding, errors="replace")


async def run(args: List[str], timeout: float = 10.0) -> str:
    """Run a command and return its stdout, or ``""`` if it fails in any way.

    Returning empty rather than raising is deliberate: every caller's fallback
    for "no output" is already the same as its fallback for "command missing",
    so distinguishing them would only add branches that do nothing.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=_NO_WINDOW,
        )
    except (OSError, ValueError):
        return ""

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        _kill(proc)
        return ""
    except (OSError, ValueError):
        return ""

    return decode_console(stdout)


async def run_powershell(script: str, timeout: float = 20.0) -> str:
    """Run a PowerShell snippet on Windows. Returns ``""`` everywhere else."""
    if sys.platform != "win32":
        return ""
    return await run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )


def _kill(proc: "asyncio.subprocess.Process") -> None:
    """Terminate a process we gave up waiting for, ignoring races."""
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass


def parse_int(text: Optional[str]) -> Optional[int]:
    """Pull an integer out of console text, tolerating separators and units."""
    if text is None:
        return None
    digits = "".join(ch for ch in text if ch.isdigit())
    return int(digits) if digits else None


def parse_float(text: Optional[str]) -> Optional[float]:
    """Pull a float out of console text, tolerating a trailing unit."""
    if text is None:
        return None
    kept: List[str] = []
    for ch in text.strip():
        if ch.isdigit() or ch in ".-":
            kept.append(ch)
        elif kept:
            break
    try:
        return float("".join(kept))
    except ValueError:
        return None


def split_key_value(line: str) -> Optional[tuple]:
    """Split a ``Key : Value`` console line, as emitted by netsh and airport."""
    if ":" not in line:
        return None
    key, _, value = line.partition(":")
    key = key.strip().strip(".").strip()
    return (key, value.strip()) if key else None
