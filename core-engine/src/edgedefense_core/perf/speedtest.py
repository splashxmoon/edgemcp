"""Internet throughput measurement.

**This is the only module in the core engine that makes an outbound network
request.** Every other check reads state the operating system already has, or
talks to the local network. Measuring download speed cannot work that way: it
requires pulling real bytes from a real server on the internet.

Because that breaks the guarantee the rest of the package makes, the exception
is confined to this one file, it never runs as part of a scan, and the caller
has to invoke it deliberately.

The default endpoint is Cloudflare's speed test service, chosen because it
needs no account or API key, is anycast (so it measures the path to a nearby
edge rather than across a continent), and is reachable over plain HTTPS with
the standard library alone -- keeping the engine dependency-free.

What is sent: HTTP requests for a number of bytes, and uploads of
incompressible random data. No identifying information is attached beyond what
any HTTPS request unavoidably reveals. The service knows the requesting IP, as
every server does; this module deliberately discards that from the result
rather than reporting it back.
"""

from __future__ import annotations

import asyncio
import http.client
import os
import ssl
import threading
import time
from dataclasses import dataclass, field
from statistics import mean
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

#: Cloudflare's public speed test. Free, keyless, anycast.
DEFAULT_ENDPOINT = "https://speed.cloudflare.com"

_DOWNLOAD_PATH = "/__down?bytes={bytes}"
_UPLOAD_PATH = "/__up"
_META_PATH = "/cdn-cgi/trace"

_USER_AGENT = "EdgeDefense/0.1 (+local network diagnostics)"

#: Read in blocks rather than whole responses so the deadline can cut a
#: transfer short without discarding what has already arrived.
_BLOCK = 64 * 1024

#: Per-request ceilings. The download figure is not arbitrary: Cloudflare
#: answers 403 above roughly 100 MB, and a rejected request reads as a link
#: that transferred nothing. 50 MB is comfortably inside the limit and still
#: large enough that a gigabit connection spends the test transferring rather
#: than reissuing requests.
_MAX_DOWNLOAD_CHUNK = 50 * 1024 * 1024
_MAX_UPLOAD_CHUNK = 32 * 1024 * 1024


@dataclass
class SpeedTestResult:
    """What the test measured, and what it could not."""

    download_mbps: Optional[float] = None
    upload_mbps: Optional[float] = None
    idle_latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    loaded_latency_ms: Optional[float] = None
    bufferbloat_ms: Optional[float] = None
    bytes_downloaded: int = 0
    bytes_uploaded: int = 0
    download_streams: int = 0
    upload_streams: int = 0
    server_location: Optional[str] = None
    server_colo: Optional[str] = None
    endpoint: str = DEFAULT_ENDPOINT
    duration_seconds: Optional[float] = None
    warnings: List[str] = field(default_factory=list)

    def bufferbloat_grade(self) -> Optional[str]:
        """Grade the latency increase seen while the link was saturated.

        Bufferbloat is why a video call falls apart the moment someone else
        starts a download: the extra delay, not the missing bandwidth, is what
        breaks interactive traffic. Thresholds follow the convention used by
        Cloudflare and Waveform's tests.
        """
        increase = self.bufferbloat_ms
        if increase is None:
            return None
        if increase < 5:
            return "A+"
        if increase < 30:
            return "A"
        if increase < 60:
            return "B"
        if increase < 200:
            return "C"
        if increase < 400:
            return "D"
        return "F"

    def capability_notes(self) -> List[str]:
        """Translate the numbers into what the connection can actually do."""
        notes: List[str] = []
        download = self.download_mbps

        if download is not None:
            if download >= 100:
                notes.append(
                    f"At {download:.0f} Mbps down, several 4K streams, large downloads "
                    "and video calls can all run at once without competing."
                )
            elif download >= 25:
                notes.append(
                    f"{download:.0f} Mbps down comfortably carries 4K video on one "
                    "screen, or HD on several, alongside normal browsing."
                )
            elif download >= 10:
                notes.append(
                    f"{download:.0f} Mbps down is enough for HD streaming and video "
                    "calls, but not for two of them at the same time."
                )
            else:
                notes.append(
                    f"{download:.0f} Mbps down is below what a single HD stream wants. "
                    "Expect buffering whenever anything else is using the connection."
                )

        upload = self.upload_mbps
        if upload is not None and upload < 5:
            notes.append(
                f"Upload is {upload:.1f} Mbps. Video calls send about 2-4 Mbps each, so "
                "your outbound direction is the constraint on calls and cloud backups, "
                "not the download figure."
            )

        grade = self.bufferbloat_grade()
        if grade in ("C", "D", "F") and self.bufferbloat_ms is not None:
            notes.append(
                f"Latency rose by {self.bufferbloat_ms:.0f} ms while the connection was "
                f"busy (grade {grade}). This is bufferbloat: it is why calls break up "
                "when someone else starts a download, and it is fixed in the router's "
                "queue settings rather than by buying more bandwidth."
            )

        return notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "download_mbps": self.download_mbps,
            "upload_mbps": self.upload_mbps,
            "idle_latency_ms": self.idle_latency_ms,
            "jitter_ms": self.jitter_ms,
            "loaded_latency_ms": self.loaded_latency_ms,
            "bufferbloat_ms": self.bufferbloat_ms,
            "bufferbloat_grade": self.bufferbloat_grade(),
            "bytes_downloaded": self.bytes_downloaded,
            "bytes_uploaded": self.bytes_uploaded,
            "download_streams": self.download_streams,
            "upload_streams": self.upload_streams,
            "server_location": self.server_location,
            "server_colo": self.server_colo,
            "endpoint": self.endpoint,
            "duration_seconds": self.duration_seconds,
            "capability_notes": self.capability_notes(),
            "warnings": self.warnings,
        }


# --------------------------------------------------------------------------
# Connection plumbing
# --------------------------------------------------------------------------


class _Connection:
    """One keep-alive HTTPS connection to the endpoint.

    Reusing a connection matters twice over: latency samples measure a round
    trip rather than a TLS handshake, and throughput is not repeatedly throttled
    by TCP slow start.
    """

    def __init__(self, endpoint: str, timeout: float = 30.0) -> None:
        parts = urlsplit(endpoint)
        self.host = parts.hostname or ""
        self.port = parts.port
        self.base_path = parts.path.rstrip("/")
        self.secure = parts.scheme != "http"
        self.timeout = timeout
        self._conn: Optional[http.client.HTTPConnection] = None

    def _open(self) -> http.client.HTTPConnection:
        if self._conn is not None:
            return self._conn
        if self.secure:
            self._conn = http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout,
                context=ssl.create_default_context(),
            )
        else:
            self._conn = http.client.HTTPConnection(
                self.host, self.port, timeout=self.timeout
            )
        return self._conn

    def reset(self) -> None:
        """Drop the connection so the next request starts a fresh one."""
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None

    def close(self) -> None:
        self.reset()

    def request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> http.client.HTTPResponse:
        """Issue a request, retrying once if a pooled connection went stale."""
        full_headers = {"User-Agent": _USER_AGENT, "Accept": "*/*"}
        if headers:
            full_headers.update(headers)
        target = f"{self.base_path}{path}"

        for attempt in (1, 2):
            conn = self._open()
            try:
                conn.request(method, target, body=body, headers=full_headers)
                return conn.getresponse()
            except (http.client.HTTPException, OSError):
                self.reset()
                if attempt == 2:
                    raise
        raise http.client.HTTPException("unreachable")

    def drain(self, response: http.client.HTTPResponse, deadline: float) -> int:
        """Read a response body, stopping at ``deadline``. Returns bytes read.

        Stopping early leaves the connection unusable for keep-alive, so it is
        dropped: an unread body would corrupt the next response on the socket.
        """
        total = 0
        while True:
            if time.monotonic() >= deadline:
                self.reset()
                return total
            block = response.read(_BLOCK)
            if not block:
                return total
            total += len(block)


#: Fields worth keeping out of the trace response. `ip` is the caller's own
#: public address: the user asked how fast their connection is, and copying
#: their public IP into a transcript answers no part of that question. It is
#: filtered here, at the point of reading, so it cannot reach the result by
#: some later accident.
_META_KEEP = ("colo", "loc")


def _fetch_meta(endpoint: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    """Ask which edge served us, so the result can say where it was measured.

    Cloudflare's ``/meta`` endpoint refuses plain clients, but ``/cdn-cgi/trace``
    is available on every Cloudflare host and carries the same two facts worth
    reporting: the datacentre code and its country.
    """
    conn = _Connection(endpoint, timeout=10.0)
    try:
        response = conn.request("GET", _META_PATH)
        if not 200 <= response.status < 300:
            response.read()
            return None, None, []
        body = response.read(16 * 1024).decode("utf-8", errors="replace")
    except (OSError, http.client.HTTPException, ValueError, TypeError):
        return None, None, []
    finally:
        conn.close()

    fields: Dict[str, str] = {}
    for line in body.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in _META_KEEP:
            fields[key] = value.strip()

    colo = fields.get("colo") or None
    return fields.get("loc") or None, colo, []


# --------------------------------------------------------------------------
# Measurement phases
# --------------------------------------------------------------------------


def _measure_latency(endpoint: str, samples: int = 10) -> Tuple[List[float], List[str]]:
    """Time a series of zero-byte requests over one warmed connection."""
    conn = _Connection(endpoint, timeout=10.0)
    timings: List[float] = []
    warnings: List[str] = []
    try:
        # First request pays for DNS, TCP and TLS. Timing it would inflate the
        # result by an order of magnitude, so it is spent warming the socket.
        try:
            conn.request("GET", _DOWNLOAD_PATH.format(bytes=0)).read()
        except (OSError, http.client.HTTPException) as exc:
            warnings.append(f"Could not reach the speed test endpoint: {exc}")
            return [], warnings

        for _ in range(samples):
            started = time.perf_counter()
            try:
                conn.request("GET", _DOWNLOAD_PATH.format(bytes=0)).read()
            except (OSError, http.client.HTTPException):
                continue
            timings.append((time.perf_counter() - started) * 1000.0)
    finally:
        conn.close()
    return timings, warnings


def _download_worker(endpoint: str, chunk: int, deadline: float, counter: "_Counter") -> None:
    """Pull bytes until the deadline, adding each block to the shared counter."""
    conn = _Connection(endpoint)
    try:
        while time.monotonic() < deadline:
            try:
                response = conn.request("GET", _DOWNLOAD_PATH.format(bytes=chunk))
                problem = _rejected(response)
                if problem:
                    counter.fail(problem)
                    response.read()
                    return
                counter.add(conn.drain(response, deadline))
            except (OSError, http.client.HTTPException):
                conn.reset()
                # A dropped stream mid-test is normal on a saturated link. The
                # remaining workers carry the measurement.
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
    finally:
        conn.close()


def _upload_worker(endpoint: str, payload: bytes, deadline: float, counter: "_Counter") -> None:
    """Push a fixed payload repeatedly until the deadline.

    Unlike the download side, an upload cannot be abandoned partway and still
    counted: the bytes are only known to have crossed the link once the server
    responds. Only completed requests are counted, so this under-reports
    slightly rather than over-reporting.
    """
    conn = _Connection(endpoint)
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(payload)),
    }
    try:
        while time.monotonic() < deadline:
            try:
                response = conn.request("POST", _UPLOAD_PATH, body=payload, headers=headers)
                problem = _rejected(response)
                response.read()
                if problem:
                    counter.fail(problem)
                    return
                counter.add(len(payload))
            except (OSError, http.client.HTTPException):
                conn.reset()
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
    finally:
        conn.close()


class _Counter:
    """Bytes transferred across all worker threads, and when the last landed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total = 0
        self.last_activity = time.monotonic()
        #: Why a phase produced nothing. Without this, a server that rejects
        #: every request is indistinguishable from a dead link: both report
        #: zero, and only one of them is the user's problem.
        self.failure: Optional[str] = None

    def add(self, amount: int) -> None:
        if amount <= 0:
            return
        with self._lock:
            self.total += amount
            self.last_activity = time.monotonic()

    def fail(self, reason: str) -> None:
        with self._lock:
            if self.failure is None:
                self.failure = reason


def _rejected(response: "http.client.HTTPResponse") -> Optional[str]:
    """Describe a non-success status, or return None if the response is good.

    An error body is still a body: read uncritically, a 403 page counts as
    bytes transferred and turns a hard failure into an implausibly slow result.
    """
    if 200 <= response.status < 300:
        return None
    return (
        f"The speed test service answered {response.status} {response.reason}. "
        "The measurement for this phase is not valid."
    )


def _latency_probe(endpoint: str, deadline: float, out: List[float]) -> None:
    """Sample latency while the transfer threads are saturating the link."""
    conn = _Connection(endpoint, timeout=15.0)
    try:
        try:
            conn.request("GET", _DOWNLOAD_PATH.format(bytes=0)).read()
        except (OSError, http.client.HTTPException):
            return
        while time.monotonic() < deadline:
            started = time.perf_counter()
            try:
                conn.request("GET", _DOWNLOAD_PATH.format(bytes=0)).read()
            except (OSError, http.client.HTTPException):
                conn.reset()
                time.sleep(0.2)
                continue
            out.append((time.perf_counter() - started) * 1000.0)
            time.sleep(0.25)
    finally:
        conn.close()


def _run_phase(
    worker: Callable[[float, "_Counter"], None],
    streams: int,
    duration: float,
) -> Tuple[float, float, Optional[str]]:
    """Run ``streams`` copies of a worker for ``duration``.

    Returns (bytes transferred, seconds elapsed, failure reason or None).

    Elapsed time runs to the last observed transfer rather than to when the
    threads happened to be joined, so a straggler shutting down does not get
    charged against the throughput figure.
    """
    counter = _Counter()
    deadline = time.monotonic() + duration
    started = time.monotonic()

    threads = [
        threading.Thread(target=worker, args=(deadline, counter), daemon=True)
        for _ in range(streams)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        # Generous join: workers stop themselves at the deadline, and this only
        # needs to outlast a single in-flight request.
        thread.join(timeout=duration + 45.0)

    elapsed = max(counter.last_activity - started, 0.001)
    return float(counter.total), elapsed, counter.failure


def _probe_upload_size(endpoint: str, budget: float) -> Tuple[int, List[str]]:
    """Find an upload size that takes roughly two seconds on this link.

    A fixed size cannot serve both a fibre uplink and a rural DSL one: too
    small and the measurement is all overhead, too large and a single request
    outlasts the whole test. Doubling from 256 KB finds the right scale in a
    few seconds regardless.
    """
    warnings: List[str] = []
    conn = _Connection(endpoint)
    size = 256 * 1024
    best = size
    deadline = time.monotonic() + budget

    try:
        while time.monotonic() < deadline and size <= _MAX_UPLOAD_CHUNK:
            payload = os.urandom(size)
            started = time.perf_counter()
            try:
                response = conn.request(
                    "POST",
                    _UPLOAD_PATH,
                    body=payload,
                    headers={
                        "Content-Type": "application/octet-stream",
                        "Content-Length": str(size),
                    },
                )
                problem = _rejected(response)
                response.read()
                if problem:
                    warnings.append(f"Upload sizing: {problem}")
                    break
            except (OSError, http.client.HTTPException) as exc:
                conn.reset()
                warnings.append(f"Upload probe failed at {size // 1024} KB: {exc}")
                break
            taken = time.perf_counter() - started
            best = size
            if taken >= 2.0:
                break
            size *= 2
    finally:
        conn.close()

    return min(best, _MAX_UPLOAD_CHUNK), warnings


def _mbps(byte_count: float, seconds: float) -> Optional[float]:
    if seconds <= 0 or byte_count <= 0:
        return None
    return round((byte_count * 8) / seconds / 1_000_000, 2)


def _jitter(samples: List[float]) -> Optional[float]:
    if len(samples) < 2:
        return None
    return mean(
        abs(later - earlier) for earlier, later in zip(samples, samples[1:])
    )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def run_speed_test_sync(
    endpoint: str = DEFAULT_ENDPOINT,
    duration: float = 6.0,
    streams: int = 4,
    include_upload: bool = True,
) -> SpeedTestResult:
    """Blocking implementation. Prefer :func:`run_speed_test`.

    Runs four phases: idle latency, download (with latency sampled under load),
    an upload sizing probe, and upload.
    """
    duration = max(2.0, min(float(duration), 30.0))
    streams = max(1, min(int(streams), 16))
    result = SpeedTestResult(endpoint=endpoint)
    started_wall = time.monotonic()

    location, colo, meta_warnings = _fetch_meta(endpoint)
    result.server_location = location
    result.server_colo = colo
    result.warnings.extend(meta_warnings)

    # Phase 1: latency with the link idle. This is the baseline everything else
    # is compared against, so it has to happen before any transfer starts.
    idle_samples, latency_warnings = _measure_latency(endpoint)
    result.warnings.extend(latency_warnings)
    if idle_samples:
        result.idle_latency_ms = round(min(idle_samples), 2)
        jitter = _jitter(idle_samples)
        result.jitter_ms = round(jitter, 2) if jitter is not None else None
    else:
        result.warnings.append(
            "The endpoint did not respond, so no measurement could be taken. Check that "
            "this machine has working internet access."
        )
        result.duration_seconds = round(time.monotonic() - started_wall, 1)
        return result

    # Phase 2: download, with a latency probe riding alongside it. Asking for
    # far more than can arrive is deliberate and harmless -- reads are abandoned
    # at the deadline -- whereas asking for too little would spend the test
    # restarting requests instead of transferring.
    chunk = _MAX_DOWNLOAD_CHUNK
    loaded_samples: List[float] = []
    probe_deadline = time.monotonic() + duration
    probe = threading.Thread(
        target=_latency_probe, args=(endpoint, probe_deadline, loaded_samples), daemon=True
    )
    probe.start()

    downloaded, download_seconds, download_failure = _run_phase(
        lambda deadline, counter: _download_worker(endpoint, chunk, deadline, counter),
        streams,
        duration,
    )
    probe.join(timeout=15.0)

    result.download_streams = streams
    if download_failure:
        result.warnings.append(f"Download: {download_failure}")
    else:
        result.bytes_downloaded = int(downloaded)
        result.download_mbps = _mbps(downloaded, download_seconds)
        if result.download_mbps is None:
            result.warnings.append(
                "No data was transferred during the download phase, so download speed "
                "is unknown."
            )

    if loaded_samples:
        # Median, not minimum: under load the interesting figure is the typical
        # delay, and a minimum would just rediscover the idle latency.
        ordered = sorted(loaded_samples)
        result.loaded_latency_ms = round(ordered[len(ordered) // 2], 2)
        if result.idle_latency_ms is not None:
            result.bufferbloat_ms = round(
                max(0.0, result.loaded_latency_ms - result.idle_latency_ms), 2
            )

    # Phase 3 and 4: size the upload, then measure it.
    if include_upload:
        upload_size, probe_warnings = _probe_upload_size(endpoint, budget=6.0)
        result.warnings.extend(probe_warnings)
        payload = os.urandom(upload_size)
        uploaded, upload_seconds, upload_failure = _run_phase(
            lambda deadline, counter: _upload_worker(endpoint, payload, deadline, counter),
            min(streams, 3),
            duration,
        )
        result.upload_streams = min(streams, 3)
        if upload_failure:
            result.warnings.append(f"Upload: {upload_failure}")
        else:
            result.bytes_uploaded = int(uploaded)
            result.upload_mbps = _mbps(uploaded, upload_seconds)
            if result.upload_mbps is None:
                result.warnings.append(
                    "No upload completed within the time limit. On a very slow uplink a "
                    "single request can outlast the test window; a longer duration would "
                    "measure it."
                )

    result.duration_seconds = round(time.monotonic() - started_wall, 1)
    return result


async def run_speed_test(
    endpoint: str = DEFAULT_ENDPOINT,
    duration: float = 6.0,
    streams: int = 4,
    include_upload: bool = True,
) -> SpeedTestResult:
    """Measure download speed, upload speed, latency and bufferbloat.

    **This contacts a server on the internet.** It is the only function in the
    core engine that does. Callers must treat it as a deliberate, user-invoked
    action rather than part of any routine check.

    Args:
        endpoint: base URL of a Cloudflare-compatible speed test service.
            Defaults to Cloudflare's public one.
        duration: seconds to spend on each of the download and upload phases.
        streams: parallel connections. A single stream under-measures fast
            links, because one TCP connection rarely fills a gigabit path.
        include_upload: measure the upload direction as well. Skipping it
            roughly halves the runtime.

    Returns:
        A result whose fields are ``None`` where measurement failed, with the
        reason recorded in ``warnings``. Never raises for network conditions.
    """
    return await asyncio.to_thread(
        run_speed_test_sync,
        endpoint=endpoint,
        duration=duration,
        streams=streams,
        include_upload=include_upload,
    )
