#!/usr/bin/env python3
"""Verify that every evaluation answer is actually derivable from the tools.

This does not call a model. It checks the weaker but prerequisite property that
the correct answer is genuinely obtainable from tool output -- if that fails, no
model could answer correctly either, and the question or the tool needs fixing
before a model evaluation is worth running.

Each answer is verified against the real tool responses, not pattern-matched:
counts are recomputed from the JSON payloads so a wrong expected answer fails.

    python evaluation/run_evaluation.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Callable, Dict

sys.path.insert(0, str(Path(__file__).parent))

from fixture import install_fixture  # noqa: E402


async def call(name: str, args: dict | None = None) -> str:
    """Invoke a tool the way a client would."""
    from edgedefense_mcp import server as srv

    raw = await srv.mcp.call_tool(name, args or {})
    blocks = raw[0] if isinstance(raw, tuple) else raw
    return blocks[0].text


async def collect() -> Dict[str, object]:
    """Gather the tool output an assistant would have to work from."""
    install_fixture()

    devices = json.loads(await call("edgedefense_list_devices", {"response_format": "json"}))
    score = json.loads(await call("edgedefense_get_trust_score", {"response_format": "json"}))

    details = {}
    for device in devices["devices"]:
        details[device["ip"]] = json.loads(
            await call(
                "edgedefense_get_device_detail",
                {"device_id": device["device_id"], "response_format": "json"},
            )
        )

    explanation = await call(
        "edgedefense_explain_finding",
        {"finding_id": "telnet_exposed:00:00:5e:00:53:01", "response_format": "json"},
    )

    return {
        "devices": devices,
        "score": score,
        "details": details,
        "telnet_explanation": json.loads(explanation),
    }


def _finding_ids(data) -> set:
    ids = set()
    for detail in data["details"].values():
        ids.update(f["finding_id"] for f in detail["findings"])
    return ids


#: One verifier per question, in the order they appear in evaluation.xml.
#: Each returns the answer string the tools actually support.
VERIFIERS: Dict[int, Callable[[dict], str]] = {
    1: lambda d: str(d["devices"]["total_devices"]),
    2: lambda d: str(d["score"]["score"]),
    3: lambda d: next(
        x["ip"] for x in d["devices"]["devices"] if x["is_gateway"]
    ),
    4: lambda d: next(
        ip for ip, detail in d["details"].items()
        if any(f["code"] == "telnet_exposed" for f in detail["findings"])
    ),
    5: lambda d: d["details"]["192.168.1.40"]["device"]["vendor"],
    6: lambda d: {
        "printer": "Printer", "router": "Router / gateway", "computer": "Computer",
    }.get(d["details"]["192.168.1.35"]["device"]["device_type"], "?"),
    7: lambda d: d["telnet_explanation"]["finding"]["finding_id"],
    8: lambda d: str(
        sum(1 for x in d["devices"]["devices"] if x["open_ports"])
    ),
    9: lambda d: str(d["score"]["deductions"]["exposed services"]),
    10: lambda d: next(
        x["ip"] for x in d["devices"]["devices"] if x["randomised_mac"]
    ),
}


def main() -> int:
    root = ElementTree.parse(Path(__file__).parent / "evaluation.xml").getroot()
    pairs = root.findall("qa_pair")
    data = asyncio.run(collect())

    failures = 0
    for index, pair in enumerate(pairs, start=1):
        question = (pair.findtext("question") or "").strip()
        expected = (pair.findtext("answer") or "").strip()

        verifier = VERIFIERS.get(index)
        if verifier is None:
            print(f"[SKIP] Q{index}: no verifier defined")
            failures += 1
            continue

        try:
            actual = str(verifier(data))
        except Exception as exc:  # a broken tool contract, not a wrong answer
            print(f"[ERROR] Q{index}: {type(exc).__name__}: {exc}")
            failures += 1
            continue

        ok = actual == expected
        failures += 0 if ok else 1
        print(f"[{'PASS' if ok else 'FAIL'}] Q{index}: {question[:66]}")
        if not ok:
            print(f"         expected {expected!r}, tools give {actual!r}")

    print()
    print(f"{len(pairs) - failures}/{len(pairs)} answers verified against tool output")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
