# EdgeDefense MCP

**Ask Claude about your home network.**

> "How many devices are on my network?"
> "Is anything unusual connected right now?"
> "What's that thing at 192.168.1.47?"
> "What's my network trust score?"

An MCP server that answers those questions in plain English. It runs entirely
on your machine.

- **No account.** Nothing to sign up for.
- **No cloud.** Makes zero outbound network requests — including analytics.
- **No admin rights.** Everything above works as a normal user.
- **Read-only.** It cannot block, disconnect, or change anything.

---

## Install

Requires Python 3.10 or newer.

```bash
pip install "edgedefense-core @ git+https://github.com/splashxmoon/edgemcp.git#subdirectory=core-engine" "edgedefense-mcp @ git+https://github.com/splashxmoon/edgemcp.git#subdirectory=mcp-server"
```

Both packages are named in one command on purpose: the server depends on the
engine, and neither is on PyPI yet, so pip has to be told where to find both.

Then add one entry to your MCP client config.

**Claude Code**

```bash
claude mcp add edgedefense -- edgedefense-mcp
```

**Codex CLI**

```bash
codex mcp add edgedefense -- edgedefense-mcp
```

**Claude Desktop** — `claude_desktop_config.json`

```json
{
  "mcpServers": {
    "edgedefense": {
      "command": "edgedefense-mcp"
    }
  }
}
```

**Cursor** — `~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "edgedefense": {
      "command": "edgedefense-mcp"
    }
  }
}
```

**Codex CLI** (manual) — `~/.codex/config.toml`

```toml
[mcp_servers.edgedefense]
command = "edgedefense-mcp"
args = []
```

**VS Code / Copilot** — `.vscode/mcp.json`

```json
{
  "servers": {
    "edgedefense": {
      "command": "edgedefense-mcp"
    }
  }
}
```

Restart your client and ask: *"What's on my network?"*

Any other MCP client works too — the command is `edgedefense-mcp`, it takes no
arguments, and it speaks stdio.

**Remote connector (claude.ai)** — for clients that take a URL instead of a
command:

```bash
edgedefense-mcp --http --port 8765 --token "$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" --allow-host mcp.edgedefenseai.com
cloudflared tunnel --url http://127.0.0.1:8765
```

Paste the printed `https://<host>/t/<token>/mcp` URL into the connector dialog
and leave the OAuth fields empty.

The server must still run on a machine in your home — it can only see the
network it sits on, so hosting it elsewhere would scan that host instead. The
URL grants a full inventory of your network, so treat it as a password. See the
[root README](../README.md#remote-connector-claudeai-add-custom-connector) for
the full explanation.

<details>
<summary>Config file locations</summary>

| Client | Path |
|---|---|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop (Linux) | `~/.config/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| Codex CLI | `~/.codex/config.toml` |
| VS Code | `.vscode/mcp.json` (workspace) |

Note the key name differs by client: VS Code uses `servers`, everything else
above uses `mcpServers`, and Codex uses a TOML `[mcp_servers.<name>]` table.

</details>

<details>
<summary>Client says "command not found"</summary>

Desktop apps often don't see the same `PATH` your terminal does, which matters
if you installed into a virtual environment. Locate the executable with
`which edgedefense-mcp` (macOS/Linux) or `where edgedefense-mcp` (Windows), then
use that full path as `command`. Alternatively point `command` at your Python
interpreter with `"args": ["-m", "edgedefense_mcp"]`, which sidesteps `PATH`
entirely.

</details>

---

## Privacy

This is a security tool asking to look at your network, so the claims below are
stated precisely rather than reassuringly.

**It makes no outbound network requests. At all.**

- No telemetry, no analytics, no crash reporting, no update checks.
- Manufacturer identification uses a vendor database bundled inside the package
  (996 entries shipped on disk), not a remote lookup API.
- Results are stored in a local SQLite file. Delete it and the history is gone:

  | Platform | Path |
  |---|---|
  | Windows | `%LOCALAPPDATA%\edgedefense\edgedefense.sqlite3` |
  | macOS | `~/Library/Application Support/edgedefense/edgedefense.sqlite3` |
  | Linux | `~/.local/share/edgedefense/edgedefense.sqlite3` |

You do not have to take this on faith — the source is right here, and
`edgedefense_core` has zero runtime dependencies for the default tier. Reading
`core-engine/src/edgedefense_core/` end to end is a short afternoon.

**What it does put on the wire:** to find devices, it sends one empty UDP
datagram to each address on your local subnet (this makes your operating system
resolve their hardware addresses), a handful of standard mDNS multicast
queries, and TCP connections to a short list of common ports. All of it stays
on your local network. Roughly the traffic of loading one web page.

---

## What it can tell you

### Tier 0 — the default, no special permissions

| | |
|---|---|
| **Device discovery** | Who is connected right now, via the system address table and device self-announcements |
| **Device identification** | Best-guess type and manufacturer — with an honest confidence level attached |
| **Open ports** | What services each device is offering, and what each one is for |
| **Trust score** | A 0–100 number with the reasons behind it |
| **Plain-English explanations** | What any finding means, why it matters, and what it *cannot* tell you |

### Tier 1 — opt-in, requires admin/root

Off by default. The tool shows you exactly what elevated access is used for and
waits for you to agree before requesting anything.

- **DNS-bypass detection** — devices connecting to addresses that were never
  looked up through your network's DNS.
- **Volume outliers** — devices moving far more data than their peers.

Only packet *headers* and counters are kept. No contents are stored, nothing is
decrypted, and captures are one-off and time-bounded — never continuous.

```bash
pip install scapy
```

---

## Tools

| Tool | What it does |
|---|---|
| `edgedefense_scan_network` | Discover devices and summarise the network. **Start here.** |
| `edgedefense_list_devices` | List devices, filtered by `all` / `unknown` / `flagged` |
| `edgedefense_get_device_detail` | Everything known about one device |
| `edgedefense_get_trust_score` | The 0–100 score, with reasons |
| `edgedefense_explain_finding` | Turn a flagged issue into a plain-English explanation |
| `edgedefense_tier1_status` | Whether traffic analysis can run here |
| `edgedefense_analyze_traffic` | Run traffic analysis (opt-in, elevated) |

Every tool is read-only. All support `response_format: "json"` if you want
structured data instead of prose.

**There is deliberately no `block_device` tool.** A free tool you installed
sixty seconds ago should not be able to disconnect things from your network.
Enforcement belongs in a product you have decided to trust.

---

## About the trust score

The score starts at 100 and subtracts capped deductions for exposed risky
services, unidentified devices, unusually broad attack surface, and (with Tier 1)
traffic anomalies.

**It is calibrated so a normal home network scores in the 90s** — because a
normal home network with a router, some phones and a TV genuinely is fine. A
scoring system that told everyone they were at risk would be better at
generating screenshots and worse at being true. Every point deducted traces to a
finding you can read in full.

Findings state their own limits. Detecting an open Telnet port tells you Telnet
is open; it does not tell you the password is still the factory default, and the
explanation says so rather than implying otherwise.

---

## Honest limitations

- **Device identification is a guess.** mDNS and hostnames are reliable; vendor
  prefixes are weaker. Every guess carries a confidence level — believe the
  confidence level.
- **The vendor database is a curated subset** of the IEEE registry (~1,000 of
  ~35,000 prefixes), chosen for consumer hardware. An unknown manufacturer
  sometimes just means "not in the local copy".
- **Modern phones randomise their hardware address**, so they cannot be
  attributed to a manufacturer. This is reported as normal and is *not* counted
  against your score.
- **Only common ports are checked** — 12 on a quick scan, 42 on a full one. A
  service on an unusual port will be missed.
- **A VPN can hide your local network** from the scan entirely.
- **Tier 1 heuristics have real false-positive modes.** DNS-over-HTTPS looks
  exactly like DNS bypass. Each finding says so.

---

## Development

```bash
git clone https://github.com/edgedefense/edgedefense-mcp
cd edgedefense-mcp
pip install -e ../core-engine
pip install -e ".[dev]"
pytest
```

Point your client at the checkout:

```json
{
  "mcpServers": {
    "edgedefense": {
      "command": "python",
      "args": ["-m", "edgedefense_mcp"]
    }
  }
}
```

Detection logic lives in [`core-engine/`](../core-engine), shared with the
EdgeDefense application. This package is the MCP wrapper and nothing else — if
you are fixing a detection bug, it belongs there.

---

## Licence

MIT. Use it, fork it, ship it.
