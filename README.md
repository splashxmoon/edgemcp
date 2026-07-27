# EdgeDefense MCP

**Ask Claude about your home network.** Runs entirely on your machine — no account, no cloud, no admin rights.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-server-orange.svg)](https://modelcontextprotocol.io)

> Server-specific docs live in [mcp-server/README.md](mcp-server/README.md).

## What this is

You know something is connected to your wifi. You have no idea what it is. Most tools answer that with a dashboard full of numbers you have to interpret yourself.

This one lets you just ask. Point Claude (or Cursor, or any MCP client) at your network and talk to it in plain English: what's connected, what that unknown thing at `192.168.1.47` probably is, and whether anything looks wrong.

Everything happens on your computer. Nothing is uploaded, nothing is logged to a server, and there is nothing to sign up for.

## Why it's different

Most network scanners hand you a table of IP addresses, MAC addresses and open ports, and leave the interpretation to you. That works if you already know what port 23 means and why it matters. This gives you a conversation instead — you ask a normal question, you get a normal answer, and if something is flagged you can ask *why* and get an explanation in plain language, including what the check genuinely can't tell you.

Two promises make it safe to install on a whim:

**It needs no special permissions.** Everything above works as a regular user. No `sudo`, no "run as administrator", no driver to install.

**It never phones home.** Not for updates, not for analytics, not even to look up who made a device — that database ships inside the package. There is no HTTP client anywhere in the code. You can verify that yourself in about ten minutes; the whole thing is a few thousand lines with zero runtime dependencies.

It is also **read-only by design**. There is deliberately no "block this device" button. A tool you installed sixty seconds ago should not be able to disconnect things from your network.

## Tools

| Tool | What you get |
|---|---|
| `edgedefense_scan_network` | Finds everything on your network and summarises it in plain English. **Start here.** |
| `edgedefense_list_devices` | Lists what's connected — filter to just the unknown ones, or just the ones with problems |
| `edgedefense_get_device_detail` | Everything known about one device: what it probably is, who made it, what it's running |
| `edgedefense_get_trust_score` | A single 0–100 score for your network, with the reasons behind it |
| `edgedefense_explain_finding` | Turns any flagged issue into a plain-English explanation of what it means and what to do |

Two more are available but switched off until you explicitly turn them on, because they need administrator access:

| Tool | What you get |
|---|---|
| `edgedefense_tier1_status` | Tells you whether deeper traffic analysis can run on this machine |
| `edgedefense_analyze_traffic` | Watches traffic for a set number of seconds and flags odd behaviour — shows you exactly what it will do and waits for you to agree first |

## Install

Requires Python 3.10 or newer.

```bash
pip install "edgedefense-core @ git+https://github.com/splashxmoon/edgemcp.git#subdirectory=core-engine" "edgedefense-mcp @ git+https://github.com/splashxmoon/edgemcp.git#subdirectory=mcp-server"
```

**Claude Code**

```bash
claude mcp add edgedefense -- edgedefense-mcp
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

<details>
<summary>Where is the Claude Desktop config file?</summary>

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

</details>

Restart your client after editing the config.

## Try it

Paste any of these:

```
Scan my home network and tell me what's connected.
```

```
What's my network trust score, and why?
```

```
Is anything unusual connected right now?
```

Good follow-ups once you have results: *"What is that device at 192.168.1.47?"* · *"Which devices couldn't you identify?"* · *"Why is that a problem?"*

A first scan takes about ten seconds.

---

## Architecture

Below this line is for people reading the code rather than using the tool.

This is a monorepo with a deliberate split between shared detection logic and the products built on top of it.

```
edgemcp/
├── core-engine/     Shared discovery, identification and scoring. Imported, never forked.
├── mcp-server/      The free, open-source MCP server. Ships independently.
└── core-app/        The paid Core/Home product. Not present yet.
```

### Why the split exists

`core-engine/` is the only place detection logic lives. Both `mcp-server/` and
the future `core-app/` import it the same way; neither reimplements any of it.

This is decided up front on purpose. Retrofitting a shared engine after two
codebases have already diverged is expensive and entirely avoidable, and the
cheapest moment to draw the line is before the second consumer exists.

`mcp-server/` is a separate folder rather than a subfolder of the engine because
it ships independently: its own packaging, its own public repository, its own
README, its own MIT licence.

### The hard boundary

**`mcp-server/` is public. Anything reachable from it is public.**

`core-engine/` therefore contains only generic, safe-to-open-source logic:
device discovery, ARP and mDNS scanning, vendor lookup, and scoring arithmetic.

The trained ML detection pipeline behind the paid product is **not** in this
repository, is not imported by anything here, and lives in a separate private
package. This is a standing architectural constraint, not a future TODO.

### Two guarantees that constrain every change

1. **Nothing phones home.** No outbound network request is made by any shipped
   code path, for any purpose, including analytics. Vendor lookups read a
   bundled database on disk. The single exception is
   `core-engine/scripts/update_oui.py`, a maintainer-run script that is not part
   of the distributed package and is documented as such in its own docstring.

2. **Tier 0 needs no elevated privileges.** Device discovery, identification,
   port fingerprinting and the trust score all run as an ordinary user on
   Windows, macOS and Linux. Only the opt-in Tier 1 traffic analysis needs more,
   and it presents a written consent notice before requesting anything.

Both are load-bearing for the product's premise. A privacy tool that quietly
calls an external API loses the argument permanently the first time a technical
user runs a packet capture on it.

### Current scope

**In:** Tier 0 zero-permission discovery, Tier 1 opt-in heuristic traffic
analysis.

**Out, by decision rather than by omission:** the ML pipeline (Tier 2),
destructive tools such as `block_device`, and Core/Home product features. A free
tool installed sixty seconds ago should not be able to disconnect things from
your network; enforcement belongs in a product you have decided to trust.

## Development

```bash
pip install -e ./core-engine
pip install -e ./mcp-server
```

Run the tests:

```bash
cd core-engine && python -m pytest -q
cd ../mcp-server && python -m pytest -q
```

Verify the evaluation questions are answerable from tool output:

```bash
cd mcp-server && python evaluation/run_evaluation.py
```

Then point an MCP client at it — see [mcp-server/README.md](mcp-server/README.md)
for install and configuration.

## Licence

MIT, across the repository.
