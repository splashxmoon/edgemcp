<img src="assets/logo.svg" alt="EdgeDefense" width="88" align="left" hspace="12" vspace="4">

# EdgeDefense MCP

**Ask Claude about your home network.** Runs entirely on your machine — no account, no cloud, no admin rights.

<br clear="left">


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
| `edgedefense_whats_changed` | Tells you what's new on your network, what vanished, and what ports opened since last scan |
| `edgedefense_list_devices` | Lists what's connected — filter to just the unknown ones, or just the ones with problems |
| `edgedefense_get_device_detail` | Everything known about one device: what it probably is, who made it, what it's running |
| `edgedefense_name_device` | Assigns a friendly name to a device so you can track it |
| `edgedefense_local_security` | Checks the Wi-Fi security, DNS, and open ports on the machine running the server |
| `edgedefense_get_trust_score` | A single 0–100 score for your network, with the reasons behind it |
| `edgedefense_explain_finding` | Turns any flagged issue into a plain-English explanation of what it means and what to do |


## Install

Step 1 — install the server. Requires Python 3.10 or newer.

```bash
pip install "edgedefense-core @ git+https://github.com/splashxmoon/edgemcp.git#subdirectory=core-engine" "edgedefense-mcp @ git+https://github.com/splashxmoon/edgemcp.git#subdirectory=mcp-server"
```

Step 2 — tell your client about it.

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

Restart your client afterwards. Any other MCP client works too — the command is
`edgedefense-mcp`, it takes no arguments, and it speaks stdio.

### Remote connector (claude.ai "Add custom connector")

That dialog asks for a URL rather than a command, which means the server has to
be reachable over HTTP.

**The server must still run on a machine in your home.** It identifies devices
by reading the local address table and listening for the announcements devices
broadcast on the local link — so it can only ever see the network it is sitting
on. Hosting it on a VPS would work perfectly and tell you about the VPS's
network, which is not what you want. The arrangement that makes sense is a
tunnel from a public hostname back to a machine at home.

#### Getting a public URL

Start with a quick tunnel. It needs no DNS changes at all and proves the whole
thing works in about a minute:

```bash
cloudflared tunnel --url http://127.0.0.1:8765
```

That prints a `https://<random>.trycloudflare.com` URL. Pass it as
`--public-url` and use it in your client. The URL changes each run, which is
fine for testing.

For a stable address on your own domain, note two things. A subdomain like
`mcp.example.com` is yours automatically — subdomains are not bought
separately, you just create a DNS record. But `cloudflared tunnel route dns`
only works if the domain's nameservers point at Cloudflare. If your domain is
still on your registrar's nameservers, either move the zone to Cloudflare
(re-creating every existing record first — **MX records especially, or email
stops arriving**) or use a tunnel provider that gives you a CNAME target you
can paste into your current DNS panel.

#### With browser sign-in (recommended)

Connecting opens a sign-in page on your own domain, and your client ends up
holding a revocable token instead of a secret URL. The authorization server
runs inside this process — there is no hosted login service and no account.

```bash
export EDGEDEFENSE_PASSPHRASE='choose-something-long'
edgedefense-mcp --http --oauth --public-url https://mcp.edgedefenseai.com --port 8765
```

```bash
cloudflared tunnel --url http://127.0.0.1:8765
```

Then paste just the endpoint into the connector dialog, leaving both OAuth
fields empty:

```
https://mcp.edgedefenseai.com/mcp
```

The client registers itself, discovers the authorization server, and opens the
sign-in page. Enter the passphrase and it connects. Restarting the server
revokes every issued token.

`--public-url` must match exactly what the browser sees, since the OAuth
metadata and the redirect back to your client are built from it.

#### Sign in with Google instead of a passphrase

Rather than sharing one passphrase, you can sign in with Google and allow
specific addresses.

Create an OAuth client in the Google Cloud Console (APIs & Services →
Credentials → Create credentials → OAuth client ID → Web application), and add
this exact redirect URI:

```
https://mcp.edgedefenseai.com/auth/google/callback
```

Then:

```bash
export EDGEDEFENSE_GOOGLE_CLIENT_ID='...apps.googleusercontent.com'
export EDGEDEFENSE_GOOGLE_CLIENT_SECRET='...'
edgedefense-mcp --http --oauth \
  --public-url https://mcp.edgedefenseai.com \
  --allow-email you@gmail.com \
  --no-passphrase
```

`--allow-email` is required and repeatable. Signing in with Google proves who
someone is; it does not decide whether they may read your network, and without
an allowlist any Google account would satisfy the check. Omit `--no-passphrase`
to offer both methods on the sign-in page.

> **One honest caveat.** With Google sign-in enabled, this server contacts
> Google while somebody is signing in — that is unavoidable for any identity
> provider. Scanning still makes no outbound request of any kind, and no
> network data is ever sent anywhere. If you would rather the server never
> talk to anything, use the passphrase.

#### With a token in the URL (simpler)

No browser step; the secret lives in the URL instead.

```bash
edgedefense-mcp --http --port 8765 --token "$(python -c 'import secrets;print(secrets.token_urlsafe(32))')" --allow-host mcp.edgedefenseai.com
```

Point a tunnel at it:

```bash
cloudflared tunnel --url http://127.0.0.1:8765
```

Then paste the printed endpoint into the connector dialog:

```
https://mcp.edgedefenseai.com/t/<your-token>/mcp
```

Leave the OAuth fields empty. The dialog has nowhere to put a header, so the
token travels in the path instead.

> **The URL is a password.** Anyone holding it gets a full inventory of your
> home network. Don't put it anywhere you wouldn't put a password, and rotate
> it by restarting with a new `--token`.

Binding to anything other than loopback without a token is refused; the server
generates one and prints it rather than exposing your network anonymously.
`--allow-host` must name the hostname clients will actually use, or the
DNS-rebinding check rejects the request. `edgedefense-mcp --help` lists the rest.

<details>
<summary>Where is the Claude Desktop config file?</summary>

| Platform | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

</details>

<details>
<summary>Client says "command not found" or the server won't start</summary>

Desktop apps often don't see the same `PATH` your terminal does, which matters
if you installed into a virtual environment. Find the real location:

```bash
# macOS / Linux
which edgedefense-mcp

# Windows
where edgedefense-mcp
```

Then use that full path in the config instead of the bare name:

```json
{
  "mcpServers": {
    "edgedefense": {
      "command": "/full/path/to/edgedefense-mcp"
    }
  }
}
```

Running it through Python directly also works, and avoids the `PATH` question
entirely:

```json
{
  "mcpServers": {
    "edgedefense": {
      "command": "/full/path/to/python",
      "args": ["-m", "edgedefense_mcp"]
    }
  }
}
```

</details>

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

2. **Needs no elevated privileges.** Device discovery, identification,
   port fingerprinting and the trust score all run as an ordinary user on
   Windows, macOS and Linux.

Both are load-bearing for the product's premise. A privacy tool that quietly
calls an external API loses the argument permanently the first time a technical
user runs a packet capture on it.

### Current scope

**In:** Zero-permission discovery and identification.

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
