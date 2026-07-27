# EdgeDefense

A monorepo with a deliberate split between shared detection logic and the
products built on top of it.

```
edge mcp/
├── core-engine/     Shared discovery, identification and scoring. Imported, never forked.
├── mcp-server/      The free, open-source MCP server. Ships independently.
└── core-app/        The paid Core/Home product. Not present yet.
```

## Why the split exists

`core-engine/` is the only place detection logic lives. Both `mcp-server/` and
the future `core-app/` import it the same way; neither reimplements any of it.

This is decided up front on purpose. Retrofitting a shared engine after two
codebases have already diverged is expensive and entirely avoidable, and the
cheapest moment to draw the line is before the second consumer exists.

`mcp-server/` is a separate folder rather than a subfolder of the engine because
it ships independently: its own packaging, its own public repository, its own
README, its own MIT licence.

## The hard boundary

**`mcp-server/` is public. Anything reachable from it is public.**

`core-engine/` therefore contains only generic, safe-to-open-source logic:
device discovery, ARP and mDNS scanning, vendor lookup, and scoring arithmetic.

The trained ML detection pipeline behind the paid product is **not** in this
repository, is not imported by anything here, and lives in a separate private
package. This is a standing architectural constraint, not a future TODO.

## Two guarantees that constrain every change

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

## Current scope

**In:** Tier 0 zero-permission discovery, Tier 1 opt-in heuristic traffic
analysis.

**Out, by decision rather than by omission:** the ML pipeline (Tier 2),
destructive tools such as `block_device`, and Core/Home product features. A free
tool installed sixty seconds ago should not be able to disconnect things from
your network; enforcement belongs in a product you have decided to trust.

## Getting started

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
