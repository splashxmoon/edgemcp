"""The sign-in page shown in the browser during the OAuth flow.

Self-contained on purpose: no external stylesheet, font or script, because a
page whose job is to accept a passphrase should not be fetching anything from
a third party. It is also the only user-visible surface this project has, so
it carries the mark and says plainly what is being authorised.
"""

from __future__ import annotations

import html

#: The mark, inlined so the page has no external requests at all.
_LOGO = """
<svg viewBox="0 0 400 400" width="52" height="52" aria-hidden="true">
  <polygon points="60,150 330,88 205,190" fill="#B4B4B4"/>
  <polygon points="60,150 205,190 196,168" fill="#6E6E6E"/>
  <polygon points="330,88 232,320 205,190" fill="#5C5C5C"/>
  <polygon points="330,88 205,190 214,205" fill="#9A9A9A"/>
</svg>
"""

_STYLE = """
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center;
    justify-content: center; padding: 24px;
    font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f6f7f9; color: #16181d;
  }
  .card {
    width: 100%; max-width: 420px; background: #fff; border: 1px solid #e3e6ea;
    border-radius: 14px; padding: 32px; box-shadow: 0 1px 3px rgba(0,0,0,.06);
  }
  .head { display: flex; align-items: center; gap: 12px; margin-bottom: 22px; }
  h1 { font-size: 19px; margin: 0; letter-spacing: -.01em; }
  .host { font-size: 13px; color: #6b7280; margin-top: 2px; }
  p.lede { margin: 0 0 20px; color: #4b5563; font-size: 14px; }
  label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 7px; }
  input[type=password] {
    width: 100%; padding: 11px 12px; font-size: 15px; border-radius: 9px;
    border: 1px solid #cbd2da; background: #fff; color: inherit;
  }
  input[type=password]:focus { outline: 2px solid #3b82f6; outline-offset: 1px; border-color: #3b82f6; }
  button {
    width: 100%; margin-top: 16px; padding: 11px; font-size: 15px; font-weight: 600;
    border: 0; border-radius: 9px; background: #16181d; color: #fff; cursor: pointer;
  }
  button:hover { background: #2b2f38; }
  .grants { margin: 20px 0 0; padding: 14px 16px; background: #f6f7f9;
            border-radius: 9px; font-size: 13px; color: #4b5563; }
  .grants strong { color: #16181d; display: block; margin-bottom: 6px; font-size: 13px; }
  .grants ul { margin: 0; padding-left: 18px; }
  .grants li { margin: 3px 0; }
  .err { margin: 0 0 16px; padding: 10px 12px; border-radius: 9px;
         background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; font-size: 13px; }
  .foot { margin-top: 18px; font-size: 12px; color: #6b7280; text-align: center; }
  @media (prefers-color-scheme: dark) {
    body { background: #0e1014; color: #e8eaed; }
    .card { background: #16181d; border-color: #2a2e37; }
    .host, p.lede, .grants, .foot { color: #9aa1ab; }
    .grants { background: #1c1f26; } .grants strong { color: #e8eaed; }
    input[type=password] { background: #0e1014; border-color: #333944; color: #e8eaed; }
    button { background: #e8eaed; color: #0e1014; } button:hover { background: #fff; }
    .err { background: #2a1416; border-color: #5b2326; color: #fca5a5; }
  }
"""


def render_login(
    txn: str,
    host: str,
    client_name: str | None = None,
    error: str | None = None,
) -> str:
    """Build the sign-in page.

    Everything interpolated is escaped: ``client_name`` in particular arrives
    from dynamic client registration and is attacker-controllable.
    """
    safe_txn = html.escape(txn, quote=True)
    safe_host = html.escape(host)
    who = html.escape(client_name) if client_name else "An MCP client"
    error_block = f'<div class="err">{html.escape(error)}</div>' if error else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign in - EdgeDefense</title>
<style>{_STYLE}</style>
</head>
<body>
  <main class="card">
    <div class="head">
      {_LOGO}
      <div>
        <h1>EdgeDefense</h1>
        <div class="host">{safe_host}</div>
      </div>
    </div>

    {error_block}

    <p class="lede">{who} is asking to connect to this network scanner.
    Enter the passphrase you started the server with.</p>

    <form method="post" action="/login">
      <input type="hidden" name="txn" value="{safe_txn}">
      <label for="passphrase">Passphrase</label>
      <input id="passphrase" name="passphrase" type="password"
             autocomplete="current-password" autofocus required>
      <button type="submit">Sign in and connect</button>
    </form>

    <div class="grants">
      <strong>Connecting grants read-only access to:</strong>
      <ul>
        <li>Which devices are on this network, and what they appear to be</li>
        <li>Open ports and the trust score derived from them</li>
      </ul>
    </div>

    <p class="foot">Runs on your machine. Nothing is uploaded.
    Revoke by restarting the server.</p>
  </main>
</body>
</html>"""


def render_done() -> str:
    """Shown if the client cannot be redirected back automatically."""
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected - EdgeDefense</title><style>{_STYLE}</style></head>
<body><main class="card">
  <div class="head">{_LOGO}<div><h1>Connected</h1></div></div>
  <p class="lede">You can close this tab and return to your client.</p>
</main></body></html>"""
