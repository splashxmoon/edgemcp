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


_GOOGLE_MARK = (
    '<svg width="17" height="17" viewBox="0 0 48 48" aria-hidden="true">'
    '<path fill="#4285F4" d="M45.1 24.5c0-1.6-.1-2.7-.4-3.9H24v7.1h12.1c-.2 1.8-1.6 4.6-4.5 6.5'
    'l6.9 5.4c4.1-3.8 6.6-9.4 6.6-15.1z"/>'
    '<path fill="#34A853" d="M24 46c5.9 0 10.9-2 14.5-5.3l-6.9-5.4c-1.8 1.3-4.3 2.2-7.6 2.2-5.8 0'
    '-10.7-3.8-12.5-9.1l-7.1 5.5C8.1 41.1 15.4 46 24 46z"/>'
    '<path fill="#FBBC05" d="M11.5 28.4c-.5-1.4-.7-2.9-.7-4.4s.3-3 .7-4.4l-7.1-5.5C2.9 17 2 20.4 2'
    ' 24s.9 7 2.4 9.9l7.1-5.5z"/>'
    '<path fill="#EA4335" d="M24 10.7c4.1 0 6.9 1.8 8.5 3.3l6.2-6C34.9 4.5 29.9 2 24 2 15.4 2 8.1 '
    '6.9 4.4 14.1l7.1 5.5C13.3 14.3 18.2 10.7 24 10.7z"/></svg>'
)

_GOOGLE_STYLE = """
  .gbtn {
    display: flex; align-items: center; justify-content: center; gap: 10px;
    width: 100%; padding: 11px; margin-bottom: 4px; font-size: 15px; font-weight: 600;
    border: 1px solid #cbd2da; border-radius: 9px; background: #fff; color: #16181d;
    text-decoration: none; cursor: pointer;
  }
  .gbtn:hover { background: #f6f7f9; }
  .or { display: flex; align-items: center; gap: 12px; margin: 18px 0 14px;
        color: #9aa1ab; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
  .or::before, .or::after { content: ""; flex: 1; height: 1px; background: #e3e6ea; }
  @media (prefers-color-scheme: dark) {
    .gbtn { background: #fff; color: #16181d; border-color: #333944; }
    .or::before, .or::after { background: #2a2e37; }
  }
"""


def render_login(
    txn: str,
    host: str,
    client_name: str | None = None,
    error: str | None = None,
    google_enabled: bool = False,
    passphrase_enabled: bool = True,
) -> str:
    """Build the sign-in page.

    Everything interpolated is escaped: ``client_name`` in particular arrives
    from dynamic client registration and is attacker-controllable.
    """
    safe_txn = html.escape(txn, quote=True)
    safe_host = html.escape(host)
    who = html.escape(client_name) if client_name else "An MCP client"
    error_block = f'<div class="err">{html.escape(error)}</div>' if error else ""

    google_block = ""
    if google_enabled and safe_txn:
        google_block = (
            f'<a class="gbtn" href="/auth/google/start?txn={safe_txn}">'
            f"{_GOOGLE_MARK}<span>Sign in with Google</span></a>"
        )
        if passphrase_enabled:
            google_block += '<div class="or">or</div>'

    passphrase_block = ""
    if passphrase_enabled:
        passphrase_block = f"""<form method="post" action="/login">
      <input type="hidden" name="txn" value="{safe_txn}">
      <label for="passphrase">Passphrase</label>
      <input id="passphrase" name="passphrase" type="password"
             autocomplete="current-password" autofocus required>
      <button type="submit">Sign in and connect</button>
    </form>"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign in - EdgeDefense</title>
<style>{_STYLE}{_GOOGLE_STYLE}</style>
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

    <p class="lede">{who} is asking to connect to this network scanner.</p>

    {google_block}
    {passphrase_block}

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
