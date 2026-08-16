# Authentication Architecture

Technical details on how the Monarch MCP Server handles authentication, session management, and security.

## Background: why cookies

Monarch no longer permits programmatic email/password login. A valid password now
returns HTTP 403 `{"detail":"Please update to the latest version of the app to
continue login."}` — the login endpoint is gated behind a browser-only flow
(Cloudflare challenge + a current web-client version) that header spoofing does not
satisfy. (The underlying library reports any 403 as `RequireMFAException`, which can
be misread as an MFA prompt.)

The server therefore authenticates by **reusing a logged-in browser session's
cookies** rather than performing a login itself.

## Authentication Flow

1. One-time setup: the user runs `python login_setup.py`, pastes their
   `session_id` and `csrftoken` cookies from a logged-in `app.monarch.com` browser
   session, and they are verified (via `get_accounts`) and stored in the keyring.
2. On startup the server checks the keyring for stored cookies (a legacy token is
   still honored as a fallback). If found, it authenticates in cookie mode; if not,
   it logs guidance to run `login_setup.py`. It never opens a browser.
3. Each request sends the session cookies plus an `X-Csrftoken` header and a current
   `Monarch-Client-Version` header (see below).
4. If the session later expires, `with_auth_recovery` clears the stale cookies and
   raises a clear error telling the user to re-run `login_setup.py`.

## Session Management

- Cookies are stored securely in the system keyring (service `com.mcp.monarch-mcp`,
  username `monarch-cookies`); the required cookies are `session_id` and `csrftoken`.
- Sessions persist across restarts, but a browser session can expire sooner than the
  old long-lived token — refresh by re-running `python login_setup.py`.
- Monarch gates API calls on a current web-client version. The library ships a stale
  value, so the server overrides it with `MONARCH_CLIENT_VERSION` (in
  `src/monarch_mcp/secure_session.py`). If calls fail with "Please update to the
  latest version of the app", bump that constant to match the live web app (grep the
  app bundle for `clientVersion`).

## Security

- Cookies are entered locally via hidden prompts (`getpass`), never transmitted
  through Claude and never written to disk (keyring only).
- `session_id` is HttpOnly in the browser; it is only visible via the DevTools
  Network tab (request `Cookie` header), not to page JavaScript.
- Session cookies are stored in the OS keyring, not in plain-text files.

## Getting the cookies

In a browser logged into Monarch:

1. Open DevTools → **Network** tab and reload the page.
2. Filter for `graphql` and click a request to `api.monarch.com`.
3. In its **Cookies** sub-tab (or **Headers → Request Headers → Cookie**), copy the
   values of `session_id` and `csrftoken`.
4. Run `python login_setup.py` and paste them into the hidden prompts.

## Legacy browser-login server (dormant)

The `auth_server.py` module still contains the previous loopback browser-login
server (with CSRF / DNS-rebinding hardening) and its unit tests, but it is **no
longer started** — `trigger_auth_flow` only checks stored credentials and points the
user at `login_setup.py`. The dormant code is retained pending removal.
