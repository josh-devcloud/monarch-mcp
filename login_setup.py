#!/usr/bin/env python3
"""Set up (or refresh) Monarch Money authentication for the MCP server.

Monarch no longer permits programmatic email/password login (it is gated behind
a browser-only Cloudflare + client-version check). Instead, this reuses a
logged-in browser session: you paste two cookies and they are verified and saved
securely to your system keyring. Re-run this whenever the session expires.
"""

import asyncio
import getpass
import sys
from pathlib import Path

# Add the src directory to the Python path for imports
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from monarch_mcp.secure_session import secure_session  # noqa: E402


INSTRUCTIONS = """\
🏦 Monarch Money — cookie authentication setup
==============================================
Monarch blocks app-based email/password login, so the MCP server authenticates
by reusing your browser session. You need two cookies: session_id and csrftoken.

How to find them:
  1. Log into Monarch at https://app.monarch.com in your browser.
  2. Open DevTools (Cmd+Option+I / F12) → Network tab.
  3. Reload the page; in the filter box type: graphql
  4. Click any request to api.monarch.com, open its Cookies (or Headers →
     Request Headers → Cookie) and copy the values of:
        • session_id   (HttpOnly — visible in the Network tab, not in the
                         Application → Cookies panel for app.monarch.com)
        • csrftoken
"""


async def main():
    print(INSTRUCTIONS)
    session_id = getpass.getpass("Paste session_id (hidden): ").strip()
    csrftoken = getpass.getpass("Paste csrftoken  (hidden): ").strip()

    if not session_id or not csrftoken:
        print("\n❌ Both session_id and csrftoken are required. Aborting.")
        return

    cookies = {"session_id": session_id, "csrftoken": csrftoken}

    # Save first so the client is built through the same path the server uses
    # (which applies the current client-version header), then verify.
    secure_session.save_cookies(cookies)

    print("\nVerifying against Monarch...")
    client = secure_session.get_authenticated_client()
    if client is None:
        secure_session.delete_cookies()
        print("❌ Could not build an authenticated client. Cookies not kept.")
        return

    try:
        accounts = await client.get_accounts()
        count = len(accounts.get("accounts", [])) if isinstance(accounts, dict) else 0
    except Exception as exc:  # noqa: BLE001  pylint: disable=broad-exception-caught
        secure_session.delete_cookies()
        print(f"❌ Verification failed ({type(exc).__name__}): {exc}")
        print("   Double-check you copied both values from a logged-in session.")
        return

    print(f"✅ Verified — {count} accounts. Cookies saved securely to your keyring.")
    print("   You can now use the Monarch MCP server (read-only by default).")
    print("   Re-run this script if your session expires.")


if __name__ == "__main__":
    asyncio.run(main())
