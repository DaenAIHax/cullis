Cullis Connector — quick install
================================

macOS
-----
  1. Double-click install.command in Finder.
  2. If macOS blocks it, right-click → Open, then confirm. This only
     happens the first time until we ship a signed build.
  3. The dashboard opens at http://127.0.0.1:7777.

Linux
-----
  1. Open a terminal in the folder you extracted.
  2. Run: ./install.sh
  3. The dashboard opens at http://127.0.0.1:7777 if you have xdg-open;
     otherwise visit that URL manually.

Windows
-------
  1. Double-click install.bat.
  2. If Windows SmartScreen blocks it, click "More info" then "Run
     anyway". Unsigned builds always trigger this.
  3. The dashboard opens at http://127.0.0.1:7777.

After install
-------------
  The connector runs in the background starting at your next login.
  Point your MCP client (Claude Desktop, Cursor, Cline) at the dashboard
  and click "Configure" for each — we'll write the right JSON for you.

Need a hand? https://cullis.io/docs/connector
