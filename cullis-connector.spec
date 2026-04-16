# PyInstaller spec for a single-binary cullis-connector distribution.
#
# Build locally:
#     pyinstaller cullis-connector.spec
#
# The CI workflow (.github/workflows/release-connector.yml) runs this on
# all three OSes and uploads a zip containing the binary + an installer
# script. See imp/connector_desktop_plan.md for how the whole chain fits.

# Templates and static files must ship as data files — Jinja2Templates
# and StaticFiles read them off disk at runtime relative to
# cullis_connector/__file__.
datas = [
    ("cullis_connector/templates", "cullis_connector/templates"),
    ("cullis_connector/static", "cullis_connector/static"),
]

# uvicorn picks its loop / protocol implementations dynamically — list
# every automatic import so PyInstaller bundles them. Without these the
# packaged binary fails with "No module named 'uvicorn.loops.asyncio'".
hiddenimports = [
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.logging",
]


a = Analysis(
    ["cullis_connector/__main__.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # The MCP server is only spawned by the IDE; the dashboard
        # binary never needs the full mcp stdio stack. Trimming it
        # keeps the bundle a few MB smaller. Uncomment if you want
        # one binary that does both roles.
        # "mcp",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="cullis-connector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # keep stdout/stderr visible — users debug via terminal
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
