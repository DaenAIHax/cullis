"""Native desktop shell for the Connector (M3.1, Phase 3).

Wraps the FastAPI dashboard in an OS-native webview so non-technical
users never see a terminal. Adds a system-tray icon with a minimal
menu — the dashboard process keeps running in the background when the
user closes the window, and a click on the tray brings it back.

Threading plan (all three matter, pick the wrong one and macOS hangs):
  - Uvicorn runs in a daemon thread, owning its own asyncio loop.
  - pystray.Icon runs detached — it spins its own platform thread
    (AppKit runloop on macOS, GTK main loop on Linux, Win32 message
    pump on Windows).
  - PyWebview owns the main thread. On macOS AppKit strictly requires
    the GUI to sit on the process's initial thread, so webview.start()
    blocks here and everything else is a guest thread.
"""
from __future__ import annotations

import logging
import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

    from cullis_connector.config import ConnectorConfig


_log = logging.getLogger(__name__)

# Cullis teal — matches the dashboard favicon and brand mark.
_ACCENT = (0, 229, 199, 255)


def _build_tray_image(size: int = 64) -> "PILImage":
    """Draw the portcullis glyph at the requested pixel size.

    We render with Pillow primitives instead of shipping a PNG asset
    so the wheel stays smaller and the icon scales cleanly for high-
    dpi trays. The geometry mirrors `cullis_connector/static/cullis-mark.svg`
    (100x100 viewBox: top bar, three vertical bars, middle crossbar,
    three triangular teeth).
    """
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    def _s(value: int) -> int:
        return int(round(value * size / 100))

    draw.rectangle([_s(8), _s(10), _s(92), _s(16)], fill=_ACCENT)
    for x in (20, 46, 72):
        draw.rectangle([_s(x), _s(16), _s(x + 8), _s(78)], fill=_ACCENT)
    draw.rectangle([_s(14), _s(44), _s(86), _s(50)], fill=_ACCENT)
    for x in (14, 40, 66):
        draw.polygon(
            [
                (_s(x), _s(78)),
                (_s(x + 20), _s(78)),
                (_s(x + 10), _s(96)),
            ],
            fill=_ACCENT,
        )
    return img


def _spawn_uvicorn(
    cfg: "ConnectorConfig",
    host: str,
    port: int,
) -> threading.Thread:
    """Launch the dashboard FastAPI app in a daemon thread."""
    import uvicorn

    from cullis_connector.web import build_app

    app = build_app(cfg)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=False,
        )
    )

    thread = threading.Thread(
        target=server.run,
        name="cullis-uvicorn",
        daemon=True,
    )
    thread.start()
    return thread


def _relaunch_argv(profile: str) -> list[str]:
    """Build the argv that spawns a fresh Connector process loading
    a different profile. Isolated so tests can inspect it without
    actually invoking subprocess."""
    # ``sys.argv[0]`` is the right entrypoint both for a pip-installed
    # console_script (``cullis-connector``) and for a PyInstaller-frozen
    # binary (the bundle's entry point). For `python -m cullis_connector`
    # development use we fall back to `-m` form.
    if sys.argv and sys.argv[0] and not sys.argv[0].endswith(".py"):
        argv0 = [sys.argv[0]]
    else:
        argv0 = [sys.executable, "-m", "cullis_connector"]
    return [*argv0, "desktop", "--profile", profile]


def _spawn_detached(argv: list[str]) -> subprocess.Popen:
    """Spawn a detached child process that survives the parent's exit.

    Detachment prevents the new desktop shell from receiving SIGINT
    when the old one quits and dodges "zombie child" situations on
    Unix. On Windows ``CREATE_NEW_PROCESS_GROUP`` plays the same role.
    """
    kwargs: dict = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
            | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        )
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(argv, **kwargs)


def _build_profiles_submenu(
    profiles: list[str],
    active: str,
    open_profiles_page: Callable[[], None],
    switch_to: Callable[[str], None] | None = None,
):
    """Submenu listing every profile on the machine with a check next
    to the one currently loaded.

    * Active entry: click is a no-op (it's already selected).
    * Non-active entry: click triggers ``switch_to(name)`` — the
      caller is expected to spawn a detached subprocess with that
      profile and then tear the current process down. If ``switch_to``
      is ``None`` we fall back to opening the Manage page, preserving
      the pre-M3.3c behaviour for callers who don't want runtime
      switching.
    * "Manage profiles…" is always available — it's the escape hatch
      for users who want to see the list or add a new profile.
    """
    import pystray

    if not profiles:
        return None

    def _click_handler(name: str):
        def _on_click(icon, item):
            if name == active:
                return  # already loaded, nothing to do
            if switch_to is not None:
                switch_to(name)
            else:
                open_profiles_page()
        return _on_click

    items: list = []
    for name in profiles:
        items.append(
            pystray.MenuItem(
                name,
                _click_handler(name),
                checked=lambda item, n=name: n == active,
                radio=True,
            )
        )
    items.append(pystray.Menu.SEPARATOR)
    items.append(
        pystray.MenuItem(
            "Manage profiles…",
            lambda icon, item: open_profiles_page(),
        )
    )
    return pystray.Menu(*items)


def _build_menu(
    open_dashboard: Callable[[], None],
    open_inbox: Callable[[], None],
    on_quit: Callable[[], None],
    *,
    profiles_submenu=None,
):
    """Tray menu: Open Dashboard / Open Inbox / [Profiles ▸] / Quit.

    Pause-notifications remains a deliberate follow-up (M3.1b) — the
    top-level surface stays small so the first packaged binary is
    easy to validate across OSes.
    """
    import pystray

    items = [
        pystray.MenuItem(
            "Open Dashboard",
            lambda icon, item: open_dashboard(),
            default=True,
        ),
        pystray.MenuItem(
            "Open Inbox",
            lambda icon, item: open_inbox(),
        ),
    ]
    if profiles_submenu is not None:
        items.append(
            pystray.MenuItem("Profiles", profiles_submenu)
        )
    items.append(pystray.Menu.SEPARATOR)
    items.append(
        pystray.MenuItem(
            "Quit",
            lambda icon, item: on_quit(),
        )
    )
    return pystray.Menu(*items)


def run_desktop_app(
    cfg: "ConnectorConfig",
    host: str = "127.0.0.1",
    port: int = 7777,
) -> int:
    """Entry point for `cullis-connector desktop`.

    Returns 2 when the optional `desktop` deps are missing so the CLI
    can surface a friendly install hint.
    """
    try:
        import pystray  # noqa: F401
        import webview
        from PIL import Image  # noqa: F401
    except ImportError as exc:
        _log.error(
            "desktop shell needs extra deps — install with "
            "`pip install 'cullis-connector[dashboard,desktop]'` "
            "(missing: %s)",
            exc.name,
        )
        return 2

    base_url = f"http://{host}:{port}"
    _spawn_uvicorn(cfg, host, port)

    window = webview.create_window(
        "Cullis",
        f"{base_url}/",
        hidden=True,
        width=1120,
        height=760,
    )

    # Intercept the native close button: hide the window so the tray
    # stays live and a later Open reveals the same instance instead of
    # racing uvicorn to spawn a second one.
    def _on_closing() -> bool:
        window.hide()
        return False

    window.events.closing += _on_closing

    def _open_dashboard() -> None:
        window.load_url(f"{base_url}/")
        window.show()

    def _open_inbox() -> None:
        window.load_url(f"{base_url}/inbox")
        window.show()

    def _open_profiles() -> None:
        window.load_url(f"{base_url}/profiles")
        window.show()

    import pystray

    # Enumerate profiles on disk so the tray can surface them. We do
    # this at startup only — a future M3.3c can refresh on demand.
    from cullis_connector.profile import config_root_from_dir, list_profiles

    root = config_root_from_dir(cfg.config_dir, cfg.profile_name)
    profiles = list_profiles(root)

    icon = pystray.Icon(
        "cullis",
        icon=_build_tray_image(64),
        title=(
            f"Cullis Connector — {cfg.profile_name}"
            if cfg.profile_name else "Cullis Connector"
        ),
    )

    def _quit_all() -> None:
        icon.stop()
        window.destroy()

    def _switch_to(target_profile: str) -> None:
        """Spawn a detached Connector for the target profile and
        tear ourselves down so it can claim port 7777.

        There is a ~1-2s window where neither process answers on
        the port while the new uvicorn binds. That's the honest
        price of a single-port design; acceptable for a manual
        tray click and far simpler than running two Connectors
        side by side.
        """
        _log.info("desktop shell switching to profile %s", target_profile)
        try:
            _spawn_detached(_relaunch_argv(target_profile))
        except OSError as exc:
            _log.error("failed to spawn replacement connector: %s", exc)
            return
        # Brief head-start so the child is past argv parsing before
        # we release the port it wants.
        time.sleep(0.3)
        _quit_all()

    profiles_submenu = _build_profiles_submenu(
        profiles,
        cfg.profile_name or "",
        _open_profiles,
        switch_to=_switch_to,
    )

    icon.menu = _build_menu(
        _open_dashboard,
        _open_inbox,
        _quit_all,
        profiles_submenu=profiles_submenu,
    )
    icon.run_detached()

    _log.info(
        "desktop shell ready — tray icon active, dashboard at %s",
        base_url,
    )
    webview.start(private_mode=False)
    return 0
