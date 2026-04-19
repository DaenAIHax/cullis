"""OS-native desktop notifications.

Surface for the dashboard inbox poller (M2.1 → M2.3): turn each
``InboxEvent`` into a libnotify / NSUserNotification / Windows Toast
popup, with graceful fallbacks when no native backend is available
(CI, headless servers, NixOS without dbus-python, etc.).

Backend chain (best to worst):
  PlyerNotifier      — cross-platform via plyer (libnotify on Linux,
                       NSUserNotification on macOS, Toast on Windows).
                       Requires plyer + each OS's runtime dep
                       (dbus-python on Linux).
  NotifySendNotifier — Linux-only, shells out to ``notify-send``.
                       Avoids the dbus-python install pain on
                       distros that ship libnotify-bin (Debian-like,
                       NixOS with libnotify in the env, …).
  StderrNotifier     — final fallback, prints to stderr so the
                       dashboard log still surfaces the message.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from typing import Protocol

_log = logging.getLogger("cullis_connector.notifier")


class Notifier(Protocol):
    """Minimal notification surface — one call per event."""

    def notify(
        self,
        title: str,
        body: str,
        *,
        on_click_url: str | None = None,
    ) -> None:
        """Display a notification.

        ``on_click_url`` is a hint to the implementation: native
        backends that support click actions can open it; backends
        that don't (most of them, in practice) can include the URL
        text in the body or ignore it.
        """
        ...


class StderrNotifier:
    """Fallback that prints to stderr — used in CI, headless deploys,
    or when plyer can't load a native backend."""

    def notify(
        self,
        title: str,
        body: str,
        *,
        on_click_url: str | None = None,
    ) -> None:
        suffix = f" → {on_click_url}" if on_click_url else ""
        print(f"[cullis-notify] {title}: {body}{suffix}", file=sys.stderr)


class PlyerNotifier:
    """Wraps ``plyer.notification.notify`` — the lazy import keeps the
    optional dependency truly optional."""

    APP_NAME = "Cullis Connector"

    def __init__(self) -> None:
        # Resolve the backend once so a missing native lib (e.g.
        # libnotify on a headless box) surfaces during construction
        # and we can fall back, instead of failing on every notify().
        from plyer import notification  # type: ignore[import-not-found]
        # Touch the implementation to trigger backend resolution.
        # plyer raises NotImplementedError lazily on .notify(); this
        # accessor is enough to make sure something is wired.
        _ = notification
        self._backend = notification

    def notify(
        self,
        title: str,
        body: str,
        *,
        on_click_url: str | None = None,
    ) -> None:
        # plyer's notify signature has no click-action parameter, so
        # we fold the URL into the body when present — at least the
        # user can copy it.
        if on_click_url:
            body = f"{body}\n{on_click_url}"
        try:
            self._backend.notify(
                title=title,
                message=body,
                app_name=self.APP_NAME,
                timeout=10,
            )
        except Exception as exc:  # noqa: BLE001
            # plyer can throw from the underlying OS API on weirder
            # desktop environments. Don't let one bad notification
            # crash the poller — log and move on.
            _log.warning("native notification failed: %s", exc)


class NotifySendNotifier:
    """Linux-only fallback that shells out to ``notify-send``.

    Sidesteps the dbus-python dependency plyer needs on Linux —
    ``notify-send`` is a binary that ships with ``libnotify`` on
    pretty much every desktop distro and on NixOS via
    ``pkgs.libnotify``.

    Construction is gated behind a ``which`` check so the factory
    knows when this option isn't available.
    """

    APP_NAME = "Cullis Connector"

    @classmethod
    def is_available(cls) -> bool:
        return sys.platform.startswith("linux") and shutil.which("notify-send") is not None

    def notify(
        self,
        title: str,
        body: str,
        *,
        on_click_url: str | None = None,
    ) -> None:
        if on_click_url:
            body = f"{body}\n{on_click_url}"
        try:
            subprocess.run(
                [
                    "notify-send",
                    "--app-name", self.APP_NAME,
                    "--expire-time", "10000",
                    title,
                    body,
                ],
                check=False,
                timeout=5,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning("notify-send failed: %s", exc)


def build_notifier() -> Notifier:
    """Pick the best Notifier we can construct on this host.

    On Linux we prefer ``notify-send`` over ``plyer`` even when both
    are present — plyer's Linux backend silently no-ops with a
    ``UserWarning`` when dbus-python is missing (NixOS, slim Docker
    images, …) and that swallow turns into "no popup ever shows up
    and no error tells you why". ``notify-send`` is a single binary,
    avoids the dbus-python dance, and gives us identical UX for our
    title+body use case.

    On macOS / Windows plyer remains the right call (no notify-send
    binary, NSUserNotification + Toast are best reached through it).

    Final fallback is always ``StderrNotifier`` so headless boxes
    still log the message in the dashboard output.
    """
    if NotifySendNotifier.is_available():
        _log.info("using notify-send for desktop notifications")
        return NotifySendNotifier()
    try:
        return PlyerNotifier()
    except ImportError:
        _log.info(
            "plyer not installed — falling back to stderr notifier "
            "(install with `pip install 'cullis-connector[dashboard]'`)"
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "plyer backend unavailable (%s) — falling back to stderr",
            exc,
        )
    return StderrNotifier()
