"""Tests for the Notifier abstraction.

We can't actually pop a system notification from CI, so the tests
exercise the surface (stderr fallback, factory selection, plyer
delegation) using monkeypatching where needed.
"""
from __future__ import annotations

import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from cullis_connector import notifier as notifier_mod
from cullis_connector.notifier import (
    PlyerNotifier,
    StderrNotifier,
    build_notifier,
)


def test_stderr_notifier_writes_title_and_body(capsys):
    StderrNotifier().notify("Hello", "world")
    captured = capsys.readouterr()
    assert "[cullis-notify]" in captured.err
    assert "Hello: world" in captured.err


def test_stderr_notifier_includes_click_url(capsys):
    StderrNotifier().notify("X", "Y", on_click_url="http://example.test")
    captured = capsys.readouterr()
    assert "http://example.test" in captured.err


def _disable_notify_send(monkeypatch):
    """Helper: pretend notify-send isn't on PATH so the factory falls
    through to plyer / stderr."""
    from cullis_connector.notifier import NotifySendNotifier
    monkeypatch.setattr(NotifySendNotifier, "is_available", classmethod(lambda cls: False))


def test_build_notifier_falls_back_to_stderr_when_plyer_missing(monkeypatch):
    """ImportError on plyer + no notify-send → StderrNotifier."""
    _disable_notify_send(monkeypatch)

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def fake_import(name, *args, **kwargs):
        if name == "plyer":
            raise ImportError("plyer not installed in this venv")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", fake_import)
    n = build_notifier()
    assert isinstance(n, StderrNotifier)


def test_build_notifier_falls_back_when_backend_resolution_fails(monkeypatch):
    """plyer imports but the backend can't be resolved + no notify-send
    → StderrNotifier."""
    _disable_notify_send(monkeypatch)

    bad_plyer = MagicMock()
    type(bad_plyer).notification = property(
        lambda self: (_ for _ in ()).throw(RuntimeError("no backend"))
    )

    monkeypatch.setitem(sys.modules, "plyer", bad_plyer)
    n = build_notifier()
    assert isinstance(n, StderrNotifier)


def test_plyer_notifier_delegates_to_plyer_backend(monkeypatch):
    """Construct PlyerNotifier with a fake plyer backend, verify
    notify() calls into it with the expected fields."""
    _disable_notify_send(monkeypatch)
    fake_notification = MagicMock()
    fake_plyer = MagicMock()
    fake_plyer.notification = fake_notification
    monkeypatch.setitem(sys.modules, "plyer", fake_plyer)

    n = PlyerNotifier()
    n.notify("Title", "Body", on_click_url="http://x.test")

    fake_notification.notify.assert_called_once()
    kwargs = fake_notification.notify.call_args.kwargs
    assert kwargs["title"] == "Title"
    assert "Body" in kwargs["message"]
    assert "http://x.test" in kwargs["message"]
    assert kwargs["app_name"] == PlyerNotifier.APP_NAME
    assert kwargs["timeout"] == 10


def test_plyer_notifier_swallows_runtime_error(monkeypatch):
    """A failure inside the OS notification API must not crash the
    poller — log + continue."""
    fake_notification = MagicMock()
    fake_notification.notify.side_effect = RuntimeError("dbus closed")
    fake_plyer = MagicMock()
    fake_plyer.notification = fake_notification
    monkeypatch.setitem(sys.modules, "plyer", fake_plyer)

    # Should not raise.
    PlyerNotifier().notify("X", "Y")


# ── notify-send subprocess fallback ──────────────────────────────────


def test_build_notifier_prefers_notify_send_on_linux(monkeypatch):
    """Even with plyer importable, notify-send wins on Linux because
    plyer.linux silently no-ops without dbus-python."""
    from cullis_connector.notifier import NotifySendNotifier
    monkeypatch.setattr(NotifySendNotifier, "is_available", classmethod(lambda cls: True))
    n = build_notifier()
    assert isinstance(n, NotifySendNotifier)


def test_build_notifier_falls_back_to_plyer_when_notify_send_missing(monkeypatch):
    from cullis_connector.notifier import NotifySendNotifier
    monkeypatch.setattr(NotifySendNotifier, "is_available", classmethod(lambda cls: False))

    fake_plyer = MagicMock()
    fake_plyer.notification = MagicMock()
    monkeypatch.setitem(sys.modules, "plyer", fake_plyer)

    n = build_notifier()
    assert isinstance(n, PlyerNotifier)


def test_notify_send_notifier_invokes_subprocess(monkeypatch):
    """The notifier should call out to ``notify-send`` with the
    expected argv shape."""
    from cullis_connector.notifier import NotifySendNotifier
    captured: dict = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return MagicMock(returncode=0)

    monkeypatch.setattr("cullis_connector.notifier.subprocess.run", _fake_run)
    NotifySendNotifier().notify("Title", "Body", on_click_url="http://x.test")

    argv = captured["argv"]
    assert argv[0] == "notify-send"
    assert "--app-name" in argv
    assert NotifySendNotifier.APP_NAME in argv
    # Title + body land at the end as positional args.
    assert argv[-2] == "Title"
    assert "http://x.test" in argv[-1]
