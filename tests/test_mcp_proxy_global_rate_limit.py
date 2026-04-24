"""Tests for the global Mastio rate-limit middleware — ADR-013 layer 2."""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcp_proxy.middleware.global_rate_limit import (
    GlobalRateLimitMiddleware,
    TokenBucket,
)


# ── TokenBucket ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_token_bucket_starts_full():
    b = TokenBucket(rate_per_sec=10, burst=5)
    # Can drain the full burst immediately.
    for _ in range(5):
        assert await b.try_acquire() is True


@pytest.mark.asyncio
async def test_token_bucket_rejects_when_empty():
    b = TokenBucket(rate_per_sec=1000, burst=2)  # rate high, but bucket starts at 2
    assert await b.try_acquire() is True
    assert await b.try_acquire() is True
    assert await b.try_acquire() is False  # third immediately → empty


@pytest.mark.asyncio
async def test_token_bucket_refills_over_time():
    b = TokenBucket(rate_per_sec=100, burst=1)
    assert await b.try_acquire() is True
    assert await b.try_acquire() is False
    # Wait 20ms → with rate=100, that's ~2 tokens, more than enough for 1.
    await asyncio.sleep(0.02)
    assert await b.try_acquire() is True


@pytest.mark.asyncio
async def test_token_bucket_caps_at_burst():
    b = TokenBucket(rate_per_sec=1000, burst=3)
    # Let plenty of time pass; bucket must never overflow burst.
    await asyncio.sleep(0.05)
    for _ in range(3):
        assert await b.try_acquire() is True
    assert await b.try_acquire() is False


@pytest.mark.asyncio
async def test_token_bucket_rejects_invalid_args():
    with pytest.raises(ValueError):
        TokenBucket(rate_per_sec=0, burst=10)
    with pytest.raises(ValueError):
        TokenBucket(rate_per_sec=10, burst=0)


# ── Middleware behaviour ────────────────────────────────────────────

def _build_app(bucket: TokenBucket) -> FastAPI:
    app = FastAPI()
    app.add_middleware(GlobalRateLimitMiddleware, bucket=bucket)

    @app.get("/v1/egress/peers")
    async def peers():
        return {"peers": []}

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.get("/metrics")
    async def metrics():
        return "# metrics\n"

    @app.get("/.well-known/jwks-local.json")
    async def jwks():
        return {"keys": []}

    return app


def test_middleware_sheds_with_503_when_empty():
    # Burst=1 means after one request the bucket is exhausted; with
    # a very low refill rate the next request sheds.
    bucket = TokenBucket(rate_per_sec=0.001, burst=1)
    app = _build_app(bucket)

    with TestClient(app) as client:
        first = client.get("/v1/egress/peers")
        assert first.status_code == 200

        second = client.get("/v1/egress/peers")
        assert second.status_code == 503
        assert second.headers.get("Retry-After") == "1"
        assert second.headers.get("X-Cullis-Shed-Reason") == "global_rate_limit"
        body = second.json()
        assert body["error"] == "global_rate_limit_exceeded"


def test_middleware_bypasses_observability_paths():
    # Drain the bucket, then hit every bypass path — they must all succeed.
    bucket = TokenBucket(rate_per_sec=0.001, burst=1)
    app = _build_app(bucket)

    with TestClient(app) as client:
        client.get("/v1/egress/peers")  # consume the token

        # These must bypass the shed regardless.
        assert client.get("/health").status_code == 200
        assert client.get("/metrics").status_code == 200
        assert client.get("/.well-known/jwks-local.json").status_code == 200


def test_middleware_emits_warning_on_shed(capsys):
    """Regression for cullis-enterprise#11 — shed events must land on
    stderr as a WARNING record in the project's JSON log shape. The
    middleware writes to ``sys.stderr`` directly (see module docstring)
    because the ``mcp_proxy`` logger is silently muted inside the ASGI
    dispatch path at runtime; ``capsys.readouterr().err`` sees that
    stderr output.
    """
    import json as _json

    bucket = TokenBucket(rate_per_sec=0.001, burst=1)
    app = _build_app(bucket)

    with TestClient(app) as client:
        client.get("/v1/egress/peers")  # first request drains the bucket (no log)
        client.get("/v1/egress/peers")  # shed → should log
        client.get("/v1/egress/peers")  # shed → should log again

    captured = capsys.readouterr().err
    shed_lines = [
        line for line in captured.splitlines()
        if "global rate limit shed" in line
    ]
    assert len(shed_lines) == 2, (
        f"expected 2 shed records on stderr, got {len(shed_lines)}:\n{captured!r}"
    )

    # Each line must be a parseable JSON record matching the proxy's
    # JSONFormatter shape so log aggregators don't see an orphan.
    for line in shed_lines:
        record = _json.loads(line)
        assert record["level"] == "WARNING"
        assert record["logger"] == "mcp_proxy"
        assert "timestamp" in record
        assert "path=/v1/egress/peers" in record["message"]
    assert "total_shed=1" in _json.loads(shed_lines[0])["message"]
    assert "total_shed=2" in _json.loads(shed_lines[1])["message"]


def test_middleware_tracks_shed_count():
    bucket = TokenBucket(rate_per_sec=0.001, burst=1)
    app = _build_app(bucket)

    # Fish out the middleware instance to read shed_count. Starlette
    # builds it lazily on first request, so make a request first to
    # populate app.middleware_stack.
    with TestClient(app) as client:
        client.get("/v1/egress/peers")  # 200, token consumed
        for _ in range(3):
            resp = client.get("/v1/egress/peers")
            assert resp.status_code == 503

    # Walk the middleware stack to find our instance.
    mw = app.middleware_stack
    while mw is not None:
        if isinstance(mw, GlobalRateLimitMiddleware):
            assert mw.shed_count == 3
            return
        mw = getattr(mw, "app", None)
    pytest.fail("GlobalRateLimitMiddleware not found in stack")
