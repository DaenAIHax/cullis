"""Tests for the embedded Rego policy engine.

The engine has two halves: ``compile_rego`` (subprocess-based opa CLI
invocation + tar.gz extraction) and ``RegoEngine.evaluate`` (WASM
instantiation via opa-wasmtime). Both are mocked out so the tests
run anywhere without the ``opa`` binary or a working wasmtime
runtime — the unit suite pins the surrounding Python orchestration,
plus the normalisation helper at the surface boundary.

End-to-end Rego compile + WASM eval against a live ``opa`` binary
lives in the dogfood smoke (bundle-built image with /usr/local/bin/opa
shipped), out of scope for this file.
"""
from __future__ import annotations

import io
import subprocess
import tarfile
from unittest.mock import MagicMock

import pytest

from mcp_proxy.policy.rego_engine import (
    CompiledPolicy,
    RegoCompileError,
    RegoEngine,
    RegoEvalError,
    _reset_instance_cache,
    compile_rego,
    evaluate_decision,
)


@pytest.fixture(autouse=True)
def _clear_instance_cache():
    """Reset the process-wide OPAPolicy cache between tests.

    Without this, tests that monkeypatch ``opa_wasmtime.OPAPolicy``
    to a fake class race: the first test populates the cache keyed
    on the fixture WASM bytes' SHA-256, and every subsequent test
    reading the same fixture WASM gets the first test's fake
    instance back instead of its own monkeypatched one.
    """
    _reset_instance_cache()
    yield
    _reset_instance_cache()


# ── tar.gz fixture helpers ────────────────────────────────────────────────


def _make_bundle(wasm_bytes: bytes, name: str = "policy.wasm") -> bytes:
    """Build the same tar.gz shape ``opa build`` produces."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(wasm_bytes)
        tar.addfile(info, io.BytesIO(wasm_bytes))
        # OPA real bundles also ship /.manifest + data.json — include
        # one extra file so the extractor's "pick the .wasm" logic is
        # exercised against a multi-member archive.
        manifest = b'{"revision":"","roots":[""]}'
        meta = tarfile.TarInfo(name="/.manifest")
        meta.size = len(manifest)
        tar.addfile(meta, io.BytesIO(manifest))
    return buf.getvalue()


# ── _resolve_opa_binary ───────────────────────────────────────────────────


def test_resolve_opa_binary_honours_env_pin(monkeypatch, tmp_path):
    """MCP_PROXY_OPA_BINARY env wins over PATH search."""
    fake_opa = tmp_path / "opa"
    fake_opa.write_text("#!/bin/sh\necho 1\n")
    fake_opa.chmod(0o755)
    monkeypatch.setenv("MCP_PROXY_OPA_BINARY", str(fake_opa))
    from mcp_proxy.policy.rego_engine import _resolve_opa_binary
    assert _resolve_opa_binary() == str(fake_opa)


def test_resolve_opa_binary_raises_when_missing(monkeypatch):
    """All candidate paths missing → RegoCompileError (not OSError)."""
    monkeypatch.delenv("MCP_PROXY_OPA_BINARY", raising=False)
    # Force shutil.which to return None for every candidate.
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _: None)
    # And ensure the absolute fallbacks don't accidentally exist.
    monkeypatch.setattr("os.path.isfile", lambda _: False)
    from mcp_proxy.policy.rego_engine import _resolve_opa_binary
    with pytest.raises(RegoCompileError, match="opa binary not found"):
        _resolve_opa_binary()


# ── compile_rego ──────────────────────────────────────────────────────────


@pytest.fixture
def fake_opa(monkeypatch, tmp_path):
    """Stub the opa binary lookup to a tmp path the test owns."""
    fake = tmp_path / "opa"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("MCP_PROXY_OPA_BINARY", str(fake))
    return fake


def test_compile_rego_success(monkeypatch, fake_opa, tmp_path):
    """Happy path: subprocess returns 0, bundle parsed, wasm extracted."""
    expected_wasm = b"\x00asm\x01\x00\x00\x00fake-wasm-bytes"
    bundle = _make_bundle(expected_wasm)

    def _fake_run(args, **kwargs):
        # opa build invocation: write the bundle the caller asked for.
        out_idx = args.index("-o") + 1
        bundle_path = args[out_idx]
        with open(bundle_path, "wb") as f:
            f.write(bundle)
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    out = compile_rego("package cullis.policy\nallow := true")
    assert isinstance(out, CompiledPolicy)
    assert out.wasm == expected_wasm
    assert len(out.sha256) == 64  # sha256 hex


def test_compile_rego_failure_surfaces_stderr(monkeypatch, fake_opa):
    """Non-zero exit → RegoCompileError carrying opa stderr verbatim."""
    def _fake_run(args, **kwargs):
        return MagicMock(
            returncode=1, stdout="",
            stderr="1 error occurred: policy.rego:2: rego_parse_error: unexpected token",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(RegoCompileError, match="rego_parse_error"):
        compile_rego("syntax error here {")


def test_compile_rego_timeout(monkeypatch, fake_opa):
    """opa build hangs → RegoCompileError with timeout context."""
    def _fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(args, kwargs.get("timeout", 10))

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(RegoCompileError, match="timed out"):
        compile_rego("package cullis.policy\nallow := true")


def test_compile_rego_missing_bundle(monkeypatch, fake_opa):
    """opa exits 0 but produces no file → RegoCompileError."""
    def _fake_run(args, **kwargs):
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(RegoCompileError, match="no bundle"):
        compile_rego("package cullis.policy\nallow := true")


def test_compile_rego_bundle_without_wasm(monkeypatch, fake_opa):
    """opa output bundle present but missing .wasm member → RegoCompileError."""
    # Tar with only a manifest, no .wasm.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        manifest = b'{"revision":""}'
        info = tarfile.TarInfo(name="/.manifest")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))
    bundle_bytes = buf.getvalue()

    def _fake_run(args, **kwargs):
        out_idx = args.index("-o") + 1
        with open(args[out_idx], "wb") as f:
            f.write(bundle_bytes)
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(RegoCompileError, match="no .wasm file"):
        compile_rego("package cullis.policy\nallow := true")


# ── RegoEngine.evaluate ───────────────────────────────────────────────────


class _FakeOPAPolicy:
    """Stand-in for opa_wasmtime.OPAPolicy used by the evaluate tests."""

    def __init__(self, wasm_bytes: bytes, result=None, raises: Exception | None = None):
        self._wasm = wasm_bytes
        self._result = result
        self._raises = raises

    def evaluate(self, input_doc, entrypoint: str = "cullis/policy"):
        if self._raises is not None:
            raise self._raises
        # Per OPA WASM ABI, the result is ``[{"result": <document>}]``
        # — return shape matches that.
        return [{"result": self._result}]


def _patch_opa_policy(monkeypatch, result=None, raises: Exception | None = None):
    """Inject ``_FakeOPAPolicy`` in place of the real opa-wasmtime class."""
    fake_module = MagicMock()
    fake_module.OPAPolicy = lambda wasm: _FakeOPAPolicy(wasm, result=result, raises=raises)
    # rego_engine does a lazy import inside ``evaluate``; patch the
    # module in sys.modules so the import inside the function picks
    # up our fake.
    import sys
    monkeypatch.setitem(sys.modules, "opa_wasmtime", fake_module)


def test_engine_evaluate_returns_unwrapped_result(monkeypatch):
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")
    _patch_opa_policy(monkeypatch, result={"decision": "allow"})
    engine = RegoEngine(policy)
    assert engine.evaluate({"agent_id": "a"}) == {"decision": "allow"}


def test_engine_evaluate_empty_list_returns_none(monkeypatch):
    """Rego rule undefined → opa-wasmtime returns ``[]`` → engine surfaces None."""
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")

    fake_module = MagicMock()
    class _EmptyOPA:
        def __init__(self, wasm): pass
        def evaluate(self, doc, entrypoint): return []
    fake_module.OPAPolicy = _EmptyOPA
    import sys
    monkeypatch.setitem(sys.modules, "opa_wasmtime", fake_module)

    engine = RegoEngine(policy)
    assert engine.evaluate({}) is None


def test_engine_evaluate_runtime_error_raises(monkeypatch):
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")
    _patch_opa_policy(monkeypatch, raises=RuntimeError("wasm trap"))
    engine = RegoEngine(policy)
    with pytest.raises(RegoEvalError, match="wasm trap"):
        engine.evaluate({})


# ── evaluate_decision normalisation ───────────────────────────────────────


def test_decision_boolean_true(monkeypatch):
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")
    _patch_opa_policy(monkeypatch, result=True)
    assert evaluate_decision(policy, {}) == {"decision": "allow"}


def test_decision_boolean_false(monkeypatch):
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")
    _patch_opa_policy(monkeypatch, result=False)
    assert evaluate_decision(policy, {}) == {"decision": "deny"}


def test_decision_dict_passthrough_with_reason(monkeypatch):
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")
    _patch_opa_policy(
        monkeypatch,
        result={"decision": "deny", "reason": "Treasury wire outside RFC1918"},
    )
    out = evaluate_decision(policy, {})
    assert out == {"decision": "deny", "reason": "Treasury wire outside RFC1918"}


def test_decision_unexpected_shape_raises(monkeypatch):
    """Rego returned something weird → fail-closed via RegoEvalError."""
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")
    _patch_opa_policy(monkeypatch, result={"verdict": "permit"})  # wrong key
    with pytest.raises(RegoEvalError, match="unexpected shape"):
        evaluate_decision(policy, {})


def test_decision_dict_with_unknown_value_raises(monkeypatch):
    """{decision: 'maybe'} is not allow|deny → fail-closed."""
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00fake")
    _patch_opa_policy(monkeypatch, result={"decision": "maybe"})
    with pytest.raises(RegoEvalError, match="unexpected shape"):
        evaluate_decision(policy, {})


# ── instance cache (perf path) ────────────────────────────────────────────


def test_instance_cache_reuses_for_same_wasm(monkeypatch):
    """Second evaluate on the same bundle MUST NOT re-instantiate OPAPolicy.

    Without cache the engine would rebuild the wasmtime instance on
    every decision (~15-25ms overhead per call). The cache key is the
    bundle SHA-256, so identical bytes share the instance.
    """
    policy = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00cache-test")

    instantiations = 0

    class _CountingOPA:
        def __init__(self, wasm_path):
            nonlocal instantiations
            instantiations += 1
        def evaluate(self, doc, entrypoint):
            return [{"result": {"decision": "allow"}}]

    import sys
    from types import SimpleNamespace
    fake_module = SimpleNamespace(OPAPolicy=_CountingOPA)
    monkeypatch.setitem(sys.modules, "opa_wasmtime", fake_module)

    engine = RegoEngine(policy)
    for _ in range(5):
        engine.evaluate({"x": 1})

    assert instantiations == 1, (
        f"OPAPolicy should be instantiated once per bundle, "
        f"got {instantiations} for 5 evaluates"
    )


def test_instance_cache_distinct_for_different_wasm(monkeypatch):
    """Different WASM bytes → different SHA → different cached instance."""
    p1 = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00first")
    p2 = CompiledPolicy.from_wasm(b"\x00asm\x01\x00\x00\x00second")
    assert p1.sha256 != p2.sha256  # sanity

    instantiations = 0

    class _CountingOPA:
        def __init__(self, wasm_path):
            nonlocal instantiations
            instantiations += 1
        def evaluate(self, doc, entrypoint):
            return [{"result": {"decision": "allow"}}]

    import sys
    from types import SimpleNamespace
    fake_module = SimpleNamespace(OPAPolicy=_CountingOPA)
    monkeypatch.setitem(sys.modules, "opa_wasmtime", fake_module)

    RegoEngine(p1).evaluate({})
    RegoEngine(p2).evaluate({})
    # Repeats: still no new instantiation.
    RegoEngine(p1).evaluate({})
    RegoEngine(p2).evaluate({})

    assert instantiations == 2, (
        f"distinct WASM bundles should each instantiate once; "
        f"got {instantiations}"
    )
