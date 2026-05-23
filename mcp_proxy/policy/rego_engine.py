"""Embedded Rego policy engine — OPA WASM eval inside the Mastio process.

Operators write Rego policies in the dashboard Policies page; the
backend compiles them to a WebAssembly bundle via the ``opa`` CLI
shipped alongside the Mastio binary, persists the WASM blob next to
the source, and evaluates each policy decision in-process via
``opa-wasmtime``. No sidecar OPA daemon, no extra container, no
network hop on the decision hot path.

Two surfaces:

  * :func:`compile_rego` — synchronous subprocess invocation of the
    bundled ``opa build`` against a tempdir containing the operator's
    Rego source. Returns the resulting WASM bytes (extracted from the
    OPA bundle tarball). Raises :class:`RegoCompileError` on syntax /
    package errors, surfacing the operator-facing diagnostic message
    so the dashboard can render it inline.

  * :class:`RegoEngine` — wraps a compiled WASM bundle. ``evaluate``
    takes an arbitrary JSON-serialisable input and returns the policy
    decision dict the operator's Rego computes under
    ``data.cullis.policy.<surface>``. Thread-safe (the underlying
    ``OPAPolicy`` is re-instantiated per call so wasmtime instance
    state never leaks between evaluations).

Failure modes are explicitly fail-closed:

  * Compile error → :class:`RegoCompileError` — the dashboard surfaces
    the message; the legacy allowlist path stays active until the
    operator fixes the Rego.

  * Runtime error (WASM trap, malformed input, missing
    ``data.cullis.policy.<surface>`` rule) → the caller sees the
    exception and treats the decision as ``deny`` (the
    PDP / tool_call / policy_bridge handlers wrap the engine call so
    a runtime fault never returns a stale ``allow``).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_log = logging.getLogger("mcp_proxy.policy.rego_engine")


# Operator can pin the ``opa`` binary location via env (containers
# bundle it at ``/usr/local/bin/opa``); the default search PATH covers
# developer machines where it lives on /usr/bin / /usr/local/bin.
_OPA_BINARY_ENV = "MCP_PROXY_OPA_BINARY"
_OPA_DEFAULT_PATHS = ("opa", "/usr/local/bin/opa", "/usr/bin/opa")

# Compile timeout — Rego is small; honest policies compile in < 1 s.
# 10 s guards against a wedged subprocess without making the dashboard
# Save button feel hung.
_COMPILE_TIMEOUT_SECONDS = 10.0


class RegoCompileError(RuntimeError):
    """Surface the ``opa build`` diagnostic to the operator."""


class RegoEvalError(RuntimeError):
    """Surface a runtime WASM eval fault to the caller."""


@dataclass(frozen=True)
class CompiledPolicy:
    """Compiled WASM bundle + the digest the cache keys on."""

    wasm: bytes
    sha256: str

    @classmethod
    def from_wasm(cls, wasm: bytes) -> "CompiledPolicy":
        digest = hashlib.sha256(wasm).hexdigest()
        return cls(wasm=wasm, sha256=digest)


def _resolve_opa_binary() -> str:
    """Find the ``opa`` binary, honouring ``MCP_PROXY_OPA_BINARY``.

    Raises :class:`RegoCompileError` (not FileNotFoundError) so the
    dashboard can surface the same error class for both
    binary-missing and compile-failed paths.
    """
    pinned = os.environ.get(_OPA_BINARY_ENV)
    candidates = (pinned,) if pinned else _OPA_DEFAULT_PATHS
    for cand in candidates:
        if not cand:
            continue
        # Honour absolute paths verbatim; fall back to PATH lookup for
        # the bare ``opa`` candidate.
        if os.path.isabs(cand):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
            continue
        import shutil
        resolved = shutil.which(cand)
        if resolved:
            return resolved
    raise RegoCompileError(
        f"opa binary not found (looked at: {candidates}). Install OPA "
        f"on the Mastio host or pin the location via {_OPA_BINARY_ENV}.",
    )


def compile_rego(source: str, *, package: str = "cullis.policy") -> CompiledPolicy:
    """Compile a Rego source string into a WASM bundle.

    Args:
        source: the Rego document the operator authored.
        package: the package path the Rego is expected to declare.
            ``opa build -e <entrypoint>`` requires an explicit
            entrypoint per rule; the caller picks the surface (e.g.
            ``cullis.policy.session``, ``cullis.policy.tool_call``).
            We compile with the package root as the entrypoint so a
            single bundle can serve multiple surfaces; the WASM eval
            then drills into the path the caller asks for.

    Returns:
        A :class:`CompiledPolicy` carrying the raw WASM bytes (the
        caller persists them as a BLOB next to the source) and the
        SHA-256 digest (used as the cache key by :class:`RegoEngine`).

    Raises:
        RegoCompileError: any compile failure — surfaced with the
            ``opa build`` stderr so the dashboard can show the operator
            the exact line / column that failed.
    """
    opa = _resolve_opa_binary()
    with tempfile.TemporaryDirectory(prefix="cullis-rego-") as workdir:
        src_path = Path(workdir) / "policy.rego"
        src_path.write_text(source)
        bundle_path = Path(workdir) / "bundle.tar.gz"
        try:
            result = subprocess.run(
                [
                    opa, "build",
                    "-t", "wasm",
                    "-e", package,
                    "-o", str(bundle_path),
                    str(src_path),
                ],
                capture_output=True,
                text=True,
                timeout=_COMPILE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RegoCompileError(
                f"opa build timed out after {_COMPILE_TIMEOUT_SECONDS}s",
            ) from exc

        if result.returncode != 0:
            # opa build writes diagnostics to stderr; preserve both
            # streams since some errors land on stdout.
            diag = (result.stderr or result.stdout or "").strip()
            raise RegoCompileError(
                diag or f"opa build exited with code {result.returncode}",
            )

        if not bundle_path.exists():
            raise RegoCompileError("opa build produced no bundle output")

        # The bundle is a tar.gz containing ``/policy.wasm`` (plus
        # data + manifest). Extract just the WASM blob.
        try:
            with tarfile.open(bundle_path, mode="r:gz") as tar:
                members = [m for m in tar.getmembers() if m.name.endswith(".wasm")]
                if not members:
                    raise RegoCompileError(
                        "opa build bundle contained no .wasm file",
                    )
                member = members[0]
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise RegoCompileError(
                        f"opa build bundle entry {member.name} unreadable",
                    )
                wasm = extracted.read()
        except tarfile.TarError as exc:
            raise RegoCompileError(
                f"opa build bundle not a valid tar.gz: {exc}",
            ) from exc

    return CompiledPolicy.from_wasm(wasm)


class RegoEngine:
    """Evaluate a compiled WASM policy against an arbitrary input.

    Thread-safety: each :meth:`evaluate` call constructs a fresh
    ``OPAPolicy`` instance so wasmtime store / linker state stays
    local to the call. The overhead is one WASM instantiate per
    decision (~100µs on modest hardware per opa-wasmtime
    benchmarks); for hotter paths a per-thread cache could be
    layered later, but the Mastio's decision rate makes the
    simplicity worth it today.
    """

    def __init__(self, policy: CompiledPolicy):
        self._policy = policy

    @property
    def sha256(self) -> str:
        return self._policy.sha256

    def evaluate(self, input_doc: Any, *, entrypoint: str = "cullis/policy") -> Any:
        """Run the policy against ``input_doc`` and return the result.

        The Rego is expected to compute the decision document at
        ``data.cullis.policy.<surface>`` so the operator can write
        rules for both ``session`` and ``tool_call`` in one Rego file
        with separate rules per surface. ``entrypoint`` selects which
        sub-document the WASM eval returns.

        Args:
            input_doc: any JSON-serialisable input (typically the OPA
                ``input`` dict that the caller would otherwise pass via
                the OPA Data API HTTP endpoint).
            entrypoint: the slash-separated package path to evaluate.
                Default ``cullis/policy`` returns the entire policy
                document; pass ``cullis/policy/session`` /
                ``cullis/policy/tool_call`` to drill into one surface.

        Returns:
            The decoded JSON result (typically a dict with
            ``decision`` + ``reason``).

        Raises:
            RegoEvalError: any WASM trap, JSON decode failure, or
                wasmtime startup error. Callers MUST treat this as a
                deny.
        """
        # Lazy import so the engine module loads without the wasmtime
        # native lib pulled in until first eval. Helps test
        # environments that monkeypatch the import.
        try:
            from opa_wasmtime import OPAPolicy  # type: ignore
        except ImportError as exc:
            raise RegoEvalError(
                "opa-wasmtime is not installed — cannot evaluate WASM "
                "policy. Install ``opa-wasmtime`` in the Mastio image.",
            ) from exc

        try:
            opa_policy = OPAPolicy(self._policy.wasm)
        except Exception as exc:
            raise RegoEvalError(
                f"OPAPolicy instantiation failed: {exc}",
            ) from exc

        try:
            # opa-wasmtime's evaluate accepts a dict; it JSON-serialises
            # internally and returns the decoded result.
            result = opa_policy.evaluate(input_doc, entrypoint=entrypoint)
        except Exception as exc:
            raise RegoEvalError(
                f"WASM eval failed for entrypoint={entrypoint}: {exc}",
            ) from exc

        # opa-wasmtime returns ``[{"result": <document>}]`` per the OPA
        # WASM ABI contract. Unwrap so callers see the document
        # directly. When the policy has no opinion (rule undefined),
        # the result is an empty list — surface as ``None``.
        if isinstance(result, list):
            if not result:
                return None
            head = result[0]
            if isinstance(head, dict) and "result" in head:
                return head["result"]
            return head
        return result


def evaluate_decision(
    policy: CompiledPolicy,
    input_doc: dict,
    *,
    entrypoint: str = "cullis/policy",
) -> dict:
    """Convenience: evaluate + normalise to the dashboard decision shape.

    Rego authors are free to return any shape under
    ``data.cullis.policy.<surface>``; the Mastio dashboard + the OPA
    Data API endpoint expect ``{"decision": "allow"|"deny",
    "reason": str?}``. This helper coerces the common shapes:

      * Boolean ``true`` → ``{"decision": "allow"}``
      * Boolean ``false`` → ``{"decision": "deny"}``
      * Dict with ``decision`` key → returned as-is (with ``reason``
        coerced to string if non-empty)
      * Anything else → ``RegoEvalError`` (so the caller fails-closed)

    Returns a dict guaranteed to carry ``decision``.
    """
    engine = RegoEngine(policy)
    result = engine.evaluate(input_doc, entrypoint=entrypoint)

    if result is True:
        return {"decision": "allow"}
    if result is False:
        return {"decision": "deny"}
    if isinstance(result, dict):
        decision = result.get("decision")
        if decision in {"allow", "deny"}:
            out = {"decision": decision}
            reason = result.get("reason")
            if reason:
                out["reason"] = str(reason)
            return out
    raise RegoEvalError(
        f"Rego policy returned unexpected shape: {json.dumps(result)[:200]} "
        f"— expected boolean or {{decision, reason}} dict.",
    )
