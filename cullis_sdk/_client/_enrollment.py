"""Enrollment + factory classmethods extracted from :mod:`cullis_sdk.client`.

Single public symbol:

* :class:`_EnrollmentMixin` — mixin folded into ``CullisClient`` that
  exposes the eight ``CullisClient.from_*`` / ``enroll_via_*``
  classmethod factories plus the two private helpers shared between
  them.

Methods moved (movement only — byte-perfect):

* ``from_enrollment`` — bootstrap from a Mastio enrollment URL.
* ``from_identity_dir`` — ADR-011 / ADR-014 canonical runtime
  constructor: TLS client cert IS the credential, optional DPoP key.
* ``from_api_key_file`` — backwards-compat alias around
  ``from_identity_dir``; emits ``DeprecationWarning``.
* ``enroll_via_byoca`` — operator-side BYOCA enrollment helper.
* ``enroll_via_spiffe`` — operator-side SPIFFE SVID enrollment helper.
* ``_do_enroll`` — shared machinery for the two ``enroll_via_*`` paths
  (POST → persist → build runtime client).
* ``_persist_enrollment`` — writes ``persist_to/{agent.json, dpop.jwk,
  cert.pem, key.pem}`` with 0600 perms on the private key.
* ``from_connector`` — bootstrap from an enrolled Connector Desktop
  identity on disk (``~/.cullis/identity/``).
* ``from_user_principal_pem`` — ADR-021 PR4c factory for
  Frontdesk-minted user principals (cert + KMS-released key kept in
  a per-process temp dir).
* ``from_spiffe_workload_api`` — legacy direct-to-Court SPIFFE auth;
  emits ``DeprecationWarning`` (ADR-011 sunset path).

Every ``cls.__new__(cls)`` factory replicates the full ``__init__``
attribute surface manually (``_pubkey_cache = {}``, ``_dpop_nonce =
None``, ``_signing_key_pem = None``, ``server_role = None``, …) —
preserved byte-identical here. See memory feedback
``sdk_factory_init_skip``: any drift between the factories and
``__init__`` re-introduces the ``AttributeError`` class of bugs the
existing duplication was designed to prevent.

The module-level helpers ``_check_insecure_tls`` and
``_build_proxy_http_client`` live in :mod:`cullis_sdk.client` (kept
there in PR #722 for backward compat with tests + the lazy import in
:mod:`cullis_sdk._client._rfq`). They are imported lazily inside the
methods that need them to break the import cycle with ``cullis_sdk.
client``.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from cullis_sdk._logging import log

if TYPE_CHECKING:
    from cullis_sdk.client import CullisClient


class _EnrollmentMixin:
    """Factory classmethods + enrollment helpers on ``CullisClient``."""

    @classmethod
    def from_enrollment(
        cls,
        enroll_url: str,
        *,
        save_config: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
        enable_dpop: bool = True,
        dpop_base_dir: "Path | None" = None,
        ca_chain_path: "str | Path | None" = None,
    ) -> "CullisClient":
        """Bootstrap a proxy-connected client from an enrollment URL.

        Calls the enrollment endpoint to receive API key and config, then
        returns a lightweight client pre-configured for the proxy egress API.

        Args:
            enroll_url: Full enrollment URL (e.g. https://proxy/v1/enroll/enroll_xxx)
            save_config: Optional file path to save the received config as .env
            verify_tls: Whether to verify TLS certificates
            timeout: HTTP request timeout in seconds
            ca_chain_path: H10 audit fix — operator-pinned Org CA bundle
                (PEM). When supplied it is loaded into both the
                bootstrap httpx client (used for the enrollment GET)
                AND the long-lived runtime client returned to the
                caller, so the Mastio's self-signed cert verifies
                against the pin instead of the system CA store. This
                completes the threading PR #363 / #365 started for
                ``from_connector``.

        Returns:
            A CullisClient configured with the proxy URL and API key.

        Example::

            client = CullisClient.from_enrollment("https://proxy.example.com/v1/enroll/enroll_buyer_abc123")
            agents = client.discover(capabilities=["order.read"])
        """
        from cullis_sdk.client import _build_proxy_http_client, _check_insecure_tls

        _check_insecure_tls(verify_tls)
        # H10: route the bootstrap GET through the same SSLContext-aware
        # builder as the runtime client so the pinned Org CA is honoured
        # at every step, not just on subsequent calls.
        http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            ca_chain_path=ca_chain_path,
        )
        try:
            resp = http.get(enroll_url)
            resp.raise_for_status()
            config = resp.json()
        except httpx.HTTPStatusError as e:
            raise PermissionError(
                f"Enrollment failed (HTTP {e.response.status_code}): {e.response.text}"
            ) from e
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            raise ConnectionError(f"Enrollment endpoint unreachable: {e}") from e
        finally:
            http.close()

        # Save config to .env file if requested
        if save_config:
            env_lines = [
                f"CULLIS_AGENT_ID={config['agent_id']}",
                f"CULLIS_PROXY_URL={config['proxy_url']}",
                f"CULLIS_ORG_ID={config['org_id']}",
            ]
            Path(save_config).write_text("\n".join(env_lines) + "\n")
            log("sdk", f"Config saved to {save_config}")

        # Build a proxy-oriented client. ADR-014: subsequent calls
        # authenticate by presenting the agent's TLS client cert at the
        # handshake — the caller is responsible for arranging cert+key
        # delivery (out-of-band, separate enrollment endpoint, etc.).
        instance = cls.__new__(cls)
        instance.base = config["proxy_url"].rstrip("/")
        instance._verify_tls = verify_tls
        # H10: thread the pinned Org CA into the long-lived runtime
        # client so every subsequent call (egress, tools/invoke,
        # public-key fetch) verifies against it.
        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            ca_chain_path=ca_chain_path,
        )
        instance.token = None
        instance._label = config["agent_id"]
        instance._signing_key_pem = None
        # H7 audit — see from_identity_dir for the rationale.
        instance._ca_chain_path = Path(ca_chain_path) if ca_chain_path else None
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = None
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = config["agent_id"]
        instance._proxy_org_id = config["org_id"]
        # Dogfood Finding #9 — proxy-bound: see __init__.
        instance._use_egress_for_sessions = True
        # Mirror __init__: callers may attach the on-disk identity bundle
        # afterwards (see ``canonical_recipient`` in cullis_connector).
        instance.identity = None
        # Bug #1 fix — fault in login on the first authed call so
        # ``list_mcp_tools`` / ``call_mcp_tool`` / ``send_oneshot`` /
        # ``chat_completion`` "just work" after ``from_enrollment``.
        # Explicit ``login_via_proxy[_with_local_key]`` before the
        # first call sets ``self.token`` and short-circuits the lazy
        # path. See ``_AuthMixin._authed_request`` for the gate.
        instance._auto_login_pending = True

        # F-B-11 Phase 3c (#181) — load or generate the persistent
        # DPoP keypair. The server stores the thumbprint in
        # ``internal_agents.dpop_jkt`` and refuses proofs signed by a
        # different key once the flag flips to ``required``. First-run
        # generates + persists, subsequent runs load from disk.
        if enable_dpop:
            from cullis_sdk.dpop import DpopKey
            try:
                instance._egress_dpop_key = DpopKey.load_or_generate(
                    config["agent_id"], base_dir=dpop_base_dir,
                )
                log("sdk", f"egress DPoP key ready (jkt={instance._egress_dpop_key.thumbprint()[:16]}…)")
            except OSError as exc:
                # Read-only containers, missing ``HOME``, etc. Fall
                # back to legacy bearer with a warning rather than
                # blowing up enrollment on a DPoP-first deploy.
                import warnings
                warnings.warn(
                    f"Could not persist egress DPoP key ({exc}); "
                    "falling back to legacy X-API-Key bearer. Set "
                    "dpop_base_dir to a writable directory or pass "
                    "enable_dpop=False to silence this warning.",
                    RuntimeWarning,
                    stacklevel=2,
                )

        log("sdk", f"Enrolled as {config['agent_id']} via proxy {config['proxy_url']}")
        return instance

    # ── ADR-011 — unified enrollment + runtime auth ───────────────────

    @classmethod
    def from_identity_dir(
        cls,
        mastio_url: str,
        *,
        cert_path: "str | Path",
        key_path: "str | Path",
        dpop_key_path: "str | Path | None" = None,
        agent_id: str | None = None,
        org_id: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
        ca_chain_path: "str | Path | None" = None,
    ) -> "CullisClient":
        """Primary runtime constructor under ADR-014.

        Builds an httpx.Client that presents the agent's TLS client cert
        at the handshake — that IS the credential. The optional DPoP
        keypair signs each egress request when ``egress_dpop_mode`` is
        ``optional`` or ``required``.

        Args:
            mastio_url: base URL of the Mastio (``https://mastio.local:9443``).
            cert_path, key_path: ADR-014 mTLS material. Required —
                without them ``/v1/egress/*`` returns 401 from nginx.
            dpop_key_path: file holding the private DPoP JWK. Omit to
                run without DPoP binding — only accepted while the
                server's ``egress_dpop_mode`` is ``off`` or ``optional``.
            agent_id, org_id: optional identity metadata. Populated on
                the client instance; the Mastio doesn't require them on
                egress calls (the cert SAN is authoritative) but callers
                rely on them for logging.

        Example::

            client = CullisClient.from_identity_dir(
                "https://mastio.local:9443",
                cert_path="/etc/cullis/agent/cert.pem",
                key_path="/etc/cullis/agent/key.pem",
                dpop_key_path="/etc/cullis/agent/dpop.jwk",
            )
            client.send_oneshot("orgb::agent-b", {"hello": "world"})
        """
        from cullis_sdk.client import _build_proxy_http_client

        instance = cls.__new__(cls)
        instance.base = mastio_url.rstrip("/")
        instance._verify_tls = verify_tls

        # Bug #1 follow-up #3: under ADR-033 three-tier PKI hardening
        # the leaf in ``cert.pem`` is signed by the Mastio Intermediate
        # CA, not the Org Root that nginx's ``ssl_client_certificate``
        # points at. Strict TLS clients (Python ssl, OpenSSL, Go) need
        # the Intermediate on the wire to build the path
        # ``leaf -> Intermediate -> Org Root``.
        #
        # Convention discovery: if a sibling ``ca-chain.pem`` exists
        # next to ``cert_path``, assemble a fullchain file (leaf ||
        # Intermediate, PEM concatenated) and hand THAT to the httpx
        # mTLS context. Customers who pre-assemble fullchain into
        # ``cert.pem`` themselves keep working — they just have no
        # sibling ``ca-chain.pem`` and we use the original
        # ``cert_path`` unchanged. Connector enrollment writes the
        # split layout (cert.pem leaf + ca-chain.pem) so this auto-
        # discovery covers the "30-min-to-agent" customer scenario.
        cert_path_obj = Path(cert_path)
        chain_sibling = cert_path_obj.parent / "ca-chain.pem"
        effective_cert_path: "str | Path" = cert_path
        if chain_sibling.is_file():
            fullchain_path = cert_path_obj.parent / "fullchain.pem"
            try:
                leaf_pem = cert_path_obj.read_text()
                chain_pem = chain_sibling.read_text()
                # Idempotent rewrite: if fullchain.pem is stale (older
                # mtime than either source), regenerate. Otherwise reuse.
                regenerate = (
                    not fullchain_path.is_file()
                    or fullchain_path.stat().st_mtime
                    < max(
                        cert_path_obj.stat().st_mtime,
                        chain_sibling.stat().st_mtime,
                    )
                )
                if regenerate:
                    fullchain_path.write_text(leaf_pem.rstrip() + "\n" + chain_pem)
                effective_cert_path = fullchain_path
                log(
                    "sdk",
                    f"discovered ca-chain.pem sibling → using fullchain="
                    f"{fullchain_path} for mTLS handshake",
                )
            except OSError as exc:
                log(
                    "sdk",
                    f"warning: ca-chain.pem sibling present but unreadable "
                    f"({exc}) — falling back to cert_path leaf only",
                )

        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            cert_path=effective_cert_path,
            key_path=key_path,
            ca_chain_path=ca_chain_path,
        )
        instance.token = None
        instance._label = agent_id or "(client-cert-auth)"
        instance._signing_key_pem = None
        # ADR-014 + Bug #1 follow-up: ``key_path`` is the agent's TLS
        # client cert private key — it IS the signing key under the
        # "TLS cert is the credential" model. Lifting it into
        # ``_signing_key_pem`` lets the lazy auto-login branch in
        # ``_authed_request`` dispatch to ``login_via_proxy_with_local_key``
        # (correct for local-key-holders) instead of ``login_via_proxy``
        # (which 404s at Mastio because Mastio doesn't hold this key).
        try:
            instance._signing_key_pem = Path(key_path).read_text()
        except OSError as exc:
            raise RuntimeError(
                f"from_identity_dir: cannot read key_path={key_path!r} "
                f"for signing-key auto-population ({exc}). The same file "
                f"is required for TLS mTLS handshake."
            ) from exc
        # H7 audit — share the operator-pinned Org CA with the sender-cert
        # verifier. Without this attribute ``decrypt_oneshot`` crashes with
        # AttributeError under the cls.__new__(cls) factory route.
        instance._ca_chain_path = Path(ca_chain_path) if ca_chain_path else None
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = None
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = agent_id
        instance._proxy_org_id = org_id
        # Bug #1 follow-up #2: ``login_via_proxy_with_local_key`` also
        # needs ``_cert_pem`` AND ``_proxy_agent_id`` /
        # ``_proxy_org_id``. ``from_identity_dir`` previously left
        # them unset for callers who didn't pass ``agent_id=`` /
        # ``org_id=`` explicitly, which broke the local-key
        # auto-login dispatch. Fill them in from the cert content on
        # disk so the cohort that holds cert+key locally can mint a
        # LOCAL_TOKEN without a separate enrolment round-trip.
        try:
            instance._cert_pem = Path(cert_path).read_text()
            # Same chain-sibling discovery as the mTLS handshake above:
            # if ``ca-chain.pem`` is present, include the Intermediate
            # in ``_cert_pem`` too so ``/v1/auth/sign-challenged-
            # assertion`` can verify the path against the Org Root.
            if chain_sibling.is_file():
                try:
                    instance._cert_pem = (
                        instance._cert_pem.rstrip() + "\n"
                        + chain_sibling.read_text()
                    )
                except OSError:
                    # Already logged above; mTLS path may still work
                    # if the server is lenient about chain verification.
                    pass
        except OSError as exc:
            raise RuntimeError(
                f"from_identity_dir: cannot read cert_path={cert_path!r} "
                f"({exc}). The same file is required for TLS mTLS handshake."
            ) from exc

        if instance._proxy_agent_id is None or instance._proxy_org_id is None:
            try:
                from cryptography import x509 as _x509
                from cryptography.hazmat.backends import default_backend as _be
                _cert_obj = _x509.load_pem_x509_certificate(
                    instance._cert_pem.encode(), _be(),
                )
                _san_ext = _cert_obj.extensions.get_extension_for_class(
                    _x509.SubjectAlternativeName,
                )
                for _uri in _san_ext.value.get_values_for_type(
                    _x509.UniformResourceIdentifier,
                ):
                    # SPIFFE ID shape: spiffe://<trust_domain>/<org_id>/<agent_name>
                    if not _uri.startswith("spiffe://"):
                        continue
                    _parts = _uri.split("/", 4)
                    if len(_parts) >= 5 and _parts[3] and _parts[4]:
                        _parsed_org = _parts[3]
                        _parsed_name = _parts[4]
                        if instance._proxy_org_id is None:
                            instance._proxy_org_id = _parsed_org
                        if instance._proxy_agent_id is None:
                            instance._proxy_agent_id = (
                                f"{_parsed_org}::{_parsed_name}"
                            )
                        instance._label = instance._proxy_agent_id
                        break
            except Exception as _exc:  # noqa: BLE001 best-effort
                log(
                    "sdk",
                    f"warning: could not extract agent_id from cert SAN: {_exc}",
                )
        # Dogfood Finding #9 — proxy-bound: see __init__.
        instance._use_egress_for_sessions = True
        # ``_update_nonce`` reads ``self.server_role`` on every response;
        # since we skip ``__init__`` above (the ``cls.__new__(cls)`` route
        # that other factories also use), the attribute must exist.
        instance.server_role = None
        instance.identity = None
        # Bug #1 fix — fault in login on the first authed call. See the
        # same flag set in ``from_enrollment`` and the lazy branch in
        # ``_AuthMixin._authed_request``. ADR-014 mTLS handshake remains
        # the credential at /v1/egress/* (no broker token needed there),
        # but the MCP aggregator + broker-mediated paths read ``self.
        # token`` and would otherwise crash on the first call until the
        # caller explicitly invoked login_via_proxy[_with_local_key].
        instance._auto_login_pending = True

        if dpop_key_path is not None:
            from cullis_sdk.dpop import DpopKey
            instance._egress_dpop_key = DpopKey.load(Path(dpop_key_path))
            log("sdk", f"Loaded DPoP key from {dpop_key_path} "
                       f"(jkt={instance._egress_dpop_key.thumbprint()[:16]}…)")

        log("sdk", f"Runtime client ready (mastio={mastio_url}, "
                   f"agent={instance._label})")
        return instance

    @classmethod
    def from_systemd_credentials(
        cls,
        mastio_url: str | None = None,
        *,
        credentials_dir: "str | Path | None" = None,
        cert_name: str = "cert.pem",
        key_name: str = "key.pem",
        dpop_key_name: str | None = "dpop.jwk",
        metadata_name: str | None = "agent.json",
        agent_id: str | None = None,
        org_id: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
        ca_chain_path: "str | Path | None" = None,
    ) -> "CullisClient":
        """Bootstrap from systemd ``LoadCredential=`` material.

        The production deployment pattern that replaces the demo-VM file
        layout (``cert.pem`` + ``key.pem`` at 0600 on a writable disk):
        a systemd unit declares one ``LoadCredential=`` line per file,
        and systemd materialises them under ``$CREDENTIALS_DIRECTORY``
        with restrictive perms — readable only by the unit's user,
        gone when the unit stops, never written to a writable disk
        (the credentials live on tmpfs and only for the process
        lifetime). The SDK reads ``$CREDENTIALS_DIRECTORY`` and points
        ``from_identity_dir`` at it.

        Example unit file::

            [Unit]
            Description=KYC screener agent
            Wants=cullis-mastio.service

            [Service]
            ExecStart=/usr/bin/python /opt/kyc-agent/main.py
            LoadCredential=cert.pem:/etc/cullis/kyc-screener/cert.pem
            LoadCredential=key.pem:/etc/cullis/kyc-screener/key.pem
            LoadCredential=dpop.jwk:/etc/cullis/kyc-screener/dpop.jwk
            LoadCredential=agent.json:/etc/cullis/kyc-screener/agent.json

        And inside the agent::

            client = CullisClient.from_systemd_credentials()
            # mastio_url + agent_id + org_id are loaded from agent.json
            # cert/key/dpop are read from $CREDENTIALS_DIRECTORY/<name>

        Args:
            mastio_url: optional override. When ``None``, the value is
                read from ``agent.json`` under ``$CREDENTIALS_DIRECTORY``.
                Pass explicitly when no ``agent.json`` ships in the unit
                or when the operator wants the URL pinned in code.
            credentials_dir: where to read the files from. When ``None``
                (default), the SDK reads ``$CREDENTIALS_DIRECTORY`` —
                the env var systemd injects for any service that
                declares at least one ``LoadCredential=`` line. Pass
                explicitly to run the agent outside systemd (e.g. in a
                container that mounts a similar tmpfs).
            cert_name, key_name: the basenames inside the credentials
                directory. Defaults match the SDK's persisted layout
                (``cert.pem`` + ``key.pem``) so an operator who
                ``LoadCredential=cert.pem:...`` does not need to override
                them. Adjust when the unit names credentials differently
                (e.g. when reusing an existing PKI bundle layout).
            dpop_key_name: name of the DPoP private JWK file. ``None``
                skips DPoP loading entirely — only safe while the
                Mastio's ``egress_dpop_mode`` is ``off`` or ``optional``.
            metadata_name: name of the JSON metadata file holding
                ``{agent_id, org_id, mastio_url}``. ``None`` skips the
                metadata read (caller passes mastio_url + agent_id +
                org_id directly). The persisted file from
                ``from_enrollment`` is named ``agent.json``.
            agent_id, org_id: optional overrides. When ``None`` and a
                metadata file is present, the value comes from JSON.

        Raises:
            RuntimeError: when ``credentials_dir`` is unset AND
                ``$CREDENTIALS_DIRECTORY`` is not in the environment
                (the unit forgot to declare ``LoadCredential=``).
            FileNotFoundError: when one of the declared files
                (``cert_name``, ``key_name``) is missing from the
                credentials directory.
            RuntimeError: when ``mastio_url`` cannot be resolved (no
                argument passed, no metadata file present, or the JSON
                file is missing the ``mastio_url`` field).
        """
        import json as _json
        import os as _os

        # Resolve the credentials directory: explicit arg wins, otherwise
        # read systemd's ``$CREDENTIALS_DIRECTORY``. Crashing with a
        # specific message beats letting ``open()`` raise a vague
        # FileNotFoundError two stack frames down.
        if credentials_dir is None:
            env_dir = _os.environ.get("CREDENTIALS_DIRECTORY")
            if not env_dir:
                raise RuntimeError(
                    "from_systemd_credentials: $CREDENTIALS_DIRECTORY is "
                    "not set and no credentials_dir argument was passed. "
                    "Either declare at least one LoadCredential= in the "
                    "systemd unit, or pass credentials_dir= explicitly.",
                )
            credentials_dir = env_dir
        creds_path = Path(credentials_dir)

        cert_path = creds_path / cert_name
        key_path = creds_path / key_name
        dpop_path: Path | None = (
            creds_path / dpop_key_name if dpop_key_name else None
        )

        # Eager existence check so the error mentions the missing
        # credential by name rather than failing inside httpx's
        # ssl.SSLContext.load_cert_chain with an opaque OSError.
        for required in (cert_path, key_path):
            if not required.exists():
                raise FileNotFoundError(
                    f"from_systemd_credentials: missing {required.name} "
                    f"under {creds_path}. Confirm the unit's "
                    f"``LoadCredential={required.name}:<host-path>`` line.",
                )
        if dpop_path is not None and not dpop_path.exists():
            # DPoP optional: don't crash when the operator chose not to
            # ship a DPoP key. Behave like ``from_identity_dir`` with
            # ``dpop_key_path=None``.
            dpop_path = None

        # Optional metadata: when the operator ships agent.json next to
        # the credentials, lift mastio_url + agent_id + org_id out of
        # it so the caller's ``from_systemd_credentials()`` call stays
        # zero-argument in the common case. Explicit kwargs still win.
        if metadata_name:
            meta_path = creds_path / metadata_name
            if meta_path.exists():
                try:
                    meta = _json.loads(meta_path.read_text())
                except (OSError, _json.JSONDecodeError) as exc:
                    raise RuntimeError(
                        f"from_systemd_credentials: failed to read "
                        f"metadata file {meta_path}: {exc}",
                    ) from exc
                if mastio_url is None:
                    mastio_url = meta.get("mastio_url")
                if agent_id is None:
                    agent_id = meta.get("agent_id")
                if org_id is None:
                    org_id = meta.get("org_id")

        if not mastio_url:
            raise RuntimeError(
                "from_systemd_credentials: mastio_url is required but "
                "neither the argument nor the metadata file resolved "
                "one. Pass mastio_url= explicitly or ship agent.json "
                "with a ``mastio_url`` field next to the credentials.",
            )

        return cls.from_identity_dir(
            mastio_url,
            cert_path=cert_path,
            key_path=key_path,
            dpop_key_path=dpop_path,
            agent_id=agent_id,
            org_id=org_id,
            verify_tls=verify_tls,
            timeout=timeout,
            ca_chain_path=ca_chain_path,
        )

    # Backwards-compat alias — deprecated. Existing callers that pass
    # ``api_key_path`` get a clear deprecation warning. Prefer
    # ``from_identity_dir(cert_path=..., key_path=..., dpop_key_path=...)``.
    @classmethod
    def from_api_key_file(
        cls,
        mastio_url: str,
        *,
        api_key_path: "str | Path | None" = None,  # ignored, accepted for compat
        dpop_key_path: "str | Path | None" = None,
        cert_path: "str | Path | None" = None,
        key_path: "str | Path | None" = None,
        agent_id: str | None = None,
        org_id: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
        ca_chain_path: "str | Path | None" = None,
    ) -> "CullisClient":
        import warnings
        warnings.warn(
            "CullisClient.from_api_key_file is deprecated under ADR-014 — "
            "the api_key path is gone, the TLS client cert IS the agent "
            "credential. Use from_identity_dir(cert_path=, key_path=, "
            "dpop_key_path=) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if cert_path is None or key_path is None:
            raise ValueError(
                "from_api_key_file (deprecated): cert_path and key_path are "
                "now required. Use from_identity_dir for the canonical entry "
                "point."
            )
        return cls.from_identity_dir(
            mastio_url,
            cert_path=cert_path,
            key_path=key_path,
            dpop_key_path=dpop_key_path,
            agent_id=agent_id,
            org_id=org_id,
            verify_tls=verify_tls,
            timeout=timeout,
            ca_chain_path=ca_chain_path,
        )

    @classmethod
    def enroll_via_byoca(
        cls,
        mastio_url: str,
        *,
        admin_secret: str,
        agent_name: str,
        cert_pem: str,
        private_key_pem: str,
        capabilities: list[str] | None = None,
        display_name: str = "",
        persist_to: "str | Path | None" = None,
        enable_dpop: bool = True,
        federated: bool = False,
        verify_tls: bool = True,
        timeout: float = 10.0,
        ca_chain_path: "str | Path | None" = None,
    ) -> "CullisClient":
        """Operator-side helper: enroll an agent via BYOCA and return a
        runtime-ready client.

        Under ADR-011 BYOCA is an **enrollment** primitive, not a runtime
        auth path — the Mastio verifies the cert chains to its Org CA,
        emits an API key + pins an optional DPoP jkt. The returned client
        is configured with those credentials for the agent's runtime.

        Call this from provisioning code (Helm hook, Vault policy init,
        CI/CD step), not from the agent's runtime entry point. The
        agent itself should use :meth:`from_api_key_file` once the
        credentials are on disk.

        Persists to ``persist_to/{api-key, dpop.jwk, agent.json}`` when
        supplied (mode 0600); otherwise the credentials stay in memory.

        Requires admin access to the Mastio (``admin_secret``).
        """
        return cls._do_enroll(
            mastio_url=mastio_url,
            endpoint_path="/v1/admin/agents/enroll/byoca",
            admin_secret=admin_secret,
            body={
                "agent_name": agent_name,
                "display_name": display_name,
                "capabilities": list(capabilities or []),
                "cert_pem": cert_pem,
                "private_key_pem": private_key_pem,
                "federated": federated,
            },
            persist_to=persist_to,
            enable_dpop=enable_dpop,
            verify_tls=verify_tls,
            timeout=timeout,
            ca_chain_path=ca_chain_path,
        )

    @classmethod
    def enroll_via_spiffe(
        cls,
        mastio_url: str,
        *,
        admin_secret: str,
        agent_name: str,
        svid_pem: str,
        svid_key_pem: str,
        trust_bundle_pem: str | None = None,
        capabilities: list[str] | None = None,
        display_name: str = "",
        persist_to: "str | Path | None" = None,
        enable_dpop: bool = True,
        federated: bool = False,
        verify_tls: bool = True,
        timeout: float = 10.0,
        ca_chain_path: "str | Path | None" = None,
    ) -> "CullisClient":
        """Operator-side helper: enroll an agent via SPIFFE SVID and
        return a runtime-ready client.

        The Mastio verifies the SVID against the SPIRE trust bundle
        (either the per-request ``trust_bundle_pem`` override or the
        operator-configured ``proxy_config.spire_trust_bundle``), pins
        the SPIFFE URI SAN as the agent's ``spiffe_id``, and emits the
        API key + DPoP jkt. See :meth:`enroll_via_byoca` for the
        persistence / runtime split.
        """
        body = {
            "agent_name": agent_name,
            "display_name": display_name,
            "capabilities": list(capabilities or []),
            "svid_pem": svid_pem,
            "svid_key_pem": svid_key_pem,
            "federated": federated,
        }
        if trust_bundle_pem is not None:
            body["trust_bundle_pem"] = trust_bundle_pem
        return cls._do_enroll(
            mastio_url=mastio_url,
            endpoint_path="/v1/admin/agents/enroll/spiffe",
            admin_secret=admin_secret,
            body=body,
            persist_to=persist_to,
            enable_dpop=enable_dpop,
            verify_tls=verify_tls,
            timeout=timeout,
            ca_chain_path=ca_chain_path,
        )

    @classmethod
    def _do_enroll(
        cls,
        *,
        mastio_url: str,
        endpoint_path: str,
        admin_secret: str,
        body: dict,
        persist_to: "str | Path | None",
        enable_dpop: bool,
        verify_tls: bool,
        timeout: float,
        ca_chain_path: "str | Path | None" = None,
    ) -> "CullisClient":
        """Shared machinery for every ``enroll_via_*`` helper.

        Generates a DPoP keypair in memory, attaches its public JWK to
        the enrollment body, POSTs to the Mastio endpoint, persists the
        credentials and returns a runtime-ready client. Kept private —
        the public surface is ``enroll_via_byoca`` / ``enroll_via_spiffe``
        so the method names read as the user's intent, not as the
        underlying transport.
        """
        from cullis_sdk.client import _build_proxy_http_client, _check_insecure_tls
        from cullis_sdk.dpop import DpopKey

        _check_insecure_tls(verify_tls)
        dpop_key: "DpopKey | None" = None
        if enable_dpop:
            dpop_key = DpopKey.generate(path=None)
            body = {**body, "dpop_jwk": dict(dpop_key.public_jwk)}

        url = f"{mastio_url.rstrip('/')}{endpoint_path}"
        headers = {
            "X-Admin-Secret": admin_secret,
            "Content-Type": "application/json",
        }

        # H10: route the bootstrap POST through the SSLContext-aware
        # builder so the pinned Org CA is honoured during enrollment,
        # not only for subsequent runtime calls.
        http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            ca_chain_path=ca_chain_path,
        )
        try:
            resp = http.post(url, json=body, headers=headers)
        finally:
            http.close()
        if resp.status_code not in (200, 201):
            raise PermissionError(
                f"Enrollment failed (HTTP {resp.status_code}): {resp.text}"
            )
        enrolled = resp.json()
        agent_id = enrolled["agent_id"]
        org_id = agent_id.split("::", 1)[0] if "::" in agent_id else None

        # ADR-014: BYOCA agents bring their own cert+key (already in
        # ``body["cert_pem"]`` / ``body["private_key_pem"]``). SPIFFE
        # agents bring an SVID under different keys. We persist the
        # cert+key when the caller asked for disk persistence so the
        # runtime client can present them at the TLS handshake against
        # nginx — that cert IS the credential under PR-C.
        cert_pem_runtime = body.get("cert_pem") or body.get("svid_pem")
        key_pem_runtime = body.get("private_key_pem") or body.get("svid_key_pem")

        cert_path_runtime: "Path | None" = None
        key_path_runtime: "Path | None" = None
        if persist_to is not None:
            persist_dir = Path(persist_to)
            cls._persist_enrollment(
                persist_dir,
                agent_id=agent_id,
                org_id=org_id,
                mastio_url=mastio_url,
                dpop_key=dpop_key,
                cert_pem=cert_pem_runtime,
                private_key_pem=key_pem_runtime,
            )
            if cert_pem_runtime and key_pem_runtime:
                cert_path_runtime = persist_dir / "cert.pem"
                key_path_runtime = persist_dir / "key.pem"

        instance = cls.__new__(cls)
        instance.base = mastio_url.rstrip("/")
        instance._verify_tls = verify_tls
        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            cert_path=cert_path_runtime,
            key_path=key_path_runtime,
            ca_chain_path=ca_chain_path,
        )
        instance.token = None
        instance._label = agent_id
        instance._signing_key_pem = None
        # H7 audit — see from_identity_dir for the rationale.
        instance._ca_chain_path = None
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = dpop_key
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = agent_id
        instance._proxy_org_id = org_id
        # Dogfood Finding #9 — proxy-bound: see __init__.
        instance._use_egress_for_sessions = True
        instance.server_role = None
        instance.identity = None

        log("sdk", f"Enrolled {agent_id} via {endpoint_path}")
        return instance

    @staticmethod
    def _persist_enrollment(
        persist_to: "Path",
        *,
        agent_id: str,
        org_id: str | None,
        mastio_url: str,
        dpop_key,  # DpopKey | None
        cert_pem: str | None = None,
        private_key_pem: str | None = None,
    ) -> None:
        """Write enrollment credentials under ``persist_to/`` with 0600
        perms on secrets. Layout (ADR-014):

            persist_to/dpop.jwk       — private DPoP JWK (only if enabled)
            persist_to/agent.json     — {agent_id, org_id, mastio_url}
            persist_to/cert.pem       — leaf cert (mTLS, the credential)
            persist_to/key.pem        — private key (mTLS, the credential)
        """
        import json as _json
        import os as _os
        persist_to.mkdir(parents=True, exist_ok=True)

        (persist_to / "agent.json").write_text(_json.dumps({
            "agent_id": agent_id,
            "org_id": org_id,
            "mastio_url": mastio_url,
        }, indent=2))

        if dpop_key is not None:
            dpop_key.save(persist_to / "dpop.jwk")

        if cert_pem:
            (persist_to / "cert.pem").write_text(cert_pem)
        if private_key_pem:
            key_file = persist_to / "key.pem"
            key_file.write_text(private_key_pem)
            _os.chmod(key_file, 0o600)

    @classmethod
    def from_connector(
        cls,
        config_dir: str | Path | None = None,
        *,
        timeout: float = 10.0,
        enable_dpop: bool = True,
        verify_tls: bool | None = None,
    ) -> "CullisClient":
        """Build a client from an enrolled Connector Desktop identity on disk.

        Reads ``~/.cullis/identity/`` (or a custom ``config_dir``) and
        returns a client pre-configured with the Mastio URL, agent_id,
        and API key. Call :meth:`login_via_proxy` afterwards to obtain a
        broker access token.

        Layout expected (written by the Connector at enrollment time):

            <config_dir>/identity/agent.crt       ← agent cert (PEM)
            <config_dir>/identity/agent.key       ← agent key (PEM)
            <config_dir>/identity/metadata.json   ← agent_id, site_url, ...

        ADR-014 PR-C: the cert is the credential — no api_key file is
        read. Earlier Connectors that wrote ``identity/api_key`` are
        compatible (the file is ignored).

        Raises ``FileNotFoundError`` if the identity hasn't been enrolled
        yet (user should open the Connector dashboard first).
        """
        from cullis_sdk.client import _build_proxy_http_client

        import json as _json
        if config_dir is None:
            config_dir = Path.home() / ".cullis"
        else:
            config_dir = Path(config_dir)

        identity_dir = config_dir / "identity"
        metadata_path = identity_dir / "metadata.json"

        if not metadata_path.exists():
            raise FileNotFoundError(
                f"Connector identity not found at {identity_dir}. "
                "Open the Connector dashboard and complete enrollment first."
            )

        metadata = _json.loads(metadata_path.read_text())
        agent_id = metadata.get("agent_id")
        site_url = metadata.get("site_url")
        if not agent_id or not site_url:
            raise RuntimeError(
                f"metadata.json at {metadata_path} is missing agent_id or site_url"
            )

        org_id = agent_id.split("::", 1)[0] if "::" in agent_id else ""

        # verify_tls precedence: explicit caller arg > URL scheme default.
        # The Connector itself doesn't persist a TLS-verify preference, so
        # callers (the ``serve`` CLI when ``--no-verify-tls`` is set, or
        # tests pinning the dev path) override the URL-scheme default.
        if verify_tls is None:
            verify_tls = site_url.startswith("https://")

        instance = cls.__new__(cls)
        instance.base = site_url.rstrip("/")
        instance._verify_tls = verify_tls
        instance.token = None
        instance._label = agent_id
        instance.server_role = None
        # Load the on-disk signing key + cert eagerly so ``decrypt_oneshot``,
        # ``send_oneshot``, and ``login_via_proxy_with_local_key`` all
        # work out of the box without every caller having to read
        # ``identity/agent.key`` + ``identity/agent.crt`` themselves.
        # Absent key/cert (legacy layout or a Connector that never
        # completed enrollment) is not fatal — tools that need them
        # surface a clear error at call time.
        key_path = identity_dir / "agent.key"
        cert_path = identity_dir / "agent.crt"
        instance._signing_key_pem = key_path.read_text() if key_path.exists() else None
        instance._cert_pem = cert_path.read_text() if cert_path.exists() else None
        # ADR-014: present the agent cert at the TLS handshake when both
        # files exist on disk. nginx in front of the Mastio verifies the
        # cert chain to the Org CA and derives the agent identity for
        # ``/v1/egress/*``. Connectors that completed enrollment after
        # 0.3.x always have both files; the conditional only covers the
        # transitional case where a legacy dump shipped only the cert.
        _mtls_cert = cert_path if (cert_path.exists() and key_path.exists()) else None
        _mtls_key = key_path if _mtls_cert is not None else None
        # ADR-015 — TOFU-pinned Org CA. The Connector dashboard writes
        # ``identity/ca-chain.pem`` after the operator confirms the
        # SHA-256 fingerprint at first contact. When present, the
        # proxy-facing httpx client must verify the Mastio's cert
        # against this pin (not the system CA store).
        _pinned_ca = identity_dir / "ca-chain.pem"
        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            cert_path=_mtls_cert,
            key_path=_mtls_key,
            ca_chain_path=_pinned_ca if _pinned_ca.exists() else None,
        )
        # H7 audit fix — share the TOFU-pinned Org CA with the sender-cert
        # verifier. ``decrypt_oneshot`` and the inner-signature path
        # then chain-validate the sender's leaf cert against the
        # operator-confirmed CA, not just any syntactically valid cert.
        instance._ca_chain_path = _pinned_ca if _pinned_ca.exists() else None
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = None
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = agent_id
        instance._proxy_org_id = org_id
        # Dogfood Finding #9 — proxy-bound: route session ops through
        # /v1/egress/sessions* (handles intra-org locally, falls
        # through to broker bridge for cross-org).
        instance._use_egress_for_sessions = True
        # Mirror __init__: callers may attach the on-disk identity bundle
        # afterwards (see ``canonical_recipient`` in cullis_connector).
        instance.identity = None

        # F-B-11 Phase 3c + 3d — load the DPoP keypair alongside the
        # rest of the Connector identity. Phase 3d (#181) has the
        # Connector persist it at enrollment time as ``dpop.jwk``
        # next to ``agent.crt`` / ``agent.key``. For legacy Connectors
        # (pre-3d) that never persisted one, generate locally and
        # reuse on subsequent runs — but note the resulting thumbprint
        # is NOT bound server-side until the operator registers it
        # via the admin endpoint (#206) or re-enrolls.
        if enable_dpop:
            from cullis_sdk.dpop import DpopKey
            dpop_path = identity_dir / "dpop.jwk"
            try:
                if dpop_path.exists():
                    instance._egress_dpop_key = DpopKey.load(dpop_path)
                else:
                    instance._egress_dpop_key = DpopKey.generate(path=dpop_path)
            except (OSError, ValueError) as exc:
                import warnings
                warnings.warn(
                    f"Could not load or generate egress DPoP key at "
                    f"{dpop_path}: {exc}. Continuing without DPoP — the "
                    f"client cert at the TLS handshake still authenticates; "
                    f"pass enable_dpop=False to silence.",
                    RuntimeWarning,
                    stacklevel=2,
                )

        log("sdk", f"Loaded Connector identity {agent_id} from {identity_dir}")
        return instance

    # ── ADR-021 PR4c — user-principal client (in-memory cert+key) ───

    @classmethod
    def from_user_principal_pem(
        cls,
        site_url: str,
        *,
        principal_id: str,
        cert_pem: str,
        key_pem: str,
        ca_chain_pem: str | None = None,
        timeout: float = 10.0,
        enable_dpop: bool = True,
        verify_tls: bool | None = None,
    ) -> "CullisClient":
        """Build a CullisClient bound to a Frontdesk-minted user principal.

        Counterpart to :meth:`from_connector`, but for the shared-mode
        Frontdesk Ambassador (ADR-021 PR4c) where the per-user cert and
        KMS-released key live entirely in memory: nothing on disk, the
        cert lifecycle is the SSO session lifecycle, and the lookup key
        is the 4-segment ``<td>/<org>/<type>/<name>`` principal_id.

        ``cert_pem`` + ``key_pem`` are the user's freshly-signed
        ADR-020 typed-principal cert (CN/O empty, SPIFFE SAN
        ``spiffe://<td>/<org>/user/<name>``) and the matching private
        key the embedded KMS just released. The factory persists them
        to a per-process temp dir so httpx + nginx can use them at the
        TLS handshake — the temp files inherit the current umask and
        are removed on ``close()`` / GC. The cert lives at most as long
        as the cached :class:`UserCredentials` row in the Ambassador.

        ``principal_id`` must be the 4-segment form. The factory derives
        the canonical typed ``agent_id`` (``{org}::user::{name}`` for
        users / workloads, ``{org}::{name}`` for plain agents) so JWT
        ``sub`` and the broker x509_verifier's parse line up exactly.

        Caller is expected to invoke
        :meth:`login_via_proxy_with_local_key` afterwards to mint a
        DPoP-bound access token. Building the client and minting the
        token are kept separate so the ambassador can probe identity
        before paying the full login round-trip.
        """
        from cullis_sdk.client import _build_proxy_http_client

        import tempfile

        parts = principal_id.split("/")
        if len(parts) != 4:
            raise ValueError(
                "principal_id must be ``<td>/<org>/<type>/<name>``; "
                f"got {principal_id!r}",
            )
        _td, org_id, ptype, name = parts
        if ptype not in ("agent", "user", "workload"):
            raise ValueError(
                f"principal_id has unknown type segment {ptype!r}; "
                "expected one of agent / user / workload",
            )
        if ptype == "agent":
            agent_id = f"{org_id}::{name}"
        else:
            agent_id = f"{org_id}::{ptype}::{name}"

        if verify_tls is None:
            verify_tls = site_url.startswith("https://")

        # Persist cert + key + CA bundle to a temp dir so httpx's SSL
        # context can load them at the handshake. Tracked on the
        # instance so ``close()`` cleans them up; nothing else needs
        # them after the client is constructed.
        tmp = tempfile.mkdtemp(prefix="cullis-user-")
        cert_path = Path(tmp) / "cert.pem"
        key_path = Path(tmp) / "key.pem"
        cert_path.write_text(cert_pem)
        key_path.write_text(key_pem)
        os.chmod(key_path, 0o600)
        ca_path: Path | None = None
        if ca_chain_pem:
            ca_path = Path(tmp) / "ca-chain.pem"
            ca_path.write_text(ca_chain_pem)

        instance = cls.__new__(cls)
        instance.base = site_url.rstrip("/")
        instance._verify_tls = verify_tls
        instance.token = None
        instance._label = agent_id
        instance.server_role = None
        instance._signing_key_pem = key_pem
        instance._cert_pem = cert_pem
        instance._http = _build_proxy_http_client(
            verify_tls=verify_tls,
            timeout=timeout,
            cert_path=cert_path,
            key_path=key_path,
            ca_chain_path=ca_path,
        )
        instance._ca_chain_path = ca_path
        instance._pubkey_cache = {}
        instance._client_seq = {}
        instance._dpop_privkey = None
        instance._dpop_pubkey_jwk = None
        instance._dpop_nonce = None
        instance._egress_dpop_key = None
        instance._egress_dpop_nonce = None
        instance._proxy_agent_id = agent_id
        instance._proxy_org_id = org_id
        instance._use_egress_for_sessions = True
        instance.identity = None
        # Track the temp dir so ``close()`` / ``__del__`` can wipe the
        # cert + key off disk. The temp files are mode 600 + key 600,
        # but the on-disk dwell-time still wants to be minimised.
        instance._user_principal_tmpdir = tmp

        if enable_dpop:
            from cullis_sdk.dpop import DpopKey
            instance._egress_dpop_key = DpopKey.generate()

        log(
            "sdk",
            f"Loaded user-principal identity {agent_id} (principal_id={principal_id})",
        )
        return instance

    # ── SPIFFE Workload API bootstrap ───────────────────────────────

    @classmethod
    def from_spiffe_workload_api(
        cls,
        broker_url: str,
        *,
        org_id: str,
        socket_path: str | None = None,
        agent_id: str | None = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> "CullisClient":
        """**Deprecated under ADR-011.** SPIFFE→Court direct login.

        Under the unified model SPIFFE becomes an *enrollment* primitive:
        operators use :meth:`enroll_via_spiffe` once (at provisioning
        time) to exchange an SVID for an API key + DPoP jkt, then the
        agent runs with :meth:`from_api_key_file` at runtime. The
        Court's ``/v1/auth/token`` endpoint is sunset (see the
        ``Deprecation`` / ``Sunset`` headers the server returns). This
        method continues to work until the Court returns 410 Gone.

        Bootstrap a broker-connected client using a SPIFFE X.509-SVID.

        Fetches the workload's SVID from the local SPIFFE Workload API
        (typically a SPIRE agent Unix socket), then authenticates to the
        broker using that certificate. Requires the ``[spiffe]`` extra.
        """
        import warnings
        warnings.warn(
            "CullisClient.from_spiffe_workload_api is deprecated under "
            "ADR-011. Use CullisClient.enroll_via_spiffe(...) once at "
            "provisioning time, then CullisClient.from_api_key_file(...) "
            "at runtime. The Court's /v1/auth/token returns 410 Gone "
            "after sunset (~90d).",
            DeprecationWarning,
            stacklevel=2,
        )
        from cullis_sdk.spiffe import fetch_x509_svid, default_agent_id

        svid = fetch_x509_svid(socket_path)
        resolved_agent_id = agent_id or default_agent_id(svid.spiffe_id, org_id)

        instance = cls(broker_url, verify_tls=verify_tls, timeout=timeout)
        instance._legacy_login_from_pem(
            resolved_agent_id, org_id, svid.cert_pem, svid.key_pem,
        )
        log("sdk", f"Authenticated {resolved_agent_id} via SPIFFE ({svid.spiffe_id})")
        return instance
