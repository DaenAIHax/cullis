"""
Pytest fixtures for the Cullis full-stack E2E test (Item 12 in plan.md).

The `e2e_stack` fixture is session-scoped: it boots the entire docker
compose stack ONCE for all e2e tests in the session, then tears it down
in a try/finally so a failed test never leaks containers.

By design these fixtures only run when pytest is invoked with `-m e2e`.
The `not e2e` marker filter in pytest.ini skips them otherwise.
"""
import os
import pathlib
import shutil
import subprocess
import time
from typing import Iterator

import httpx
import pytest

# Resolve paths relative to this file so the test can be invoked from any cwd.
_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
_COMPOSE_FILE = _HERE / "docker-compose.e2e.yml"
_PROJECT_NAME = "cullis-e2e"

# Fixtures directory bind-mounted into the broker container as /app/certs.
# Must be writable by the container's `appuser` because the broker writes
# .admin_secret_hash here on first boot when KMS_BACKEND=local.
_FIXTURES_DIR = _HERE / ".fixtures"
_BROKER_CERTS_FIXTURE = _FIXTURES_DIR / "broker_certs"

# Endpoints exposed on the host (matching the port mapping in the compose file)
BROKER_URL = "http://localhost:18000"
PROXY_ALPHA_URL = "http://localhost:19100"
PROXY_BETA_URL = "http://localhost:19101"

# Credentials baked into docker-compose.e2e.yml
ADMIN_SECRET = "cullis-e2e-admin-secret-do-not-reuse"
PROXY_ALPHA_ADMIN_SECRET = "cullis-e2e-proxy-alpha-secret"
PROXY_BETA_ADMIN_SECRET = "cullis-e2e-proxy-beta-secret"

# Bounds for boot wait
_HEALTH_TIMEOUT_SECONDS = 180
_HEALTH_POLL_INTERVAL = 2.0


def _docker_compose_cmd() -> list[str]:
    """
    Detect whether to use `docker compose` (plugin) or `docker-compose`
    (standalone). Raises SkipTest if neither is available.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed — skipping e2e tests")
    # Try plugin first
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True, capture_output=True, timeout=10,
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    pytest.skip("docker compose plugin not found — skipping e2e tests")


def _compose(args: list[str], *, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a docker compose subcommand against the e2e project."""
    cmd = _docker_compose_cmd() + [
        "--project-name", _PROJECT_NAME,
        "-f", str(_COMPOSE_FILE),
    ] + args
    return subprocess.run(
        cmd,
        cwd=str(_REPO_ROOT),
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _ensure_broker_certs_fixture() -> None:
    """
    Make sure tests/e2e/.fixtures/broker_certs/ contains a broker CA that
    the container's `appuser` can read AND that the directory is writable
    so the lifespan can persist .admin_secret_hash.

    Strategy:
      1. Run generate_certs.py once at the repo root (idempotent — skips if
         dev certs already exist) to make sure the source certs exist.
      2. Copy broker-ca.pem + broker-ca-key.pem into the fixture dir with
         world-readable mode (0o644) so the container user can read them.
      3. Make the fixture dir world-writable (0o777) so appuser can create
         the .admin_secret_hash file inside it.

    The fixture is idempotent: if the files already exist with the right
    perms, this is a no-op fast path.
    """
    src_key = _REPO_ROOT / "certs" / "broker-ca-key.pem"
    src_cert = _REPO_ROOT / "certs" / "broker-ca.pem"

    if not src_key.exists() or not src_cert.exists():
        generate_script = _REPO_ROOT / "generate_certs.py"
        if not generate_script.exists():
            pytest.skip(
                "Cannot prepare broker certs fixture: certs/broker-ca.pem is "
                "missing and generate_certs.py is not available"
            )
        print("[e2e] Generating broker CA via generate_certs.py...")
        subprocess.run(
            ["python", str(generate_script)],
            cwd=str(_REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if not src_key.exists() or not src_cert.exists():
            pytest.fail(
                "generate_certs.py ran but did not produce the expected files"
            )

    _BROKER_CERTS_FIXTURE.mkdir(parents=True, exist_ok=True)
    # World-writable so the container's appuser can create .admin_secret_hash.
    # This is a test fixture under tests/e2e/.fixtures (gitignored), not a
    # production secret store, so 0o777 is acceptable.
    os.chmod(_BROKER_CERTS_FIXTURE, 0o777)

    for src in (src_key, src_cert):
        dst = _BROKER_CERTS_FIXTURE / src.name
        # Always refresh — generate_certs.py is idempotent and the source
        # may have rotated. shutil.copy preserves contents, not perms.
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o644)

    # Clean any stale .admin_secret_hash from a previous run so the lifespan
    # bootstraps fresh against the current ADMIN_SECRET in the compose file.
    stale_hash = _BROKER_CERTS_FIXTURE / ".admin_secret_hash"
    if stale_hash.exists():
        stale_hash.unlink()


def _wait_for_url(url: str, label: str, timeout: int = _HEALTH_TIMEOUT_SECONDS) -> None:
    """Poll a URL until it returns 200, or fail the test after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    last_err: str = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code == 200:
                return
            last_err = f"HTTP {r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(_HEALTH_POLL_INTERVAL)
    raise TimeoutError(
        f"{label} did not become healthy within {timeout}s "
        f"(last error: {last_err}, url: {url})"
    )


@pytest.fixture(scope="session")
def e2e_stack() -> Iterator[dict]:
    """
    Boot the full Cullis stack via docker compose, wait for /healthz on
    every service, yield the relevant URLs, then tear everything down.

    Yields a dict:
        {
          "broker_url":      "http://localhost:18000",
          "proxy_alpha_url": "http://localhost:19100",
          "proxy_beta_url":  "http://localhost:19101",
          "admin_secret":    "cullis-e2e-admin-secret-do-not-reuse",
        }

    The teardown runs even if a test fails. If KEEP_E2E_STACK=1 is set
    in the environment, the stack is left running for manual inspection.
    """
    if not _COMPOSE_FILE.exists():
        pytest.fail(f"Compose file missing: {_COMPOSE_FILE}")

    # Pre-flight: make sure docker is reachable. Some CI sandboxes have
    # docker installed but cannot actually start containers.
    try:
        subprocess.run(
            ["docker", "info"], check=True, capture_output=True, timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker daemon is not reachable: {exc}")

    # Clean up any leftover stack from a previous interrupted run
    _compose(["down", "-v", "--remove-orphans"], check=False, timeout=120)

    # Prepare the broker CA fixture that gets bind-mounted into the broker
    # container as /app/certs (KMS_BACKEND=local). Without this the broker
    # /readyz check fails because get_broker_public_key_pem() cannot find
    # the CA cert on disk.
    print("[e2e] Preparing broker certs fixture...")
    _ensure_broker_certs_fixture()

    print(f"\n[e2e] Booting stack via {_COMPOSE_FILE.name}...")
    try:
        _compose(["up", "-d", "--build"], timeout=600)
    except subprocess.CalledProcessError as exc:
        print(f"[e2e] docker compose up failed:\n{exc.stderr}")
        raise

    try:
        # Health checks against the host-exposed endpoints
        _wait_for_url(f"{BROKER_URL}/healthz",       "broker")
        _wait_for_url(f"{BROKER_URL}/readyz",        "broker readyz")
        _wait_for_url(f"{PROXY_ALPHA_URL}/health",   "proxy-alpha")
        _wait_for_url(f"{PROXY_BETA_URL}/health",    "proxy-beta")
        print("[e2e] Stack is healthy. Yielding to tests.")

        yield {
            "broker_url":      BROKER_URL,
            "proxy_alpha_url": PROXY_ALPHA_URL,
            "proxy_beta_url":  PROXY_BETA_URL,
            "admin_secret":    ADMIN_SECRET,
            "proxy_alpha_admin_secret": PROXY_ALPHA_ADMIN_SECRET,
            "proxy_beta_admin_secret":  PROXY_BETA_ADMIN_SECRET,
        }
    finally:
        if os.environ.get("KEEP_E2E_STACK") == "1":
            print(
                f"\n[e2e] KEEP_E2E_STACK=1 set — leaving the stack running.\n"
                f"      Inspect:  docker compose --project-name {_PROJECT_NAME} "
                f"-f {_COMPOSE_FILE} ps\n"
                f"      Tear down: docker compose --project-name {_PROJECT_NAME} "
                f"-f {_COMPOSE_FILE} down -v"
            )
        else:
            print("\n[e2e] Tearing down stack...")
            _compose(["down", "-v", "--remove-orphans"], check=False, timeout=120)
            print("[e2e] Teardown complete.")
