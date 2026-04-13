"""
Test that deploy_{demo,broker,proxy}.sh each use distinct COMPOSE_PROJECT_NAME
values so docker volumes don't collide on a fresh host (shake-out P0-03).

A fresh user who runs demo first and broker second on the same host must NOT
share the postgres data volume; otherwise the broker's freshly generated
POSTGRES_PASSWORD mismatches the persisted one and asyncpg crashes with an
opaque InvalidPasswordError.
"""
import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

DEPLOY_SCRIPTS = {
    "deploy_demo.sh": "cullis-demo",
    "deploy_broker.sh": "cullis-broker",
    "deploy_proxy.sh": "cullis-proxy",
}


def _read(name: str) -> str:
    return (REPO_ROOT / name).read_text()


def test_deploy_scripts_exist():
    for name in DEPLOY_SCRIPTS:
        path = REPO_ROOT / name
        assert path.exists(), f"{name} missing at repo root"


def test_each_script_sets_compose_project_name():
    """Every deploy script must export COMPOSE_PROJECT_NAME with its namespaced value."""
    pattern = re.compile(
        r'^\s*export\s+COMPOSE_PROJECT_NAME=["\']?([A-Za-z0-9_-]+)["\']?',
        re.MULTILINE,
    )
    for name, expected in DEPLOY_SCRIPTS.items():
        source = _read(name)
        match = pattern.search(source)
        assert match, f"{name} does not export COMPOSE_PROJECT_NAME"
        assert match.group(1) == expected, (
            f"{name} exports COMPOSE_PROJECT_NAME={match.group(1)!r}, "
            f"expected {expected!r}"
        )


def test_project_names_are_distinct():
    """All three scripts must use different project names — this is the actual
    bug fix for shake-out P0-03."""
    names = set(DEPLOY_SCRIPTS.values())
    assert len(names) == len(DEPLOY_SCRIPTS), (
        f"deploy scripts share a COMPOSE_PROJECT_NAME: {sorted(DEPLOY_SCRIPTS.values())}"
    )


def test_demo_down_removes_volumes():
    """Demo is ephemeral — `./deploy_demo.sh down` MUST remove volumes so a
    subsequent broker deploy can't inherit a stale postgres password."""
    source = _read("deploy_demo.sh")
    # Match the cmd_down function body. It must invoke `compose down -v`.
    assert re.search(r"compose\s+down\s+-v", source), (
        "deploy_demo.sh cmd_down must run 'compose down -v' (demo is ephemeral)"
    )


def test_broker_detects_stale_postgres_volume():
    """deploy_broker.sh must probe for a pre-existing postgres volume before
    `docker compose up` and warn the user how to recover (shake-out P0-03)."""
    source = _read("deploy_broker.sh")
    assert "docker volume inspect" in source, (
        "deploy_broker.sh must call `docker volume inspect` to detect stale volumes"
    )
    assert "InvalidPasswordError" in source, (
        "deploy_broker.sh should mention the exact error (InvalidPasswordError) "
        "so a user who hit the bug can grep the fix"
    )
