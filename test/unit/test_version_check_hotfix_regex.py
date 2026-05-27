"""Regression test for the v0.6.0 sidebar banner bug.

The sidebar update advisory rendered "Update: 0.5.4.1 (running 0.6.0)"
on a fresh v0.6.0 install. Root cause: ``mcp_proxy.version_check._SEMVER_RE``
only accepted 3-component versions, so ``0.5.4.1`` fell into the
"unparseable" fallback ``(1, v)`` that sorted AFTER all parseable
tuples ``(0, ...)``. ``max(candidates, key=_version_key)`` therefore
picked the garbage tag, the banner compared it against running
``0.6.0``, and the cold-reader saw a confidence-killer.

These tests pin the corrected behaviour:
  - 4-component hotfix versions parse and sort between the 3-component
    base and the next minor.
  - Unparseable strings sort BEFORE everything parseable.
  - ``get_latest_version``-shaped selection (``max`` over real release
    list) picks the highest 3-component release when a 4-component
    hotfix is present.
"""
from mcp_proxy.version_check import _SEMVER_RE, _version_key


def test_regex_accepts_3_component_version():
    assert _SEMVER_RE.match("0.6.0")
    assert _SEMVER_RE.match("1.0.0")


def test_regex_accepts_4_component_hotfix():
    assert _SEMVER_RE.match("0.5.4.1")
    assert _SEMVER_RE.match("1.2.3.4")


def test_regex_accepts_prerelease_suffix():
    assert _SEMVER_RE.match("0.5.0-rc1")
    assert _SEMVER_RE.match("0.5.0-alpha")
    assert _SEMVER_RE.match("0.5.0-beta3")


def test_regex_accepts_hotfix_with_prerelease_suffix():
    """``0.5.4.1-rc1`` is unusual but should not break."""
    assert _SEMVER_RE.match("0.5.4.1-rc1")


def test_regex_rejects_garbage():
    assert _SEMVER_RE.match("foo") is None
    assert _SEMVER_RE.match("v0.6.0") is None  # leading v not stripped here
    assert _SEMVER_RE.match("0.6") is None  # too few components
    assert _SEMVER_RE.match("0.6.0.1.2") is None  # too many components


def test_garbage_sorts_before_parseable():
    """Regression: unparseable strings used to sort AFTER parseable
    (key ``(1, v)``) which let ``max()`` pick a garbage tag from the
    GitHub releases list and render it into the operator's sidebar.
    """
    assert _version_key("foo") < _version_key("0.0.1")
    assert _version_key("garbage") < _version_key("0.6.0")


def test_hotfix_sorts_between_base_and_next_minor():
    """The bug case: ``0.5.4.1`` should be > ``0.5.4`` but < ``0.5.5``."""
    assert _version_key("0.5.4") < _version_key("0.5.4.1")
    assert _version_key("0.5.4.1") < _version_key("0.5.5")
    assert _version_key("0.5.4.1") < _version_key("0.6.0")


def test_prerelease_sorts_before_release():
    assert _version_key("0.5.0-rc1") < _version_key("0.5.0")
    assert _version_key("0.5.0-rc1") < _version_key("0.5.0-rc2")
    assert _version_key("0.5.0-alpha") < _version_key("0.5.0-beta")
    assert _version_key("0.5.0-beta") < _version_key("0.5.0-rc1")


def test_max_picks_highest_3_component_against_hotfix_in_list():
    """The exact ``get_latest_version`` shape that the bug manifested in."""
    tags = ["0.6.0", "0.5.5", "0.5.4.1", "0.5.4", "0.5.3", "0.5.0-rc1"]
    assert max(tags, key=_version_key) == "0.6.0"


def test_max_picks_highest_hotfix_when_no_newer_3_component():
    """Inverse: if 0.6.0 didn't exist, the hotfix would correctly win."""
    tags = ["0.5.5", "0.5.4.1", "0.5.4", "0.5.3"]
    assert max(tags, key=_version_key) == "0.5.5"
    tags = ["0.5.4.1", "0.5.4", "0.5.3"]
    assert max(tags, key=_version_key) == "0.5.4.1"
