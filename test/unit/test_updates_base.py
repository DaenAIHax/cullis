"""Contract tests for :class:`mcp_proxy.updates.base.Migration`.

The base class enforces its metadata contract via ``__init_subclass__``
so bad migrations fail at import time, not at boot-detection time. These
tests assert the raises-loud behaviour for every required attribute plus
the enum validators.
"""
from __future__ import annotations

import pytest

from mcp_proxy.updates.base import Migration


def _valid_kwargs() -> dict:
    """Class attr bundle a concrete subclass needs to instantiate."""
    return {
        "migration_id": "2099-01-01-test",
        "migration_type": "new-feature",
        "criticality": "info",
        "description": "Test migration — unit fixture",
        "preserves_enrollments": True,
        "affects_enrollments": (),
    }


def _make(name: str = "X", **overrides) -> type[Migration]:
    """Build a concrete Migration subclass with the given class attrs."""
    attrs: dict = {**_valid_kwargs(), **overrides}

    async def _check(self) -> bool:  # noqa: D401 — fixture
        return False

    async def _up(self) -> None:
        return None

    async def _rollback(self) -> None:
        return None

    attrs.update({"check": _check, "up": _up, "rollback": _rollback})
    return type(name, (Migration,), attrs)


def test_valid_subclass_instantiates():
    cls = _make("ValidA")
    inst = cls()
    assert inst.migration_id == "2099-01-01-test"
    assert inst.migration_type == "new-feature"
    assert inst.criticality == "info"
    assert inst.description == "Test migration — unit fixture"
    assert inst.preserves_enrollments is True
    assert inst.affects_enrollments == ()


def test_missing_classattr_rejected():
    # Omitting ``description`` — a non-abstract subclass with missing
    # required class attrs must raise at class-definition time.
    async def _check(self) -> bool:
        return False

    async def _up(self) -> None:
        return None

    async def _rollback(self) -> None:
        return None

    with pytest.raises(TypeError, match="description"):
        type(
            "MissingDescription",
            (Migration,),
            {
                "migration_id": "2099-01-01-x",
                "migration_type": "new-feature",
                "criticality": "info",
                # no description
                "preserves_enrollments": True,
                "affects_enrollments": (),
                "check": _check,
                "up": _up,
                "rollback": _rollback,
            },
        )


def test_abstract_methods_not_implemented_rejected():
    # Subclass with metadata OK but forgets to override ``up`` — the
    # ABCMeta machinery rejects instantiation (not class creation).
    class Partial(Migration):
        migration_id = "2099-01-01-partial"
        migration_type = "new-feature"
        criticality = "info"
        description = "partial"
        preserves_enrollments = True
        affects_enrollments = ()

        async def check(self) -> bool:
            return False

        # up and rollback missing

    with pytest.raises(TypeError, match="abstract"):
        Partial()  # type: ignore[abstract]


def test_migration_type_invalid_rejected():
    with pytest.raises(TypeError, match="migration_type"):
        _make("BadType", migration_type="not-a-real-type")


def test_criticality_invalid_rejected():
    with pytest.raises(TypeError, match="criticality"):
        _make("BadCrit", criticality="catastrophic")


def test_affects_enrollments_unknown_rejected():
    with pytest.raises(TypeError, match="affects_enrollments"):
        _make("BadEnr", affects_enrollments=("connector", "mainframe"))


def test_affects_enrollments_not_tuple_rejected():
    with pytest.raises(TypeError, match="tuple"):
        _make("BadEnrType", affects_enrollments=["connector"])  # type: ignore[arg-type]


def test_preserves_enrollments_must_be_bool():
    with pytest.raises(TypeError, match="preserves_enrollments"):
        _make("BadPreserve", preserves_enrollments="yes")  # type: ignore[arg-type]


def test_empty_description_rejected():
    with pytest.raises(TypeError, match="description"):
        _make("EmptyDesc", description="   ")


def test_empty_migration_id_rejected():
    with pytest.raises(TypeError, match="migration_id"):
        _make("EmptyId", migration_id="")


def test_contract_enforced_on_every_subclass():
    # Contract enforcement runs on every subclass, abstract or not.
    # ABCMeta populates ``__abstractmethods__`` *after* the __init_subclass__
    # hook returns, so skipping based on that flag is unreliable. A helper
    # base that wants to defer ``check``/``up``/``rollback`` still has to
    # declare sensible defaults for the metadata attrs.
    with pytest.raises(TypeError, match="missing required class attributes"):
        class _Naked(Migration):  # noqa: F841
            pass
