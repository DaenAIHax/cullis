"""Guard the PyPI ``cullis-sdk`` license metadata (2026-06-10 P0).

The SDK is Apache-2.0 (``cullis_sdk/LICENSE``, repo NOTICE); only the
Mastio is FSL-1.1-Apache-2.0. The standalone PyPI packaging declared
FSL + a Proprietary classifier, which is exactly what a procurement
license scanner reads — a wrong answer to the first due-diligence
question. These tests pin the wheel metadata to the real license.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPI_DIR = REPO_ROOT / "packaging" / "pypi-sdk"


def test_sdk_own_license_is_apache():
    text = (REPO_ROOT / "cullis_sdk" / "LICENSE").read_text()
    assert "Apache License" in text
    assert "Functional Source License" not in text


def test_pypi_metadata_declares_apache():
    import tomllib

    with (PYPI_DIR / "pyproject.toml").open("rb") as fh:
        project = tomllib.load(fh)["project"]
    assert project["license"] == {"text": "Apache-2.0"}
    classifiers = project["classifiers"]
    assert "License :: OSI Approved :: Apache Software License" in classifiers
    assert not [c for c in classifiers if "Proprietary" in c]


def test_build_stages_sdk_license_not_repo_root_fsl():
    build_sh = (PYPI_DIR / "build.sh").read_text()
    assert 'cp -f "${REPO_ROOT}/cullis_sdk/LICENSE" "${STAGE_DIR}/LICENSE"' in build_sh
    assert 'cp -f "${REPO_ROOT}/LICENSE" ' not in build_sh, (
        "build.sh must not stage the repo-root FSL LICENSE as the "
        "wheel's top-level LICENSE"
    )
