#!/usr/bin/env bash
# Build the standalone `cullis-sdk` wheel + sdist.
#
# Hatchling's sdist builder refuses include paths that escape the
# pyproject directory (for good reasons — tar archives with `..` are
# a minor footgun). So instead of playing tricks with `force-include`
# and symlinks we stage the sources into `packaging/pypi-sdk/` first,
# then invoke `python -m build` against the staged tree.
#
# Idempotent: safe to re-run. The staged copies are gitignored by the
# repo-root `.gitignore` so they never leak into commits.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
STAGE_DIR="${SCRIPT_DIR}"
OUT_DIR="${REPO_ROOT}/dist"

echo "==> Staging sources into ${STAGE_DIR}"

# Fresh copy of the SDK package every time — avoids stale files.
rm -rf "${STAGE_DIR}/cullis_sdk"
cp -a "${REPO_ROOT}/cullis_sdk" "${STAGE_DIR}/cullis_sdk"

# Drop any __pycache__ directories the dev environment may have left
# in the source tree before they leak into the sdist.
find "${STAGE_DIR}/cullis_sdk" -type d -name __pycache__ -exec rm -rf {} +

# Package readme for PyPI (lives next to pyproject.toml).
cp -f "${REPO_ROOT}/cullis_sdk/README.md" "${STAGE_DIR}/README_PKG.md"

# License + notices. The wheel contains ONLY cullis_sdk/, which is
# Apache-2.0 (see NOTICE) — so the wheel's top-level LICENSE must be
# the SDK's own Apache text, NOT the repo-root FSL one. Shipping the
# FSL text as LICENSE here made license scanners (and procurement)
# read the package as FSL-licensed (2026-06-10 review, P0). NOTICE is
# kept for the multi-license context of the source repo.
cp -f "${REPO_ROOT}/cullis_sdk/LICENSE" "${STAGE_DIR}/LICENSE"
cp -f "${REPO_ROOT}/NOTICE"             "${STAGE_DIR}/NOTICE"
# Stale staged copy from builds prior to the license fix.
rm -f "${STAGE_DIR}/LICENSE-APACHE-2.0"

# CHANGELOG.md is authored in-place at ${STAGE_DIR}/CHANGELOG.md (SDK-
# specific PyPI release history, distinct from the monorepo CHANGELOG
# which covers Mastio / Connector / Court too). No copy step needed.

mkdir -p "${OUT_DIR}"

echo "==> Building wheel + sdist into ${OUT_DIR}"
( cd "${STAGE_DIR}" && python -m build --outdir "${OUT_DIR}" )

echo "==> Artefacts:"
ls -lah "${OUT_DIR}"/cullis_sdk-* 2>/dev/null || true
