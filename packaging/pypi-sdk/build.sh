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

# License + notices, required by FSL-1.1-Apache-2.0 distribution terms.
# The SDK's per-file LICENSE in cullis_sdk/LICENSE already covers
# the package itself; we additionally ship the repo-root copies so the
# wheel is self-contained for distributors who only ever see the
# installed package.
cp -f "${REPO_ROOT}/LICENSE"            "${STAGE_DIR}/LICENSE"
cp -f "${REPO_ROOT}/LICENSE-APACHE-2.0" "${STAGE_DIR}/LICENSE-APACHE-2.0"
cp -f "${REPO_ROOT}/NOTICE"             "${STAGE_DIR}/NOTICE"
cp -f "${REPO_ROOT}/CHANGELOG.md"       "${STAGE_DIR}/CHANGELOG.md"

mkdir -p "${OUT_DIR}"

echo "==> Building wheel + sdist into ${OUT_DIR}"
( cd "${STAGE_DIR}" && python -m build --outdir "${OUT_DIR}" )

echo "==> Artefacts:"
ls -lah "${OUT_DIR}"/cullis_sdk-* 2>/dev/null || true
