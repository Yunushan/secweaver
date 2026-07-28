#!/bin/sh
set -eu

SECWEAVER_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SECWEAVER_ROOT=$(CDPATH= cd -- "${SECWEAVER_SCRIPT_DIR}/.." && pwd)
cd "${SECWEAVER_ROOT}"

exec "${SECWEAVER_ROOT}/bin/secweaver" \
  --config secweaver.toml \
  scan \
  --report-dir "${SECWEAVER_REPORT_DIR:-secweaver-reports}" \
  "$@"
