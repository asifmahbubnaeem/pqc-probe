#!/usr/bin/env bash
# Run the project's checks and save the full output to scratch/last-check.log
# (scratch/ is gitignored) so it can be read without copy-pasting.
#
#   scripts/check.sh          fmt + clippy + test + release build
#   scripts/check.sh smoke    the above, then a few live probes
#
# Exits non-zero if any step failed. The last line of the log is "## RESULT: PASS|FAIL".
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p scratch
LOG=scratch/last-check.log

# Defaults from docs/oqs-setup.md and docs/ssh-setup.md; override by exporting your own.
export PQC_PROBE_OPENSSL="${PQC_PROBE_OPENSSL:-/opt/openssl-3.5/bin/openssl}"
export PQC_PROBE_OPENSSL_OQS="${PQC_PROBE_OPENSSL_OQS:-/opt/openssl-3.5/bin/openssl-oqs}"
export PQC_PROBE_SSH_OQS="${PQC_PROBE_SSH_OQS:-/opt/oqs-openssh/bin/ssh}"

fail=0
step() {
  local name="$1"; shift
  echo "## $name"
  "$@" 2>&1
  local rc=$?
  echo "-> exit $rc"
  if [ "$rc" -ne 0 ]; then fail=1; fi
  return 0
}

{
  echo "# $(date -Is)  HEAD $(git rev-parse --short HEAD)  changed files: $(git status --short | wc -l)"
  step "cargo fmt" cargo fmt
  step "cargo clippy" cargo clippy --all-targets -- -D warnings
  step "cargo test" cargo test
  step "cargo build --release" cargo build --release
  if [ "${1:-}" = "smoke" ] && [ "$fail" -eq 0 ]; then
    step "probe github.com:443 (tls, both)" ./target/release/pqc-probe probe github.com:443 --mode both
    step "probe github.com:22 (ssh, both)" ./target/release/pqc-probe probe github.com:22 --protocol ssh --mode both
    step "probe cloudflare.com:443 (tls, both)" ./target/release/pqc-probe probe cloudflare.com:443 --mode both
  fi
  echo "## RESULT: $([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
  exit "$fail"
} 2>&1 | tee "$LOG"
exit "${PIPESTATUS[0]}"
