#!/usr/bin/env bash
# Tests for action/run.sh. A fake `docker` serves the reports in action/fixtures, so nothing is
# pulled or probed. Needs bash and jq. Run: action/test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat > "$work/bin/docker" <<'FAKE'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  image) [ -z "${FAKE_IMAGE_MISSING:-}" ] ;;
  pull) exit 0 ;;
  run)
    while [ $# -gt 0 ] && [ "$1" != probe ]; do shift; done
    t="$2"
    f="$FIXTURES/${t%%:*}.json"
    if [ -f "$f" ]; then cat "$f"; else echo "Error: resolving $t: no such host" >&2; exit 1; fi ;;
  *) exit 99 ;;
esac
FAKE
chmod +x "$work/bin/docker"

pass=0
fail=0
dir=""
code=0

# run_case NAME [VAR=value ...]: run the action in its own directory with these inputs.
run_case() {
  local name="$1"; shift
  dir="$work/$name"
  mkdir -p "$dir"
  (cd "$dir" && env -i PATH="$work/bin:$PATH" HOME="$HOME" FIXTURES="$here/fixtures" \
      FAKE_DOCKER_LOG="$dir/docker.log" GITHUB_STEP_SUMMARY="$dir/summary.md" \
      GITHUB_OUTPUT="$dir/output" "$@" "$here/run.sh" > "$dir/stdout" 2>&1)
  code=$?
  current="$name"
}

check() {
  local label="$1"; shift
  if "$@"; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL [$current] $label"
    sed 's/^/    | /' "$dir/stdout"
  fi
}

has() { grep -qF -- "$2" "$dir/$1" 2>/dev/null; }

# --- reporting without a policy
run_case report_only INPUT_TARGETS="pq.test classical.test"
check "exit 0" [ "$code" = 0 ]
check "pq report saved" [ -f "$dir/pqc-probe-reports/pq.test.json" ]
check "classical report saved" [ -f "$dir/pqc-probe-reports/classical.test.json" ]
check "pq row" has summary.md '| `pq.test` | yes (`X25519MLKEM768`) | yes (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`) | ok |'
check "classical row: offered but not negotiated is not PQ" has summary.md '| `classical.test` | no | no | ok |'
check "outputs" has output "violations=0"
check "outputs errors" has output "errors=0"
check "report-dir output" has output "report-dir=pqc-probe-reports"

# --- policies
run_case gate_tls INPUT_TARGETS="pq.test classical.test" INPUT_REQUIRE_PQ_TLS=true
check "exit 1" [ "$code" = 1 ]
check "one violation" has output "violations=1"
check "annotation" has stdout "::error title=pqc-probe::classical.test: no TLS handshake with a post-quantum group"
check "failing row" has summary.md '| `classical.test` | no | no | FAIL |'

run_case gate_ssh_pass INPUT_TARGETS="pq.test" INPUT_REQUIRE_PQ_SSH=true
check "exit 0" [ "$code" = 0 ]

run_case both_gates_count_once INPUT_TARGETS="classical.test" INPUT_REQUIRE_PQ_TLS=true INPUT_REQUIRE_PQ_SSH=true
check "exit 1" [ "$code" = 1 ]
check "counted once" has output "violations=1"

run_case experimental_only_pq INPUT_TARGETS="tlsonly.test" INPUT_PROTOCOL=tls INPUT_REQUIRE_PQ_TLS=true
check "a PQ handshake by the experimental client counts" [ "$code" = 0 ]
check "no SSH section shows a dash" has summary.md '| `tlsonly.test` | yes (`X25519MLKEM768`) | - | ok |'

# --- probe errors
run_case error_fails INPUT_TARGETS="pq.test down.test"
check "exit 1" [ "$code" = 1 ]
check "errors=1" has output "errors=1"
check "error row" has summary.md '| `down.test` | - | - | error: Error: resolving down.test: no such host |'
check "other target still reported" [ -f "$dir/pqc-probe-reports/pq.test.json" ]
check "no partial report" [ ! -e "$dir/pqc-probe-reports/down.test.json" ]

run_case error_tolerated INPUT_TARGETS="pq.test down.test" INPUT_FAIL_ON_ERROR=false
check "exit 0" [ "$code" = 0 ]

run_case garbage_is_an_error INPUT_TARGETS="garbage.test" INPUT_FAIL_ON_ERROR=false
check "exit 0" [ "$code" = 0 ]
check "counted as error" has output "errors=1"
check "not kept as a report" [ ! -e "$dir/pqc-probe-reports/garbage.test.json" ]

# --- target lists
run_case list_parsing INPUT_TARGETS=$'pq.test, classical.test\n# a comment\n   tlsonly.test  # trailing'
check "exit 0" [ "$code" = 0 ]
check "three reports" [ "$(ls "$dir/pqc-probe-reports" | grep -c json)" = 3 ]

run_case port_in_target INPUT_TARGETS="pq.test:8443"
check "file name keeps the port" [ -f "$dir/pqc-probe-reports/pq.test_8443.json" ]

run_case ports_passed INPUT_TARGETS="pq.test" INPUT_TLS_PORT=8443 INPUT_SSH_PORT=2222 INPUT_TIMEOUT=20
check "flags reach the CLI" has docker.log "probe pq.test --protocol both --mode both --timeout 20 --output json --tls-port 8443 --ssh-port 2222"

run_case no_glob INPUT_TARGETS="*" INPUT_FAIL_ON_ERROR=false
check "a star is rejected, not expanded" [ "$code" = 2 ]

# --- bad input is refused before anything runs
for bad in \
  "INPUT_PROTOCOL=ftp" "INPUT_MODE=fast" "INPUT_TIMEOUT=0" "INPUT_TIMEOUT=abc" \
  "INPUT_TLS_PORT=70000" "INPUT_SSH_PORT=0" "INPUT_REQUIRE_PQ_TLS=yes" "INPUT_FAIL_ON_ERROR=1" \
  "INPUT_PROTOCOL=ssh INPUT_REQUIRE_PQ_TLS=true" "INPUT_PROTOCOL=tls INPUT_REQUIRE_PQ_SSH=true"; do
  # shellcheck disable=SC2086
  run_case "bad_${bad//[^A-Za-z0-9]/_}" INPUT_TARGETS="pq.test" $bad
  check "exit 2 for $bad" [ "$code" = 2 ]
  check "nothing run for $bad" [ ! -s "$dir/docker.log" ]
done
for t in 'a.test;rm -rf /' '-oProxyCommand=x' 'user@host.test' 'http://x.test' '[::1]' ''; do
  run_case "bad_target" INPUT_TARGETS="$t"
  check "exit 2 for target '$t'" [ "$code" = 2 ]
done

# --- which image
run_case image_from_version_tag INPUT_TARGETS="pq.test" ACTION_REF=v0.2.1
check "version tag" has docker.log "image inspect ghcr.io/asifmahbubnaeem/pqc-probe:0.2.1"
run_case image_from_major_tag INPUT_TARGETS="pq.test" ACTION_REF=v1
check "major tag" has docker.log "image inspect ghcr.io/asifmahbubnaeem/pqc-probe:1"
run_case image_from_branch INPUT_TARGETS="pq.test" ACTION_REF=main
check "branch means edge" has docker.log "image inspect ghcr.io/asifmahbubnaeem/pqc-probe:edge"
run_case image_explicit INPUT_TARGETS="pq.test" ACTION_REF=v1 INPUT_IMAGE=pqc-probe:ci
check "explicit image wins" has docker.log "run --rm --init pqc-probe:ci pqc-probe probe pq.test"
run_case image_pulled_when_missing INPUT_TARGETS="pq.test" FAKE_IMAGE_MISSING=1 INPUT_IMAGE=pqc-probe:ci
check "pulled" has docker.log "pull --quiet pqc-probe:ci"

echo "action tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
