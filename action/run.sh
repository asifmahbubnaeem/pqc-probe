#!/usr/bin/env bash
# pqc-probe GitHub Action: probe each target with the pqc-probe image, save its JSON report,
# write a job summary and, if asked, fail on a post-quantum policy.
#
# Exit status: 0 ok, 1 policy violation or probe error, 2 bad input.
set -euo pipefail
set -f  # no globbing: target lists are split on whitespace below

# Names that mark a post-quantum group or key exchange. Keep in sync with
# is_pq_group_name() in crates/pqc-probe-core/src/lib.rs.
PQ_PATTERN='mlkem|kyber|frodo|bike|hqc|sntrup'
DEFAULT_REPO='ghcr.io/asifmahbubnaeem/pqc-probe'

PROTOCOL="${INPUT_PROTOCOL:-both}"
MODE="${INPUT_MODE:-both}"
TLS_PORT="${INPUT_TLS_PORT:-}"
SSH_PORT="${INPUT_SSH_PORT:-}"
TIMEOUT="${INPUT_TIMEOUT:-15}"
REQUIRE_PQ_TLS="${INPUT_REQUIRE_PQ_TLS:-false}"
REQUIRE_PQ_SSH="${INPUT_REQUIRE_PQ_SSH:-false}"
FAIL_ON_ERROR="${INPUT_FAIL_ON_ERROR:-true}"
OUT_DIR="${INPUT_OUTPUT_DIR:-pqc-probe-reports}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
GH_OUTPUT="${GITHUB_OUTPUT:-/dev/null}"

die() { echo "::error title=pqc-probe::$*"; exit 2; }

is_bool() { [ "$1" = true ] || [ "$1" = false ]; }
is_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

# ---- validate inputs ------------------------------------------------------------------------
case "$PROTOCOL" in tls|ssh|both) ;; *) die "protocol must be tls, ssh or both (got '$PROTOCOL')" ;; esac
case "$MODE" in vanilla|experimental|both) ;; *) die "mode must be vanilla, experimental or both (got '$MODE')" ;; esac
for b in REQUIRE_PQ_TLS REQUIRE_PQ_SSH FAIL_ON_ERROR; do
  is_bool "${!b}" || die "$(echo "$b" | tr 'A-Z_' 'a-z-') must be true or false (got '${!b}')"
done
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] && [ "$TIMEOUT" -ge 1 ] && [ "$TIMEOUT" -le 120 ] || die "timeout must be 1-120 seconds"
[ -z "$TLS_PORT" ] || is_port "$TLS_PORT" || die "tls-port must be 1-65535"
[ -z "$SSH_PORT" ] || is_port "$SSH_PORT" || die "ssh-port must be 1-65535"
if [ "$REQUIRE_PQ_TLS" = true ] && [ "$PROTOCOL" = ssh ]; then die "require-pq-tls needs protocol tls or both"; fi
if [ "$REQUIRE_PQ_SSH" = true ] && [ "$PROTOCOL" = tls ]; then die "require-pq-ssh needs protocol ssh or both"; fi

targets=()
while IFS= read -r line; do
  line="${line%%#*}"
  for t in ${line//,/ }; do
    [[ "$t" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$ ]] || die "not a host or host:port: '$t'"
    targets+=("$t")
  done
done <<< "${INPUT_TARGETS:-}"
[ "${#targets[@]}" -gt 0 ] || die "targets is empty"

# ---- image ----------------------------------------------------------------------------------
image="${INPUT_IMAGE:-}"
if [ -z "$image" ]; then
  ref="${ACTION_REF:-}"
  if [[ "$ref" =~ ^v([0-9]+(\.[0-9]+){0,2}([-+][0-9A-Za-z.-]+)?)$ ]]; then
    image="$DEFAULT_REPO:${BASH_REMATCH[1]}"
  else
    image="$DEFAULT_REPO:edge"
  fi
fi
echo "pqc-probe image: $image"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker pull --quiet "$image" >/dev/null || die "could not pull $image"
fi

# ---- probe ----------------------------------------------------------------------------------
mkdir -p "$OUT_DIR"

# "yes:<names>" if a client completed a handshake with a PQ group, "no" otherwise, "n/a" if the
# report has no TLS section.
tls_pq() {
  jq -r --arg p "$PQ_PATTERN" '
    if .tls == null then "n/a" else
      ([.tls.vanilla, .tls.experimental | select(. != null) | .kems_tried[]
        | select(.handshake_succeeded and (.offered | test($p; "i"))) | .offered] | unique) as $g
      | if ($g | length) > 0 then "yes:" + ($g | join(",")) else "no" end
    end' "$1"
}

# Same for SSH: a post-quantum algorithm that a client verified with a real key exchange.
ssh_pq() {
  jq -r --arg p "$PQ_PATTERN" '
    if .ssh == null then "n/a" else
      ([.ssh.vanilla, .ssh.experimental | select(. != null) | .client_verified[]
        | select(test($p; "i"))] | unique) as $g
      | if ($g | length) > 0 then "yes:" + ($g | join(",")) else "no" end
    end' "$1"
}

cell() {
  case "$1" in
    yes:*) echo "yes (\`${1#yes:}\`)" | sed 's/,/`, `/g' ;;
    no) echo "no" ;;
    *) echo "-" ;;
  esac
}

violations=0
errors=0
rows=()
for t in "${targets[@]}"; do
  name="${t//:/_}"
  report="$OUT_DIR/$name.json"
  errlog="$OUT_DIR/$name.err"
  args=(probe "$t" --protocol "$PROTOCOL" --mode "$MODE" --timeout "$TIMEOUT" --output json)
  [ -z "$TLS_PORT" ] || args+=(--tls-port "$TLS_PORT")
  [ -z "$SSH_PORT" ] || args+=(--ssh-port "$SSH_PORT")
  echo "::group::pqc-probe $t"
  if docker run --rm --init "$image" pqc-probe "${args[@]}" > "$report.tmp" 2> "$errlog" \
      && jq -e '.schema_version' "$report.tmp" >/dev/null 2>&1; then
    mv "$report.tmp" "$report"
    [ -s "$errlog" ] || rm -f "$errlog"
  else
    rm -f "$report.tmp"
    errors=$((errors + 1))
    reason="$(tail -n 1 "$errlog" 2>/dev/null || true)"
    echo "::error title=pqc-probe::$t could not be probed: ${reason:-no output}"
    rows+=("| \`$t\` | - | - | error: ${reason:-no output} |")
    echo "::endgroup::"
    continue
  fi
  tls="$(tls_pq "$report")"
  ssh="$(ssh_pq "$report")"
  result="ok"
  if [ "$REQUIRE_PQ_TLS" = true ] && [[ "$tls" != yes:* ]]; then
    result="FAIL"; violations=$((violations + 1))
    echo "::error title=pqc-probe::$t: no TLS handshake with a post-quantum group"
  fi
  if [ "$REQUIRE_PQ_SSH" = true ] && [[ "$ssh" != yes:* ]]; then
    [ "$result" = FAIL ] || violations=$((violations + 1))
    result="FAIL"
    echo "::error title=pqc-probe::$t: no SSH key exchange with a post-quantum algorithm"
  fi
  echo "TLS post-quantum: $tls"
  echo "SSH post-quantum: $ssh"
  echo "::endgroup::"
  rows+=("| \`$t\` | $(cell "$tls") | $(cell "$ssh") | $result |")
done

# ---- summary and outputs --------------------------------------------------------------------
{
  echo "### pqc-probe"
  echo
  echo "Protocol \`$PROTOCOL\`, mode \`$MODE\`. Policy: require-pq-tls \`$REQUIRE_PQ_TLS\`, require-pq-ssh \`$REQUIRE_PQ_SSH\`."
  echo
  echo "| Target | TLS post-quantum | SSH post-quantum | Result |"
  echo "|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
  echo
  echo "Post-quantum means a handshake actually completed with that group or key exchange. JSON reports: \`$OUT_DIR\`."
} >> "$SUMMARY"
{
  echo "report-dir=$OUT_DIR"
  echo "violations=$violations"
  echo "errors=$errors"
} >> "$GH_OUTPUT"

echo "targets: ${#targets[@]}, policy violations: $violations, errors: $errors"
if [ "$violations" -gt 0 ]; then exit 1; fi
if [ "$errors" -gt 0 ] && [ "$FAIL_ON_ERROR" = true ]; then exit 1; fi
exit 0
