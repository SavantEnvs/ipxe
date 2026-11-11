#!/usr/bin/env bash
#
# mayhem/test.sh — run iPXE's own self-test suite (built by mayhem/build.sh as tests.linux).
# Every suite prints `OK: "<name>" <N> tests passed`; the run ends with `OK: all <T> tests passed`.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/mayhem/work/tests.linux"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh must build it" >&2
  emit_ctrf "ipxe-selftest" 0 1
  exit 1
fi

OUTFILE="$(mktemp)"
trap 'rm -f "$OUTFILE"' EXIT
timeout 600 "$RUNNER" >"$OUTFILE" 2>&1
rc=$?
sed 's/\x1b\[[0-9;]*m//g' "$OUTFILE" | tr -d '\r' >"$OUTFILE.txt"
mv "$OUTFILE.txt" "$OUTFILE"

passed=0; suites=0
while read -r n; do passed=$(( passed + n )); suites=$(( suites + 1 )); done \
  < <(sed -n -E 's/^OK: "[^"]+" ([0-9]+) tests passed$/\1/p' "$OUTFILE")
total="$(sed -n -E 's/^OK: all ([0-9]+) tests passed$/\1/p' "$OUTFILE" | tail -1)"
failed="$(grep -c -E '^(FAIL|ERROR|FAILED)|not ok' "$OUTFILE" || true)"

# Behavioural assertions, not just an exit status: the suites must have run, their per-suite counts must
# add up to the reported total, and known-answer suites (crypto digests, string/URI/x509 parsing, TCP/IP
# checksums) must each report their tests as passed.
if [ "$rc" -ne 0 ]; then failed=$(( failed + 1 )); fi
if [ -z "$total" ] || [ "$total" -ne "$passed" ] || [ "$passed" -lt 1000 ]; then failed=$(( failed + 1 )); fi
for suite in sha256 sha512 string tcpip x509 uri deflate; do
  grep -q -E "^OK: \"$suite\" [1-9][0-9]* tests passed$" "$OUTFILE" || failed=$(( failed + 1 ))
done

echo "ipxe tests.linux: rc=$rc suites=$suites passed=$passed total=${total:-none} failed=$failed"
emit_ctrf "ipxe-selftest" "$passed" "$failed"
