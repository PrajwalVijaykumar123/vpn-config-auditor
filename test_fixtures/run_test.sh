#!/bin/sh
# Runs the real scanner.py against four real fixture files - a
# compliant and a deliberately broken config for each of OpenVPN and
# WireGuard - and asserts specific findings by check_id.
set -e
cd "$(dirname "$0")/.."

OUT=/tmp/vpn_test_$$
mkdir -p "$OUT"

run() {
  label="$1"; shift
  python3 scanner.py "$@" --json "$OUT/$label.json" --fail-on any > "$OUT/$label.txt" 2>&1
  echo $? > "$OUT/$label.exit"
}

assert_exit() {
  label="$1"; expected="$2"
  actual=$(cat "$OUT/$label.exit")
  [ "$actual" = "$expected" ] && echo "PASS: $label exit code $actual" \
    || { echo "FAIL: $label expected exit $expected, got $actual"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

assert_fail() {
  label="$1"; check_id="$2"
  python3 -c "
import json, sys
results = json.load(open('$OUT/$label.json'))
r = next((x for x in results if x['check_id'] == '$check_id'), None)
sys.exit(0 if r and r['status'] == 'fail' else 1)
" && echo "PASS: $label -> $check_id fails as expected" \
  || { echo "FAIL: $label -> $check_id did not fail"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

assert_no_fail() {
  label="$1"
  python3 -c "
import json, sys
results = json.load(open('$OUT/$label.json'))
failed = [r['check_id'] for r in results if r['status'] == 'fail']
if failed:
    print('Unexpected failures:', failed); sys.exit(1)
" && echo "PASS: $label has zero failed checks" \
  || { echo "FAIL: $label unexpectedly failed"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

echo "== OpenVPN: compliant fixture =="
set +e; run ovpn_compliant --openvpn test_fixtures/compliant_client.ovpn; set -e
cat "$OUT/ovpn_compliant.txt"
assert_exit ovpn_compliant 0
assert_no_fail ovpn_compliant

echo
echo "== OpenVPN: noncompliant fixture =="
set +e; run ovpn_noncompliant --openvpn test_fixtures/noncompliant_client.ovpn; set -e
cat "$OUT/ovpn_noncompliant.txt"
assert_exit ovpn_noncompliant 1
for cid in OVPN-1 OVPN-2 OVPN-3 OVPN-4 OVPN-5 OVPN-6; do
  assert_fail ovpn_noncompliant "$cid"
done

echo
echo "== WireGuard: compliant fixture =="
set +e; run wg_compliant --wireguard test_fixtures/compliant_wg0.conf; set -e
cat "$OUT/wg_compliant.txt"
assert_exit wg_compliant 0
assert_no_fail wg_compliant

echo
echo "== WireGuard: noncompliant fixture =="
set +e; run wg_noncompliant --wireguard test_fixtures/noncompliant_wg0.conf; set -e
cat "$OUT/wg_noncompliant.txt"
assert_exit wg_noncompliant 1
for cid in WG-1 WG-2 WG-3; do
  assert_fail wg_noncompliant "$cid"
done

rm -rf "$OUT"
echo
echo "All tests passed."
