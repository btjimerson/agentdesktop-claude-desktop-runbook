#!/bin/bash
# Validates a macOS device after the Intune deployment. Run with sudo on the
# pilot Mac. Exit code = number of failed checks.
#   sudo ./test-endpoint.sh [--expect-signed-in] [--version 0.6.0]
set -u
EXPECTED_VERSION=0.6.0; SIGNED_IN=0
while [ $# -gt 0 ]; do
  case $1 in
    --expect-signed-in) SIGNED_IN=1 ;;
    --version) EXPECTED_VERSION=$2; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac; shift
done
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }

APP=/Applications/agentdesktop.app/Contents/MacOS/agentdesktop
SOCK=/var/run/agentdesktop/agentdesktop.sock
CA=/var/lib/agentdesktop/intercept-ca.pem
PLIST='/Library/Managed Preferences/com.anthropic.claudefordesktop.plist'
PROXY=127.0.0.1:18471
fails=0
pass() { echo "PASS  $1${2:+ - $2}"; }
fail() { echo "FAIL  $1${2:+ - $2}"; fails=$((fails+1)); }
info() { echo "INFO  $1${2:+ - $2}"; }

# --- Install ---
v=$("$APP" --version 2>/dev/null)
[[ $v == *"$EXPECTED_VERSION"* ]] && pass "agentdesktop is $EXPECTED_VERSION" "$v" || fail "agentdesktop is $EXPECTED_VERSION" "got '$v'"
launchctl print system/dev.agentdesktop.daemon 2>/dev/null | grep -q 'state = running' \
  && pass "LaunchDaemon dev.agentdesktop.daemon is running" || fail "LaunchDaemon dev.agentdesktop.daemon is running"
perms=$(stat -f '%Su:%Sg %Lp' /etc/agentdesktop/config.yaml 2>/dev/null)
[ "$perms" = "root:wheel 600" ] && pass "config.yaml is root:wheel 0600" || fail "config.yaml is root:wheel 0600" "got '$perms'"
grep -q 'gatewayMode: intercept' /etc/agentdesktop/config.yaml && grep -qE 'login\.microsoftonline\.com/[0-9a-f-]{36}/v2\.0' /etc/agentdesktop/config.yaml \
  && grep -q access_as_user /etc/agentdesktop/config.yaml \
  && pass "config.yaml selects intercept mode with Entra" || fail "config.yaml selects intercept mode with Entra"

# --- Daemon ---
info_json=$(curl -sS --max-time 5 --unix-socket "$SOCK" http://localhost/v1/daemon-info 2>&1)
jqf() { python3 -I -c 'import json,sys
d=json.load(sys.stdin).get("intercept") or {}
v=d.get(sys.argv[1]); print("" if v is None else v)' "$1" <<<"$info_json" 2>/dev/null; }
[ "$(jqf bound)" = True ] && [ "$(jqf listen)" = "$PROXY" ] \
  && pass "intercept listener is bound on $PROXY" || fail "intercept listener is bound on $PROXY" "bound=$(jqf bound) error=$(jqf error)"

# --- Claude Desktop pin ---
pin=$(/usr/libexec/PlistBuddy -c 'Print :egressProxyUrl' "$PLIST" 2>/dev/null)
[ "$pin" = "http://$PROXY" ] && pass "managed preferences pin egressProxyUrl" "$pin" || fail "managed preferences pin egressProxyUrl" "got '$pin'"
/usr/libexec/PlistBuddy -c 'Print' "$PLIST" 2>/dev/null | grep -q 'inference' \
  && fail "no inference* keys in managed preferences" || pass "no inference* keys (Claude Desktop stays on claude.ai sign-in)"

# --- CA trust ---
if security verify-cert -c "$CA" >/dev/null 2>&1; then pass "intercept CA is trusted in the System keychain"; else fail "intercept CA is trusted in the System keychain"; fi
file_sha=$(openssl x509 -in "$CA" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')
daemon_sha=$(jqf caSha256 | tr -d ':' | tr 'A-F' 'a-f')
[ -n "$file_sha" ] && [ "$file_sha" = "$daemon_sha" ] && pass "CA SHA-256 matches daemon-info" "${file_sha:0:16}" || fail "CA SHA-256 matches daemon-info" "file=$file_sha daemon=$daemon_sha"
n=$(security find-certificate -a -c 'agentdesktop intercept CA' /Library/Keychains/System.keychain 2>/dev/null | grep -c '^keychain:')
[ "$n" = 1 ] && pass "only one intercept CA in the System keychain" || fail "only one intercept CA in the System keychain" "$n found"

# --- TLS through the listener (curl uses the System trust store via SecureTransport/LibreSSL) ---
for host in claude.ai api.anthropic.com; do
  out=$(curl -sS -o /dev/null --max-time 20 --proxy "http://$PROXY" --cacert "$CA" -w '%{http_code}' "https://$host/" 2>&1)
  case $out in
    000*|*"certificate"*) fail "$host via the listener (chain valid against the intercept CA)" "$out" ;;
    *) pass "$host via the listener (chain valid against the intercept CA)" "HTTP $out" ;;
  esac
done
issuer=$(echo | openssl s_client -proxy "$PROXY" -connect login.microsoftonline.com:443 -servername login.microsoftonline.com 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
[[ -n $issuer && $issuer != *agentdesktop* ]] && pass "other hosts are tunnelled, not intercepted" "$issuer" || fail "other hosts are tunnelled, not intercepted" "$issuer"

# --- Gateway ---
code=$(curl -sS -o /dev/null --max-time 20 --proxy "http://$PROXY" --cacert "$CA" -w '%{http_code}' https://claude.ai/ 2>&1)
if [ "$SIGNED_IN" = 1 ]; then
  case $code in 502|401) fail "request through the listener reaches the gateway" "HTTP $code; $(jqf lastFailure)" ;; *) pass "request through the listener reaches the gateway" "HTTP $code" ;; esac
  [ "$(jqf forwarded)" -gt 0 ] 2>/dev/null && pass "daemon counts forwarded requests" "$(jqf forwarded)" || fail "daemon counts forwarded requests" "$(jqf lastFailure)"
else
  [ "$code" = 502 ] && pass "signed out: fails closed with 502 (nothing connects directly)" || fail "signed out: fails closed with 502" "HTTP $code"
fi

# --- Claude Desktop (best effort) ---
log=$(ls -t /Users/*/Library/Logs/Claude/main.log 2>/dev/null | head -1)
if [ -n "$log" ]; then
  grep -qF "pinned to fixed proxy at $PROXY" "$log" && pass "Claude Desktop main.log shows the pinned proxy" || info "Claude Desktop main.log does not show the pin yet" "restart Claude Desktop"
  t=$(grep -cE 'ERR_CERT|ERR_SSL' "$log"); [ "$t" = 0 ] && pass "Claude Desktop main.log has no ERR_CERT/ERR_SSL" || fail "Claude Desktop main.log has no ERR_CERT/ERR_SSL" "$t lines"
else info "Claude Desktop main.log not found" "start Claude Desktop once and re-run"; fi

echo; echo "$fails failure(s)"; exit "$fails"
