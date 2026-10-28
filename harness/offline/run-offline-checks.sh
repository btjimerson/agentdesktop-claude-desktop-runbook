#!/bin/bash
# Offline checks: no tenant, no device, no admin rights. Run on a Mac (arm64).
#
#  1. Render the macOS Intune script; bash -n and shellcheck it.
#  2. Validate the rendered daemon config with the REAL agentdesktop v0.6.0
#     binary (`daemon --dry-run`), plus negative cases the daemon must refuse.
#  3. Run the REAL agentgateway v1.6.0 with the rendered routes and prove the
#     jwtAuth policy: no token, forged, wrong audience, wrong issuer, expired
#     are refused; an Entra-shaped token is passed to the upstream.
#
# Usage: run-offline-checks.sh [work-dir]
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=${1:-$(mktemp -d)}
AGENTDESKTOP_TAG=v0.6.0
AGW_VERSION=v1.6.0
AGW_SHA256=6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685  # darwin-arm64
mkdir -p "$work"; cd "$work" || exit 1

pass=0; fail=0; skip=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; [ -n "${2:-}" ] && echo "      $2"; fail=$((fail+1)); }
skp()  { echo "SKIP  $1"; skip=$((skip+1)); }

TENANT=11111111-2222-3333-4444-555555555555
CLIENT=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
cat >deployment.json <<EOF
{"agentdesktopVersion":"${AGENTDESKTOP_TAG#v}","tenantId":"$TENANT","clientId":"$CLIENT","gatewayUrl":"https://gateway.example.com"}
EOF

# ---- 1. macOS script ---------------------------------------------------------
if "$repo/macos/render-macos-script.sh" deployment.json "$work/agentdesktop-setup.sh" >/dev/null; then
  ok "macOS script renders"
else bad "macOS script renders"; fi
bash -n agentdesktop-setup.sh && ok "bash -n agentdesktop-setup.sh" || bad "bash -n agentdesktop-setup.sh"
if command -v shellcheck >/dev/null; then
  shellcheck -S warning agentdesktop-setup.sh "$repo/macos/render-macos-script.sh" "$here/run-offline-checks.sh" >shellcheck.out 2>&1 \
    && ok "shellcheck" || bad "shellcheck" "$(head -5 shellcheck.out)"
else skp "shellcheck not installed"; fi
sed -n "/<<'AGENTDESKTOP_CONFIG'/,/^AGENTDESKTOP_CONFIG$/p" agentdesktop-setup.sh | sed '1d;$d' >config.yaml
grep -q '@@' config.yaml && bad "config has unreplaced tokens" || ok "config has no unreplaced tokens"

# ---- 2. Real daemon dry-run --------------------------------------------------
if [ "$(uname -sm)" != "Darwin arm64" ]; then
  skp "daemon dry-run (needs the darwin-arm64 binary)"
else
  if [ ! -x agentdesktop ]; then
    gh release download "$AGENTDESKTOP_TAG" --repo agentdesktop-dev/agentdesktop \
      -p agentdesktop-darwin-arm64 -p agentdesktop-darwin-arm64.sha256 -D dl --clobber >/dev/null 2>&1
    if [ -f dl/agentdesktop-darwin-arm64 ] && (cd dl && shasum -a 256 -c agentdesktop-darwin-arm64.sha256 >/dev/null 2>&1); then
      cp dl/agentdesktop-darwin-arm64 agentdesktop; chmod +x agentdesktop
    fi
  fi
  if [ ! -x agentdesktop ]; then skp "daemon dry-run (binary download or checksum failed)"; else
    out=$(./agentdesktop daemon --config config.yaml --dry-run 2>&1)
    if grep -q 'egressProxyUrl' <<<"$out" && grep -q 'http://127.0.0.1:18471' <<<"$out"; then
      ok "daemon accepts the config and plans egressProxyUrl=http://127.0.0.1:18471"
    else bad "daemon dry-run on rendered config" "$(head -5 <<<"$out")"; fi
    if grep -qE 'inference(Provider|GatewayBaseUrl)' <<<"$out"; then
      bad "daemon must not write inference settings in intercept mode"
    else ok "no inference* settings written (Claude Desktop stays on claude.ai sign-in)"; fi

    expect_refused() { # name, sed expression, expected message fragment
      sed "$2" config.yaml >neg.yaml
      msg=$(./agentdesktop daemon --config neg.yaml --dry-run 2>&1)
      if [ $? -ne 0 ] && grep -qi "$3" <<<"$msg"; then ok "daemon refuses: $1"
      else bad "daemon refuses: $1" "$(head -3 <<<"$msg")"; fi
    }
    expect_refused "plain-HTTP gateway"            's#url: https://gateway.example.com#url: http://gateway.example.com#' 'HTTPS'
    expect_refused "auth: subscription with intercept" 's#gatewayMode: intercept#gatewayMode: intercept\n    auth: subscription#' 'auth cannot be combined'
    expect_refused "non-loopback listener"         's#^daemon:#daemon:\n  intercept:\n    listen: 0.0.0.0:18471#' 'loopback'
    expect_refused "useLlmGateway: false"          's#useLlmGateway: true#useLlmGateway: false#' 'useLlmGateway'
  fi
fi

# ---- 3. Real agentgateway: jwtAuth policy ------------------------------------
if [ "$(uname -sm)" != "Darwin arm64" ]; then skp "agentgateway policy test (needs darwin-arm64)"; else
  mkdir -p agw
  if [ ! -x agw/agentgateway ]; then
    curl -fsSL --retry 3 -o agw/agentgateway \
      "https://github.com/agentgateway/agentgateway/releases/download/$AGW_VERSION/agentgateway-darwin-arm64" 2>/dev/null
    echo "$AGW_SHA256  agw/agentgateway" | shasum -a 256 -c >/dev/null 2>&1 && chmod +x agw/agentgateway || rm -f agw/agentgateway
  fi
  if [ ! -x agw/agentgateway ]; then skp "agentgateway policy test (download or checksum failed)"; else
    python3 -I "$here/mint_jwt.py" init keys
    port=14011; jwks_port=14012
    (cd keys && exec python3 -I -m http.server "$jwks_port" --bind 127.0.0.1 >/dev/null 2>&1) & jwks_pid=$!
    ISS="https://login.microsoftonline.com/$TENANT/v2.0"
    sed -e "s#@@TENANT_ID@@#$TENANT#g" -e "s#@@CLIENT_ID@@#$CLIENT#g" \
        -e "s#@@JWKS_URL@@#http://127.0.0.1:$jwks_port/jwks.json#g" \
        -e "s#@@GATEWAY_PORT@@#$port#g" -e "s#@@BIND_ADDRESS@@#127.0.0.1#g" \
        "$repo/config/agentgateway.yaml.tmpl" >agw/agentgateway.yaml
    ./agw/agentgateway -f agw/agentgateway.yaml >agw/log.txt 2>&1 & agw_pid=$!
    trap 'kill $agw_pid $jwks_pid 2>/dev/null' EXIT
    for _ in $(seq 1 30); do nc -z 127.0.0.1 $port 2>/dev/null && break; sleep 1; done
    if ! nc -z 127.0.0.1 $port 2>/dev/null; then bad "agentgateway starts with the rendered routes" "$(tail -5 agw/log.txt)"; else
      ok "agentgateway starts with the rendered routes"
      call() { # host, [header]
        if [ -n "${2:-}" ]; then
          curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "Host: $1" -H "$2" "http://127.0.0.1:$port/"
        else curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "Host: $1" "http://127.0.0.1:$port/"; fi
      }
      mint() { python3 -I "$here/mint_jwt.py" token keys "$@"; }
      for host in claude.ai api.anthropic.com; do
        [ "$(call $host)" = 401 ] && ok "$host: no token -> 401" || bad "$host: no token -> 401"
        c=$(call $host "x-agentdesktop-identity: Bearer $(mint --iss "$ISS" --aud "$CLIENT" --bad-signature)")
        [ "$c" = 401 ] && ok "$host: forged signature -> 401" || bad "$host: forged signature -> 401" "got $c"
        c=$(call $host "x-agentdesktop-identity: Bearer $(mint --iss "$ISS" --aud api://wrong)")
        [ "$c" = 401 ] && ok "$host: wrong audience -> 401" || bad "$host: wrong audience -> 401" "got $c"
        c=$(call $host "x-agentdesktop-identity: Bearer $(mint --iss https://login.microsoftonline.com/other/v2.0 --aud "$CLIENT")")
        [ "$c" = 401 ] && ok "$host: wrong issuer -> 401" || bad "$host: wrong issuer -> 401" "got $c"
        c=$(call $host "x-agentdesktop-identity: Bearer $(mint --iss "$ISS" --aud "$CLIENT" --ttl -120)")
        [ "$c" = 401 ] && ok "$host: expired token -> 401" || bad "$host: expired token -> 401" "got $c"
        c=$(call $host "x-agentdesktop-identity: $(mint --iss "$ISS" --aud "$CLIENT")")
        [ "$c" = 401 ] && ok "$host: token without 'Bearer ' prefix -> 401" || bad "$host: token without 'Bearer ' prefix -> 401" "got $c"
      done
      c=$(call claude.ai "x-agentdesktop-identity: Bearer $(mint --iss "$ISS" --aud "$CLIENT")")
      if [ "$c" = 000 ]; then skp "valid token reaches upstream (no network to claude.ai)"
      elif [ "$c" != 401 ]; then ok "claude.ai: valid Entra-shaped token passes policy (upstream answered $c)"
      else bad "claude.ai: valid Entra-shaped token passes policy" "got 401: $(tail -3 agw/log.txt)"; fi
      c=$(call unlisted.example "x-agentdesktop-identity: Bearer $(mint --iss "$ISS" --aud "$CLIENT")")
      [ "$c" != 200 ] && ok "unlisted host is not routed (got $c)" || bad "unlisted host must not be routed"
      grep -q 'Bearer ey' agw/log.txt && bad "gateway log leaks the identity token" || ok "gateway log does not contain the token"
    fi
  fi
fi

echo; echo "passed=$pass failed=$fail skipped=$skip  (work dir: $work)"
[ "$fail" -eq 0 ]
