#!/bin/bash
# Renders macos/agentdesktop-setup.sh.tmpl and config/config.yaml.tmpl into one
# Intune shell script. Usage: render-macos-script.sh <deployment.json> [out-file]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
deployment=${1:?usage: render-macos-script.sh <deployment.json> [out-file]}
out=${2:-$here/out/agentdesktop-setup.sh}

field() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$deployment" "$1"; }
version=$(field agentdesktopVersion); tenant=$(field tenantId); client=$(field clientId); gateway=$(field gatewayUrl)

guid='^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
[[ $tenant =~ $guid && $client =~ $guid ]] || { echo "tenantId and clientId must be GUIDs" >&2; exit 1; }
[[ $gateway == https://* ]] || { echo "gatewayUrl must be https://" >&2; exit 1; }

mkdir -p "$(dirname "$out")"
python3 -I - "$here/agentdesktop-setup.sh.tmpl" "$here/../config/config.yaml.tmpl" "$out" \
  "$version" "$tenant" "$client" "${gateway%/}" <<'PY'
import sys
tmpl, cfg, out, version, tenant, client, gateway = sys.argv[1:]
config = open(cfg).read()
for k, v in {"@@GATEWAY_URL@@": gateway, "@@TENANT_ID@@": tenant, "@@CLIENT_ID@@": client}.items():
    config = config.replace(k, v)
script = open(tmpl).read().replace("@@VERSION@@", version).replace("@@CONFIG@@", config.rstrip("\n"))
assert "@@" not in script, "unreplaced token"
open(out, "w").write(script)
PY
chmod 0755 "$out"
echo "wrote $out"
