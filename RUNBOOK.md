# Runbook: Claude Desktop (first-party) through agentgateway, deployed with Intune and Entra ID

Agent Desktop **v0.6.0** · covers Windows 10/11 (x64, ARM64) and macOS (Apple silicon, Intel)

## 1. What this deploys

Claude Desktop keeps its normal claude.ai sign-in (chat history, connectors, organization settings). Agent Desktop sends its `claude.ai` and `api.anthropic.com` traffic through your agentgateway, which authenticates each request with the user's Entra ID identity.

```
Claude Desktop ──CONNECT──▶ Agent Desktop listener (127.0.0.1:18471, on the device)
 (egressProxyUrl pin)        │  decrypts only claude.ai + api.anthropic.com (local CA)
                             │  tunnels every other host untouched
                             ▼  adds  x-agentdesktop-identity: Bearer <Entra access token>
                          agentgateway ── policy (jwtAuth, logging) ──▶ claude.ai / api.anthropic.com
```

If the listener or gateway is unavailable, requests **fail**. Nothing connects to an intercepted host directly.

What Intune and Entra each do:

| Piece | Windows | macOS |
| --- | --- | --- |
| Install Agent Desktop | Win32 app (`.intunewin` wrapping the signed MSI) | macOS app (PKG) |
| Device configuration | Written by the install script; config hash in the detection rule so changes redeploy | Intune shell script (every 15 min) |
| Trust the per-device CA | Install script + SYSTEM scheduled task (`Sync-InterceptCaTrust.ps1`) | Same shell script (`security add-trusted-cert`) |
| Pin Claude Desktop to the listener | Daemon writes `HKLM\SOFTWARE\Policies\Claude` `egressProxyUrl` | Daemon writes `/Library/Managed Preferences/com.anthropic.claudefordesktop.plist` |
| User identity | Entra ID app registration, access token with scope `access_as_user` | same |
| Who may use it | Entra enterprise app with "Assignment required" + a Users group | same |

## 2. Read this first

1. **The CA is created on each device, so Intune cannot push it ahead of time.** The daemon generates a CA the first time it runs; each device has a different one. Intune "Trusted certificate" profiles need a known file, so this runbook trusts the CA with a script that runs as SYSTEM/root after the daemon creates it. The CA carries X.509 Name Constraints: it can issue only for `claude.ai` and `api.anthropic.com` (and never for an IP address). The script refuses to trust a certificate without that constraint.
2. **Claude Desktop must be restarted** after the pin and the CA trust are in place. It reads `egressProxyUrl` only at launch. Agent Desktop does not restart it. Plan a user message or a restart window.
3. **Only macOS has been tested upstream with the real Claude Desktop** (PR #194). The Windows path uses the same listener (tested on Windows in CI with a test client) and the Windows policy-registry pin (PR #193), but Claude Desktop on Windows has not been run against it upstream. Treat the Windows pilot (section 8) as the first real test, and keep the pilot ring small.
4. **Fail closed means an outage is visible.** A gateway outage stops Claude Desktop for every user on the pilot ring. Run the gateway with the availability you would give any other production dependency before widening the rollout.
5. **No-bypass is not guaranteed by the device alone.** At launch Claude Desktop opens one connection to claude.ai before the pin applies, and any local process can use the listener (it adds the identity header for them). If policy requires that claude.ai is reachable only through the gateway, add a network rule that lets only the gateway's egress addresses reach those hosts.
6. **The gateway sees claude.ai cookies and tokens.** Redact `Cookie`, `Set-Cookie` and `Authorization` in gateway logs (the supplied config does).
7. **The CA is valid for two years.** Put a reminder at 20 months. Renewal is described in section 10.

## 3. Prerequisites

**Gateway**
- agentgateway **v1.6.0 or later**, reachable at an **HTTPS** URL from every device (plain HTTP is accepted only on loopback). A certificate your devices already trust (public or enterprise CA) is required; the devices' trust store must include the CA that issued the gateway certificate.
- Outbound access from the gateway to `claude.ai:443` and `api.anthropic.com:443`.

**Entra ID**
- A role that can create app registrations, grant tenant-wide consent and manage groups (Application Administrator + Groups Administrator, or Global Administrator).
- If Conditional Access blocks the *device code flow*, the `agentdesktop login` command cannot be used; browser sign-in from the tray app is unaffected.

**Intune**
- Win32 app deployment and (macOS) shell scripts and PKG apps.
- Optional: Remediations (needs Windows Enterprise E3/E5/A3/A5). The scheduled-task design below needs no extra licence.

**Devices**
- Windows 10 21H2+ / Windows 11, Intune-enrolled, Claude Desktop already installed or deployed.
- macOS Intune-enrolled with the Intune management agent.
- Local administrator is **not** needed by users. Users must be able to run the Agent Desktop tray app to sign in.

**Packaging workstation (Windows)**
- PowerShell 7, GitHub CLI (`gh`, authenticated), [`IntuneWinAppUtil.exe`](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool), `Microsoft.Graph.Authentication` and `IntuneWin32App` PowerShell modules.

## 4. Step 1 — Gateway

1. Render `config/agentgateway.yaml.tmpl` with your values (or copy the two routes into your existing configuration):

   | Value | Meaning |
   | --- | --- |
   | tenant ID | Your Entra tenant GUID |
   | client ID | The app registration's Application (client) ID from Step 2 |
   | JWKS URL | `https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys` |

2. Keep these settings. Each one fixes a failure that was found in testing:
   - `jwtAuth.mode: strict` — the default mode lets requests without a token through.
   - `location.header.prefix: "Bearer "` — the daemon sends `Bearer <token>`; without the prefix every request gets 401.
   - `alpn: ["http/1.1"]` on the backend TLS policy — lets WebSocket upgrades work.
   - `requestHeaderModifier.remove: [x-agentdesktop-identity]` — keeps the identity token from reaching Anthropic.
   - `sensitiveHeaders` — keeps cookies and tokens out of logs.
3. Terminate TLS for the gateway URL in front of agentgateway (or in its listener) and note the URL: this is `gatewayUrl`.

## 5. Step 2 — Entra ID

Run (PowerShell 7) as an administrator who can consent:

```powershell
.\harness\entra\New-EntraApp.ps1 -TenantId <tenant-guid> -GatewayUrl https://gateway.contoso.com -Prefix AgentDesktop
```

It creates the objects below and writes `config/deployment.json`. To do it by hand in the Entra admin center:

| Setting | Value |
| --- | --- |
| App registration | Single tenant, name "Agent Desktop Gateway" |
| Authentication → Mobile and desktop applications | Redirect URI `http://127.0.0.1:51327/callback` (add through the manifest `publicClient.redirectUris` if the portal rejects an IP address); **Allow public client flows: Yes** |
| Expose an API | Application ID URI `api://<client-id>`; scope `access_as_user` (Admins and users or Admins only), enabled |
| Manifest | `api.requestedAccessTokenVersion: 2` |
| API permissions | Grant admin consent for `access_as_user` for the tenant (own API) |
| Enterprise application → Properties | **Assignment required = Yes** |
| Enterprise application → Users and groups | Assign the `AgentDesktop-Users` security group |
| Groups | `AgentDesktop-Users` (people who may sign in), `AgentDesktop-Devices` (Intune assignment target) |

**Why the API scope matters.** The daemon sends the OIDC *access* token to the gateway. Without `api://<client-id>/access_as_user` in the scopes, Entra issues a Microsoft Graph token that no gateway can validate. With it, tokens have `ver: 2.0`, `iss: https://login.microsoftonline.com/<tenant>/v2.0` and `aud: <client-id>`, which is what the gateway policy checks.

Recommended: add a Conditional Access policy for the enterprise application requiring MFA and a compliant device. Start in report-only mode.

Verify before touching Intune:

```powershell
.\harness\validate\Test-Tenant.ps1 -DeploymentFile .\config\deployment.json
.\harness\validate\Test-EntraSignIn.ps1 -DeploymentFile .\config\deployment.json            # a user in the Users group
.\harness\validate\Test-EntraSignIn.ps1 -DeploymentFile .\config\deployment.json -ExpectDenied   # a user outside it
```

## 6. Step 3 — Package and publish

### Windows

```powershell
cd windows
.\Build-IntuneWinPackage.ps1 -DeploymentFile ..\config\deployment.json -IntuneWinAppUtil C:\tools\IntuneWinAppUtil.exe -OutputDir .\out
cd ..\harness\intune
.\Publish-ToIntune.ps1 -DeploymentFile ..\..\config\deployment.json -BuildDir ..\..\windows\out
```

The build script downloads `agentdesktop-windows-amd64.msi` for the version in `deployment.json`, checks it against the release's `.sha256` asset, renders the configuration, and stamps the detection script. Repeat with `-Architecture arm64` for ARM64 devices.

To upload by hand instead, create **Apps → Windows → Add → Windows app (Win32)** with:

| Field | Value |
| --- | --- |
| App package file | `windows\out\agentdesktop-amd64.intunewin` |
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AgentDesktop.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-AgentDesktop.ps1` |
| Install behavior | **System** |
| Device restart behavior | No specific action |
| Return codes | defaults (0, 1707 success; 3010 soft reboot; 1641 hard reboot; 1618 retry) |
| Requirements | OS architecture x64 (or ARM64), minimum Windows 10 21H2 |
| Detection rules | Custom script: `windows\out\Detect-AgentDesktop-amd64.ps1`; run as 64-bit **Yes**; signature check **No** |
| Assignment | **Required** → group `AgentDesktop-Devices` |

What the install script does, in order: verifies the MSI hash → installs/upgrades silently → writes `%ProgramData%\AgentDesktop\config.yaml` → restarts the `AgentDesktop` service → waits for `state\intercept-ca.pem` → trusts it in `LocalMachine\Root` → registers the `AgentDesktop-InterceptCA-Trust` SYSTEM task (at startup and hourly, so reinstalls and rotations stay trusted) → writes the completion marker `HKLM\SOFTWARE\AgentDesktop\IntuneDeployment`. Logs: `%ProgramData%\AgentDesktop\logs\`.

A configuration change is deployed by editing `deployment.json` (or the template), rebuilding and uploading the new `.intunewin` to the **same** app (Update package). The detection rule compares the config hash, so devices reinstall.

Optional Intune Remediation: use `Sync-InterceptCaTrust.ps1 -Mode Detect` as the detection script and `-Mode Remediate` as the remediation, run as SYSTEM, 64-bit.

### macOS

```bash
macos/render-macos-script.sh config/deployment.json macos/out/agentdesktop-setup.sh
```

1. **Apps → macOS → Add → macOS app (PKG)**: upload `agentdesktop-macos-arm64.pkg` (and the `amd64` one for Intel Macs; assign by architecture). Verify the checksum against the release's `.sha256` file first. Assign **Required** to the devices group.
2. **Devices → macOS → Scripts → Add**: upload `agentdesktop-setup.sh`. Run as **root** (not signed-in user), hide notifications, **repeat every 15 minutes**, max 3 retries. Assign to the same group.

The script exits non-zero until the PKG has installed the expected version, so Intune retries it. It then writes `/etc/agentdesktop/config.yaml` (root:wheel 0600), restarts the daemon only when the file changed, trusts the CA in the System keychain, removes superseded intercept CAs, and adds the console user to the `agentdesktop` group.

Do not also deploy a Claude Desktop managed-preferences profile (`com.anthropic.claudefordesktop`) from Intune for the same keys; the daemon manages that file in intercept mode.

## 7. Step 4 — User sign-in

On each device a user must sign in to the gateway once, as themselves:

- Open the **Agent Desktop** tray application (on Windows it starts at logon) and follow its sign-in checklist; this opens a browser to the Entra sign-in. The user must be a member of `AgentDesktop-Users`.
- Or, on a machine without a usable browser: `agentdesktop login` prints a verification URL and code (needs the device code flow to be allowed by Conditional Access).

Then **quit and reopen Claude Desktop**. Claude Desktop remains signed in to claude.ai as before.

## 8. Step 5 — Pilot validation

Use a pilot ring of 3–5 devices (Windows and macOS separately). Complete every row before widening.

| # | Check | How | Pass |
| --- | --- | --- | --- |
| 1 | Package installed | `Test-Tenant.ps1` (Intune section) or Intune portal → app → Device install status | `installed` on every pilot device |
| 2 | Device state, signed out | Windows (elevated): `harness\validate\Test-Endpoint.ps1`; macOS: `sudo harness/validate/test-endpoint.sh` | 0 failures; requests through the listener answer **502** (fail closed) |
| 3 | Sign in as an allowed user | Section 7 | tray shows signed in |
| 4 | Device state, signed in | Re-run with `-ExpectSignedIn` / `--expect-signed-in` | 0 failures; `forwarded` > 0 |
| 5 | Claude Desktop works | Restart Claude Desktop; open a chat, the Code tab, a connector | Works; chat history still present; no certificate warnings |
| 6 | Gateway evidence | Gateway access log | Requests for `claude.ai` and `api.anthropic.com` with the user's Entra identity; no cookie or token values in the log |
| 7 | Unassigned user refused | `Test-EntraSignIn.ps1 -ExpectDenied` | AADSTS50105 |
| 8 | Fail closed | Stop the gateway (or block it) | Claude Desktop requests fail; `daemon-info` shows the cause; recovers without restarting Claude Desktop when the gateway returns |
| 9 | Rollback | Section 10 "Stop using the gateway" | Pin removed; Claude Desktop works directly after restart |
| 10 | Reboot and sleep | Reboot, then sleep/wake on a different network | Listener bound, CA still trusted, requests recover |

`Test-Endpoint` writes an evidence JSON file (Windows: `%ProgramData%\AgentDesktop\logs\validation-*.json`). Keep these with the pilot sign-off.

Rollout: pilot ring → 10% → 50% → all, one week each, watching Intune install status, the gateway error rate and help-desk tickets.

## 9. Monitoring

- **On the device**: `daemon-info` (Windows named pipe `\\.\pipe\agentdesktop`; macOS socket `/var/run/agentdesktop/agentdesktop.sock`, readable by members of the `agentdesktop` group). The `intercept` section shows `bound`, `error`, `caCertificate`, `caSha256`, `forwarded`, `gatewayFailures`, `tunnels`, `tunnelFailures` and `lastFailure`. `Test-Endpoint` reads it for you.
- **In Intune**: app install status; script run status (macOS); optional Remediation results.
- **At the gateway**: access logs per route; alert on a rise in 401 (token or policy problem) and 5xx (upstream).
- Known upstream behaviour: about 2 in 450 requests saw a TLS `bad_record_mac` alert between agentgateway and `api.anthropic.com` in the upstream manual test; Claude Desktop retried both. Cause unknown.

## 10. Operations

| Task | Procedure |
| --- | --- |
| **Upgrade Agent Desktop** | Set `agentdesktopVersion` in `deployment.json`, rebuild, upload to the same Intune app (Windows); upload the new PKG and rerender the script (macOS). The installers stop and restart the service themselves. Keep a pilot ring first. |
| **Change gateway URL / Entra values** | Edit `deployment.json`, rebuild or rerender, redeploy. The daemon restarts its listener on any `llmGateway` change. |
| **Stop using the gateway (kill switch)** | Redeploy a config without `gatewayMode: intercept` (or remove the app/script). The daemon removes the pin; it does **not** remove the CA trust. Users must restart Claude Desktop. To remove trust too, run the uninstall command (Windows) or `security delete-certificate` for the `agentdesktop intercept CA` certificates (macOS). |
| **Renew the CA (before 24 months)** | Delete `intercept-ca.pem`, `intercept-ca-hosts.json` from the state directory (`%ProgramData%\AgentDesktop\state`, `/var/lib/agentdesktop`) and restart the service. The daemon creates a new CA; the trust script adds it and removes the old one. Restart Claude Desktop. |
| **Uninstall** | Windows: assign the app's uninstall (or run `Uninstall-AgentDesktop.ps1`). macOS: see `frontend/desktop/MACOS_INSTALLER.md` in the repository ("Remove") and delete the CA. Device identity and configuration are kept by design. |
| **New macOS user accounts** | Added to the `agentdesktop` group by the setup script (console user) and the PKG; others: `sudo dseditgroup -o edit -a USER -t user agentdesktop`. |

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Claude Desktop shows network/certificate errors, `ERR_CERT_AUTHORITY_INVALID` | CA not trusted, or Claude Desktop started before trust was added | `Sync-InterceptCaTrust.ps1 -Mode Detect` (Windows) / `security verify-cert -c /var/lib/agentdesktop/intercept-ca.pem` (macOS); trust it; restart Claude Desktop |
| Every request returns **502** | Not signed in, gateway unreachable, or token refresh failed | `daemon-info.intercept.lastFailure`; sign in via the tray app; check gateway reachability and its TLS certificate on the device |
| Every request returns **401** from the gateway | Wrong `aud`/`iss`, missing `Bearer ` prefix, or a Graph token instead of the API token | Run `Test-EntraSignIn.ps1`; confirm the scopes in `config.yaml` include `api://<client-id>/access_as_user` and `requestedAccessTokenVersion` is 2 |
| `AADSTS50105` at sign-in | User not in `AgentDesktop-Users` | Add the user to the group |
| `AADSTS65001` (consent required) | Admin consent not granted | Grant consent for `access_as_user` (section 5) |
| `AADSTS50011` redirect URI mismatch | Redirect URI not registered as a public-client URI | Register `http://127.0.0.1:51327/callback` |
| `intercept.bound` is false, error mentions bind | Port 18471 in use | Free the port, or set `daemon.intercept.listen` to another fixed loopback port in the config (the pin follows it) |
| Claude Desktop ignores the proxy | It was running before the pin | Quit and reopen it; Windows: confirm `HKLM\SOFTWARE\Policies\Claude\egressProxyUrl`; macOS: confirm the managed-preferences plist |
| Windows install fails at "daemon did not create intercept-ca.pem" | Config invalid or service not started | `%ProgramData%\AgentDesktop\logs`, `Get-Service AgentDesktop`, `agentdesktop.exe daemon --config <file> --dry-run` shows validation errors |
| Config rejected | e.g. HTTP gateway URL, `auth: subscription` set with intercept, non-loopback listener | The daemon refuses these on purpose; fix the setting |
| Intune shows the Win32 app "not detected" after install | Marker missing: install script failed before its last step | Read `intune-install.log`; the marker is written last |
| macOS shell script keeps failing with "installed version" | PKG still installing/updating | Wait for the next run |

## 12. Validation status of this package

Be explicit with the pilot team about what has and has not been exercised:

| Item | Status |
| --- | --- |
| Rendered configuration accepted by the real agentdesktop v0.6.0 daemon; refusals (HTTP gateway, `auth`, non-loopback listener, `useLlmGateway: false`) | **Executed** (macOS arm64 binary, `daemon --dry-run`) |
| Gateway routes and `jwtAuth` policy on the real agentgateway v1.6.0 (no token, forged, wrong audience/issuer, expired, missing prefix → 401; valid Entra-shaped token passes; unlisted host not routed) | **Executed** with locally minted tokens |
| macOS setup script | Syntax- and shellcheck-clean; **not run on a managed Mac** |
| Windows scripts, Entra provisioning, Intune publishing, tenant and device tests | **Written, not executed** (no Windows host or tenant was available while preparing this package). Run the pilot in section 8 and fix forward |
| Real Claude Desktop through the listener | macOS: upstream manual run (PR #194). Windows: **untested upstream**; first real test is your pilot |

## Appendix A — File inventory

| Path | Purpose |
| --- | --- |
| `config/config.yaml.tmpl` | Device configuration template |
| `config/agentgateway.yaml.tmpl` | Gateway routes and policy |
| `config/deployment.example.json` | Inputs: version, tenant, client, gateway URL |
| `windows/` | Build, install, detect, uninstall, CA trust scripts |
| `macos/` | Setup script template and renderer |
| `harness/offline/` | Checks that need no tenant or device |
| `harness/entra/New-EntraApp.ps1` | Entra app, groups, consent |
| `harness/intune/Publish-ToIntune.ps1` | Publish the Win32 app |
| `harness/validate/` | Device, tenant and sign-in tests |

## Appendix B — References

- Feature: <https://github.com/agentdesktop-dev/agentdesktop/pull/194> · Release: <https://github.com/agentdesktop-dev/agentdesktop/releases/tag/v0.6.0>
- Windows policy-registry pin: PR #193 · Installer behaviour: `frontend/desktop/WINDOWS_INSTALLER.md`, `MACOS_INSTALLER.md` in the repository
- Daemon configuration reference: `schema/daemon-config.md`
