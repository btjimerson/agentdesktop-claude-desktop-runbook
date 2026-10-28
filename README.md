# Claude Desktop first-party mode with Intune and Entra ID

Deliverables for agentdesktop **v0.6.0** (feature: [PR #194](https://github.com/agentdesktop-dev/agentdesktop/pull/194)).

- **[RUNBOOK.md](RUNBOOK.md)** — the deployment document: architecture, prerequisites, Entra, gateway, Intune (Windows and macOS), pilot checklist, operations, troubleshooting.
- **Test harness** (`harness/`) — validates the runbook; each layer can be run on its own.

## Harness layers

| Layer | What it proves | Needs | Script |
| --- | --- | --- | --- |
| 1. Offline | Rendered config is accepted by the real v0.6.0 daemon and the bad variants are refused; the gateway policy (real agentgateway v1.6.0) rejects no/forged/wrong-audience/wrong-issuer/expired tokens and passes an Entra-shaped token; macOS script passes shellcheck | A Mac (arm64), `gh`, `curl`, `openssl`, `python3` | `harness/offline/run-offline-checks.sh` |
| 2. Entra | App registration, API scope, v2 tokens, assignment-required, admin consent, groups; token claims for an allowed user; denial (AADSTS50105) for an unassigned user | A test tenant, PowerShell 7, `Microsoft.Graph.Authentication` | `harness/entra/New-EntraApp.ps1`, `harness/validate/Test-Tenant.ps1`, `harness/validate/Test-EntraSignIn.ps1` |
| 3. Intune | Package builds, publishes and installs on an enrolled device; install status per device | Intune, `IntuneWin32App` module, one enrolled Windows VM (and a Mac for macOS) | `windows/Build-IntuneWinPackage.ps1`, `harness/intune/Publish-ToIntune.ps1`, `harness/validate/Test-Tenant.ps1` |
| 4. Device | Service, config, policy pin, CA trust, TLS through the listener (intercept vs tunnel), fail-closed, signed-in forwarding | The enrolled device, elevated | `harness/validate/Test-Endpoint.ps1` (Windows), `harness/validate/test-endpoint.sh` (macOS) |

## Suggested order against a test tenant

```powershell
# 1. Entra objects + deployment.json
.\harness\entra\New-EntraApp.ps1 -TenantId <guid> -GatewayUrl https://<test-gateway> -Prefix AgentDesktopTest
.\harness\validate\Test-Tenant.ps1 -DeploymentFile .\config\deployment.json
.\harness\validate\Test-EntraSignIn.ps1 -DeploymentFile .\config\deployment.json              # allowed user
.\harness\validate\Test-EntraSignIn.ps1 -DeploymentFile .\config\deployment.json -ExpectDenied # unassigned user

# 2. Build, publish, assign to the test device group
.\windows\Build-IntuneWinPackage.ps1 -DeploymentFile .\config\deployment.json -IntuneWinAppUtil C:\tools\IntuneWinAppUtil.exe -OutputDir .\windows\out
.\harness\intune\Publish-ToIntune.ps1 -DeploymentFile .\config\deployment.json -BuildDir .\windows\out

# 3. Add the test VM to the devices group, sync it in Intune, then:
.\harness\validate\Test-Tenant.ps1 -DeploymentFile .\config\deployment.json     # install status
# On the VM, elevated:
.\harness\validate\Test-Endpoint.ps1                       # signed out: expect 502 fail-closed
# sign in via the tray app, restart Claude Desktop, then:
.\harness\validate\Test-Endpoint.ps1 -ExpectSignedIn
```

Layer 1 needs no tenant:

```bash
harness/offline/run-offline-checks.sh
```

## Status

| Executed here | Not executed here |
| --- | --- |
| Layer 1 in full (config dry-run with the real v0.6.0 binary, real agentgateway v1.6.0 policy tests, shellcheck) | All PowerShell (Windows scripts, Entra, Intune, device tests): no Windows host, no Intune/Entra tenant was available |
| | macOS setup script on a managed Mac |
| | Real Claude Desktop on Windows through the listener (also untested upstream) |

The PowerShell was written to the documented cmdlets and APIs but has not been parsed or run; expect to fix small issues on first run. `harness/intune/Publish-ToIntune.ps1` uses the community `IntuneWin32App` module; RUNBOOK section 6 lists the same settings for a manual portal upload.
