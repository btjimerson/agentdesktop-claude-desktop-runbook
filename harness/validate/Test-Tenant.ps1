<#
.SYNOPSIS
  Read-only tenant checks: Entra app configuration and Intune deployment status.

.DESCRIPTION
  Requires Microsoft.Graph.Authentication and consent to Application.Read.All,
  Group.Read.All, DeviceManagementApps.Read.All, DeviceManagementManagedDevices.Read.All.
  Intune status uses the Graph beta endpoints (the v1.0 equivalents are limited).
  Exit code = number of failed checks.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DeploymentFile)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication
$d = Get-Content $DeploymentFile -Raw | ConvertFrom-Json
Connect-MgGraph -TenantId $d.tenantId -NoWelcome -Scopes 'Application.Read.All', 'Group.Read.All',
  'DeviceManagementApps.Read.All', 'DeviceManagementManagedDevices.Read.All'
function Graph($uri) { Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject }

$fails = 0
function Check($name, [scriptblock]$test) {
  try { $r = & $test; Write-Host ("PASS  {0}{1}" -f $name, $(if ($r -is [string]) { " - $r" })) -ForegroundColor Green }
  catch { $script:fails++; Write-Host "FAIL  $name - $($_.Exception.Message)" -ForegroundColor Red }
}

# --- Entra ---
$app = (Graph "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$($d.clientId)'").value[0]
$sp = (Graph "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($d.clientId)'").value[0]
Check 'app is single-tenant' { if ($app.signInAudience -eq 'AzureADMyOrg') { $true } else { throw $app.signInAudience } }
Check 'access tokens are v2.0' { if ($app.api.requestedAccessTokenVersion -eq 2) { $true } else { throw "requestedAccessTokenVersion=$($app.api.requestedAccessTokenVersion)" } }
Check 'identifier URI is api://<clientId>' { if ($app.identifierUris -contains "api://$($d.clientId)") { $true } else { throw ($app.identifierUris -join ',') } }
Check 'scope access_as_user exists and is enabled' {
  $s = $app.api.oauth2PermissionScopes | Where-Object value -eq 'access_as_user'
  if ($s.isEnabled) { $true } else { throw 'missing or disabled' } }
Check 'redirect URI http://127.0.0.1:51327/callback is registered as a public client URI' {
  if ($app.publicClient.redirectUris -contains 'http://127.0.0.1:51327/callback') { $true } else { throw ($app.publicClient.redirectUris -join ',') } }
Check 'public client flows are allowed (device authorization)' { if ($app.isFallbackPublicClient) { $true } else { throw 'isFallbackPublicClient is false' } }
Check 'assignment required on the enterprise app' { if ($sp.appRoleAssignmentRequired) { $true } else { throw 'users outside the group can sign in' } }
Check 'tenant-wide admin consent granted for access_as_user' {
  $g = (Graph "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)' and resourceId eq '$($sp.id)'").value
  if ($g.consentType -contains 'AllPrincipals' -and ($g.scope -match 'access_as_user')) { $true } else { throw 'no AllPrincipals grant' } }
Check 'Users group is assigned to the enterprise app' {
  $a = (Graph "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo").value | Where-Object principalId -eq $d.usersGroupId
  if ($a) { $true } else { throw 'not assigned' } }

# --- Intune ---
if (-not $d.intuneAppId) { Write-Host 'INFO  no intuneAppId in deployment.json; skipping Intune checks' -ForegroundColor Yellow }
else {
  $id = $d.intuneAppId
  Check 'Intune app is assigned to the devices group as required' {
    $a = (Graph "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$id/assignments").value
    $hit = $a | Where-Object { $_.target.groupId -eq $d.devicesGroupId -and $_.intent -eq 'required' }
    if ($hit) { $true } else { throw 'no required assignment for the devices group' } }
  $members = (Graph "https://graph.microsoft.com/v1.0/groups/$($d.devicesGroupId)/members").value
  Write-Host "INFO  devices group has $($members.Count) member(s)" -ForegroundColor Yellow
  $status = (Graph "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$id/deviceStatuses").value
  foreach ($s in $status) {
    Check "install state on $($s.deviceName)" {
      if ($s.installState -eq 'installed') { "installed at $($s.lastSyncDateTime)" } else { throw "$($s.installState) $($s.errorCode)" } }
  }
  Check 'at least one device reported install status' { if ($status.Count -gt 0) { "$($status.Count) device(s)" } else { throw 'no device has reported yet; sync the device in Intune' } }
}
Write-Host "`n$fails failure(s)"
exit $fails
