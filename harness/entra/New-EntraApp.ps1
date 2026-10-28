<#
.SYNOPSIS
  Creates the Entra ID objects the deployment needs, in a test or production tenant.

.DESCRIPTION
  - App registration "Agent Desktop Gateway" (single tenant, public client) that
    exposes the API scope api://<clientId>/access_as_user and issues v2.0 access tokens.
  - Enterprise application (service principal) with "Assignment required" = Yes.
  - Tenant-wide admin consent for access_as_user (no user consent prompt).
  - Security groups: <Prefix>-Users (allowed to sign in) and <Prefix>-Devices
    (Intune assignment target).
  - Writes deployment.json for the build scripts.

  Why the API scope: the daemon sends the OIDC ACCESS token to the gateway. With
  only openid/offline_access Entra issues a Microsoft Graph token that no gateway
  can validate. A token for the app's own API has aud = clientId and
  iss = https://login.microsoftonline.com/<tenant>/v2.0.

  Requires the Microsoft.Graph.Authentication module and a signed-in account that
  can consent to Application.ReadWrite.All, Group.ReadWrite.All,
  DelegatedPermissionGrant.ReadWrite.All, AppRoleAssignment.ReadWrite.All
  (Application Administrator + Groups Administrator, or Global Administrator).

.EXAMPLE
  .\New-EntraApp.ps1 -TenantId <guid> -GatewayUrl https://gateway.contoso.com -Prefix AgentDesktop-Pilot
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][string]$TenantId,
  [Parameter(Mandatory)][string]$GatewayUrl,
  [string]$Prefix = 'AgentDesktop',
  [string]$DisplayName = 'Agent Desktop Gateway',
  [string]$AgentdesktopVersion = '0.6.0',
  [string]$OutFile = (Join-Path $PSScriptRoot '..\..\config\deployment.json')
)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -TenantId $TenantId -NoWelcome -Scopes `
  'Application.ReadWrite.All', 'Group.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'

function Graph($method, $uri, $body = $null) {
  $p = @{ Method = $method; Uri = $uri; OutputType = 'PSObject' }
  if ($body) { $p.Body = ($body | ConvertTo-Json -Depth 10); $p.ContentType = 'application/json' }
  Invoke-MgGraphRequest @p
}

# --- App registration ---------------------------------------------------------
$existing = (Graph GET "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq '$DisplayName'").value
if ($existing.Count -gt 1) { throw "More than one application named '$DisplayName'; delete extras first" }
$scopeId = [guid]::NewGuid().ToString()
if ($existing) {
  $app = $existing[0]
  Write-Host "Reusing app registration $($app.appId)"
  $scopeId = ($app.api.oauth2PermissionScopes | Where-Object value -eq 'access_as_user').id ?? $scopeId
} elseif ($PSCmdlet.ShouldProcess($DisplayName, 'create app registration')) {
  $app = Graph POST 'https://graph.microsoft.com/v1.0/applications' @{
    displayName = $DisplayName; signInAudience = 'AzureADMyOrg' }
}
$null = Graph PATCH "https://graph.microsoft.com/v1.0/applications/$($app.id)" @{
  identifierUris = @("api://$($app.appId)")
  isFallbackPublicClient = $true                       # device-authorization sign-in
  publicClient = @{ redirectUris = @('http://127.0.0.1:51327/callback') }   # the daemon's default redirectUri
  api = @{
    requestedAccessTokenVersion = 2                    # v2.0 tokens: iss .../<tenant>/v2.0, aud = clientId
    oauth2PermissionScopes = @(@{
        id = $scopeId; value = 'access_as_user'; type = 'Admin'; isEnabled = $true
        adminConsentDisplayName = 'Use Claude through the Agent Desktop gateway'
        adminConsentDescription = 'Lets Agent Desktop send gateway requests on behalf of the signed-in user.'
        userConsentDisplayName = 'Use Claude through the gateway'
        userConsentDescription = 'Lets Agent Desktop send gateway requests on your behalf.' })
  }
}

# --- Enterprise application ---------------------------------------------------
$sp = (Graph GET "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($app.appId)'").value | Select-Object -First 1
if (-not $sp) { $sp = Graph POST 'https://graph.microsoft.com/v1.0/servicePrincipals' @{ appId = $app.appId } }
$null = Graph PATCH "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)" @{ appRoleAssignmentRequired = $true }

$grant = (Graph GET "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$($sp.id)' and resourceId eq '$($sp.id)'").value | Select-Object -First 1
if (-not $grant) {
  $null = Graph POST 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' @{
    clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $sp.id; scope = 'access_as_user' }
}

# --- Groups --------------------------------------------------------------------
function Ensure-Group($name, $description) {
  $g = (Graph GET "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$name'").value | Select-Object -First 1
  if ($g) { return $g }
  Graph POST 'https://graph.microsoft.com/v1.0/groups' @{
    displayName = $name; description = $description; mailEnabled = $false; mailNickname = ($name -replace '[^A-Za-z0-9]', '')
    securityEnabled = $true; groupTypes = @() }
}
$users = Ensure-Group "$Prefix-Users" 'May sign in to the Agent Desktop gateway'
$devices = Ensure-Group "$Prefix-Devices" 'Devices that receive Agent Desktop through Intune'

$assigned = (Graph GET "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo").value | Where-Object principalId -eq $users.id
if (-not $assigned) {
  $null = Graph POST "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignedTo" @{
    principalId = $users.id; resourceId = $sp.id; appRoleId = '00000000-0000-0000-0000-000000000000' }
}

# --- Output --------------------------------------------------------------------
$out = [ordered]@{
  agentdesktopVersion = $AgentdesktopVersion
  tenantId = $TenantId
  clientId = $app.appId
  gatewayUrl = $GatewayUrl.TrimEnd('/')
  issuer = "https://login.microsoftonline.com/$TenantId/v2.0"
  jwksUrl = "https://login.microsoftonline.com/$TenantId/discovery/v2.0/keys"
  usersGroupId = $users.id
  devicesGroupId = $devices.id
  servicePrincipalId = $sp.id
}
$out | ConvertTo-Json | Set-Content $OutFile
Write-Host "`nWrote $OutFile" -ForegroundColor Green
Write-Host "Add pilot users to '$Prefix-Users' and pilot devices to '$Prefix-Devices'."
Write-Host "Gateway jwtAuth: issuer=$($out.issuer) audiences=[$($app.appId)] jwks=$($out.jwksUrl)"
