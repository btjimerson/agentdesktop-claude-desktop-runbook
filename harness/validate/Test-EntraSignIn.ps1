<#
.SYNOPSIS
  Proves the Entra side end to end for one user: signs in with the OAuth device
  code flow (the same public client and scope the daemon uses) and checks the
  access token the gateway will receive.

.DESCRIPTION
  PASS conditions for an allowed user:
    ver = 2.0, iss = https://login.microsoftonline.com/<tenant>/v2.0,
    aud = <clientId>, scp contains access_as_user, token not expired.
  With -ExpectDenied (a user NOT in the Users group), PASS means Entra refuses the
  sign-in with AADSTS50105 (assignment required).
  The token is never written to disk or printed.

.EXAMPLE
  .\Test-EntraSignIn.ps1 -DeploymentFile ..\..\config\deployment.json
  .\Test-EntraSignIn.ps1 -DeploymentFile ..\..\config\deployment.json -ExpectDenied
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$DeploymentFile,
  [switch]$ExpectDenied
)
$ErrorActionPreference = 'Stop'
$d = Get-Content $DeploymentFile -Raw | ConvertFrom-Json
$base = "https://login.microsoftonline.com/$($d.tenantId)/oauth2/v2.0"
$scope = "openid offline_access api://$($d.clientId)/access_as_user"

$dc = Invoke-RestMethod -Method Post -Uri "$base/devicecode" -Body @{ client_id = $d.clientId; scope = $scope }
Write-Host $dc.message -ForegroundColor Cyan

$token = $null; $failure = $null
$deadline = (Get-Date).AddSeconds($dc.expires_in)
while ((Get-Date) -lt $deadline -and -not $token -and -not $failure) {
  Start-Sleep -Seconds ([int]$dc.interval)
  try {
    $token = Invoke-RestMethod -Method Post -Uri "$base/token" -Body @{
      grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $d.clientId; device_code = $dc.device_code }
  } catch {
    $body = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
    if ($body.error -ne 'authorization_pending') { $failure = $body }
  }
}

$results = @()
function Result($ok, $name, $detail = '') {
  $script:results += [pscustomobject]@{ ok = $ok; name = $name }
  Write-Host ('{0}  {1}{2}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $(if ($detail) { " - $detail" })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
}

if ($ExpectDenied) {
  Result ($failure.error_description -match 'AADSTS50105') 'unassigned user is refused (AADSTS50105)' "$($failure.error): $(($failure.error_description -split "`r?`n")[0])"
  Result (-not $token) 'no token was issued'
} else {
  if (-not $token) { Result $false 'sign-in completed' "$($failure.error): $($failure.error_description)" }
  else {
    function Decode($jwt) {
      $p = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/'); $p += '=' * ((4 - $p.Length % 4) % 4)
      [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json }
    $c = Decode $token.access_token
    Result ($c.ver -eq '2.0') 'access token is v2.0' "ver=$($c.ver)"
    Result ($c.iss -eq "https://login.microsoftonline.com/$($d.tenantId)/v2.0") 'issuer matches the gateway jwtAuth issuer' $c.iss
    Result ($c.aud -eq $d.clientId) 'audience is the app client ID' $c.aud
    Result (($c.scp -split ' ') -contains 'access_as_user') 'scp contains access_as_user' $c.scp
    Result ($c.exp -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) 'token not expired'
    Result ([bool]$token.refresh_token) 'refresh token issued (offline_access)'
    Write-Host "Signed-in user: $($c.preferred_username)"
  }
}
$fails = @($results | Where-Object { -not $_.ok }).Count
Write-Host "`n$fails failure(s)"
exit $fails
