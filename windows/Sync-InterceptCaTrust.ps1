<#
.SYNOPSIS
  Trusts the device's Agent Desktop intercept CA as a machine root.

.DESCRIPTION
  The daemon generates a CA per device on first use, so no certificate can be
  pushed from Intune ahead of time. This script runs as SYSTEM, reads the CA the
  daemon wrote, checks it is the constrained intercept CA, and imports it into
  LocalMachine\Root.

  -Mode Detect      Exit 0 when the current CA is trusted, 1 when it is not.
  -Mode Remediate   Trust the current CA and remove superseded intercept CAs.

  Usable as the detection/remediation pair of an Intune Remediation (needs
  Windows Enterprise E3/E5/A3/A5 licensing) and as the body of the scheduled
  task that the installer registers (works with any Intune licence).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Detect', 'Remediate')][string]$Mode,
  [string]$StateDir = (Join-Path $env:ProgramData 'AgentDesktop\state')
)
$ErrorActionPreference = 'Stop'
$SubjectPrefix = 'CN=agentdesktop intercept CA'
$NameConstraintsOid = '2.5.29.30'

function Write-Result($ok, $message, $extra = @{}) {
  ([ordered]@{ ok = $ok; message = $message } + $extra) | ConvertTo-Json -Compress
}

$pem = Join-Path $StateDir 'intercept-ca.pem'
if (-not (Test-Path -LiteralPath $pem)) {
  Write-Result $false 'intercept-ca.pem not found; the daemon has not created the CA yet'
  exit 1
}

$b64 = ((Get-Content -LiteralPath $pem -Raw) -replace '-----[A-Z ]+-----', '' -replace '\s', '')
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))

# Refuse anything that is not the constrained CA the daemon generates.
if (-not $cert.Subject.StartsWith($SubjectPrefix)) {
  Write-Result $false "unexpected CA subject '$($cert.Subject)'; not trusting" @{ thumbprint = $cert.Thumbprint }
  exit 1
}
if (-not ($cert.Extensions | Where-Object { $_.Oid.Value -eq $NameConstraintsOid })) {
  Write-Result $false 'CA has no Name Constraints extension; not trusting' @{ thumbprint = $cert.Thumbprint }
  exit 1
}
if ($cert.NotAfter -lt (Get-Date)) {
  Write-Result $false "CA expired $($cert.NotAfter.ToString('o')); restart the daemon after removing intercept-ca.pem to regenerate" @{ thumbprint = $cert.Thumbprint }
  exit 1
}

$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine')
$store.Open('ReadWrite')
try {
  $trusted = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
  $stale = @($store.Certificates | Where-Object {
      $_.Subject.StartsWith($SubjectPrefix) -and $_.Thumbprint -ne $cert.Thumbprint })

  if ($Mode -eq 'Detect') {
    if ($trusted -and $stale.Count -eq 0) {
      Write-Result $true 'intercept CA trusted' @{ thumbprint = $cert.Thumbprint; notAfter = $cert.NotAfter.ToString('o') }
      exit 0
    }
    Write-Result $false 'intercept CA not trusted or stale CAs present' @{ thumbprint = $cert.Thumbprint; stale = $stale.Count }
    exit 1
  }

  if (-not $trusted) { $store.Add($cert) }
  foreach ($old in $stale) { $store.Remove($old) }
  Write-Result $true 'intercept CA trusted' @{
    thumbprint = $cert.Thumbprint; removedStale = $stale.Count; notAfter = $cert.NotAfter.ToString('o') }
  exit 0
}
finally { $store.Close() }
