<#
.SYNOPSIS
  Builds the Intune Win32 package (.intunewin) for Agent Desktop.

.DESCRIPTION
  1. Downloads agentdesktop-windows-<arch>.msi for the version in deployment.json
     from GitHub Releases and verifies it against the release's .sha256 asset.
  2. Renders config\config.yaml.tmpl with the tenant values.
  3. Stamps Detect-AgentDesktop.ps1 with the version and config hash.
  4. Runs IntuneWinAppUtil.exe (Microsoft Win32 Content Prep Tool).

  Needs: gh CLI (authenticated) and IntuneWinAppUtil.exe
  (https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool).

.EXAMPLE
  .\Build-IntuneWinPackage.ps1 -DeploymentFile ..\config\deployment.json `
    -IntuneWinAppUtil C:\tools\IntuneWinAppUtil.exe -OutputDir .\out
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$DeploymentFile,
  [Parameter(Mandatory)][string]$IntuneWinAppUtil,
  [string]$OutputDir = (Join-Path $PSScriptRoot 'out'),
  [ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64'
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$d = Get-Content $DeploymentFile -Raw | ConvertFrom-Json
foreach ($f in 'agentdesktopVersion', 'tenantId', 'clientId', 'gatewayUrl') {
  if (-not $d.$f) { throw "deployment.json is missing '$f'" }
}
if ($d.gatewayUrl -notmatch '^https://') { throw 'gatewayUrl must be https://' }
$guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
if ($d.tenantId -notmatch $guid -or $d.clientId -notmatch $guid) { throw 'tenantId and clientId must be GUIDs' }

$stage = Join-Path $OutputDir "stage-$Architecture"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# 1. MSI + checksum from the release.
$tag = "v$($d.agentdesktopVersion)"
$asset = "agentdesktop-windows-$Architecture.msi"
$dl = Join-Path $OutputDir "download-$Architecture"
New-Item -ItemType Directory -Force -Path $dl | Out-Null
gh release download $tag --repo agentdesktop-dev/agentdesktop -p $asset -p "$asset.sha256" -D $dl --clobber
if ($LASTEXITCODE -ne 0) { throw "gh release download failed for $tag" }
$expected = ((Get-Content (Join-Path $dl "$asset.sha256") -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash -Algorithm SHA256 (Join-Path $dl $asset)).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "MSI checksum mismatch: $actual vs $expected" }
$sig = Get-AuthenticodeSignature (Join-Path $dl $asset)
if ($sig.Status -ne 'Valid') { Write-Warning "MSI Authenticode status is '$($sig.Status)' (expected Valid on Windows)" }
Copy-Item (Join-Path $dl $asset) (Join-Path $stage 'agentdesktop.msi')

# 2. Config.
$config = (Get-Content (Join-Path $repoRoot 'config\config.yaml.tmpl') -Raw).
  Replace('@@GATEWAY_URL@@', $d.gatewayUrl.TrimEnd('/')).
  Replace('@@TENANT_ID@@', $d.tenantId).
  Replace('@@CLIENT_ID@@', $d.clientId)
if ($config -match '@@') { throw 'unreplaced token in config.yaml' }
[System.IO.File]::WriteAllText((Join-Path $stage 'config.yaml'), ($config -replace "`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
$configSha = (Get-FileHash -Algorithm SHA256 (Join-Path $stage 'config.yaml')).Hash.ToLowerInvariant()

# 3. Scripts and metadata.
foreach ($f in 'Install-AgentDesktop.ps1', 'Uninstall-AgentDesktop.ps1', 'Sync-InterceptCaTrust.ps1') {
  Copy-Item (Join-Path $PSScriptRoot $f) $stage
}
[ordered]@{ version = $d.agentdesktopVersion; msiSha256 = $actual; configSha256 = $configSha } |
  ConvertTo-Json | Set-Content (Join-Path $stage 'package.json')
(Get-Content (Join-Path $PSScriptRoot 'Detect-AgentDesktop.ps1') -Raw).
  Replace('__VERSION__', $d.agentdesktopVersion).Replace('__CONFIG_SHA256__', $configSha) |
  Set-Content (Join-Path $OutputDir "Detect-AgentDesktop-$Architecture.ps1")

# 4. Package.
& $IntuneWinAppUtil -c $stage -s Install-AgentDesktop.ps1 -o $OutputDir -q
if ($LASTEXITCODE -ne 0) { throw 'IntuneWinAppUtil failed' }
$out = Join-Path $OutputDir "agentdesktop-$Architecture.intunewin"
Move-Item (Join-Path $OutputDir 'Install-AgentDesktop.intunewin') $out -Force

Write-Host "Package:   $out"
Write-Host "Detection: $(Join-Path $OutputDir "Detect-AgentDesktop-$Architecture.ps1")"
Write-Host "Install:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-AgentDesktop.ps1"
Write-Host "Uninstall: powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-AgentDesktop.ps1"
