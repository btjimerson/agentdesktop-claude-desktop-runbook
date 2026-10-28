<#
.SYNOPSIS
  Publishes the Agent Desktop Win32 app to Intune and assigns it to the pilot
  device group as Required.

.DESCRIPTION
  Uses the community IntuneWin32App module (MSEndpointMgr), which wraps the
  Graph content-upload flow:  Install-Module IntuneWin32App -Scope CurrentUser
  Run Windows\Build-IntuneWinPackage.ps1 first.

  The cmdlet calls below follow the module's documented parameters; they have
  not been executed against a tenant by the author. Run with -WhatIf-style review
  of the portal after the first publish, or upload the .intunewin manually using
  the values in RUNBOOK.md section 6.

.EXAMPLE
  .\Publish-ToIntune.ps1 -DeploymentFile ..\..\config\deployment.json -BuildDir ..\..\windows\out
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$DeploymentFile,
  [Parameter(Mandatory)][string]$BuildDir,
  [ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64',
  [string]$Publisher = 'Agent Desktop'
)
$ErrorActionPreference = 'Stop'
Import-Module IntuneWin32App
$d = Get-Content $DeploymentFile -Raw | ConvertFrom-Json
if (-not $d.devicesGroupId) { throw 'deployment.json has no devicesGroupId; run harness\entra\New-EntraApp.ps1 first' }

Connect-MSIntuneGraph -TenantID $d.tenantId | Out-Null

$intunewin = Join-Path $BuildDir "agentdesktop-$Architecture.intunewin"
$detectScript = Join-Path $BuildDir "Detect-AgentDesktop-$Architecture.ps1"
foreach ($f in $intunewin, $detectScript) { if (-not (Test-Path $f)) { throw "missing $f; run Build-IntuneWinPackage.ps1" } }

$graphArch = @{ amd64 = 'x64'; arm64 = 'arm64' }[$Architecture]
$detection = New-IntuneWin32AppDetectionRuleScript -ScriptFile $detectScript -EnforceSignatureCheck $false -RunAs32Bit $false
$requirement = New-IntuneWin32AppRequirementRule -Architecture $graphArch -MinimumSupportedWindowsRelease 'W10_21H2'

$name = "Agent Desktop $($d.agentdesktopVersion) - Claude Desktop intercept ($graphArch)"
$app = Add-IntuneWin32App -FilePath $intunewin -DisplayName $name `
  -Description "Agent Desktop $($d.agentdesktopVersion): routes Claude Desktop's claude.ai traffic through the corporate agentgateway with Entra ID identity." `
  -Publisher $Publisher -InstallExperience system -RestartBehavior suppress `
  -DetectionRule $detection -RequirementRule $requirement `
  -InstallCommandLine 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-AgentDesktop.ps1' `
  -UninstallCommandLine 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-AgentDesktop.ps1' `
  -Verbose

Add-IntuneWin32AppAssignmentGroup -Include -ID $app.id -GroupID $d.devicesGroupId -Intent required -Notification hideAll
Write-Host "Published '$name' ($($app.id)) to group $($d.devicesGroupId)" -ForegroundColor Green

$d | Add-Member -NotePropertyName intuneAppId -NotePropertyValue $app.id -Force
$d | ConvertTo-Json | Set-Content $DeploymentFile
