<#
.SYNOPSIS
  Intune Win32 app install wrapper for Agent Desktop (Claude Desktop intercept mode).

.DESCRIPTION
  Runs as SYSTEM from the .intunewin package. Expects these files beside it:
    agentdesktop.msi, config.yaml, Sync-InterceptCaTrust.ps1, package.json

  Install command line:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-AgentDesktop.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkg = Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json
$data = Join-Path $env:ProgramData 'AgentDesktop'
$scripts = Join-Path $data 'scripts'
$logs = Join-Path $data 'logs'
New-Item -ItemType Directory -Force -Path $data, $scripts, $logs | Out-Null
Start-Transcript -Path (Join-Path $logs 'intune-install.log') -Append | Out-Null

try {
  # 1. Package integrity: the MSI must be the release asset the build verified.
  $msi = Join-Path $root 'agentdesktop.msi'
  $hash = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant()
  if ($hash -ne $pkg.msiSha256.ToLowerInvariant()) { throw "MSI SHA-256 $hash does not match package.json" }

  # 2. Install or upgrade. The MSI stops/starts the AgentDesktop service itself.
  $p = Start-Process msiexec.exe -Wait -PassThru -NoNewWindow -ArgumentList @(
    '/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$(Join-Path $logs 'msi-install.log')`"")
  if ($p.ExitCode -notin 0, 3010) { throw "msiexec exited $($p.ExitCode)" }

  # 3. Configuration. The MSI keeps an existing config, so write ours after it.
  $config = Join-Path $data 'config.yaml'
  $new = Join-Path $root 'config.yaml'
  if (Test-Path $config) { Copy-Item $config "$config.bak" -Force }
  Copy-Item $new $config -Force

  # 4. Helper script + hardened ACL (SYSTEM runs it from a scheduled task).
  Copy-Item (Join-Path $root 'Sync-InterceptCaTrust.ps1') $scripts -Force
  & icacls.exe $scripts /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null

  # 5. Restart so the daemon reads the new config (creates the CA, writes the
  #    HKLM\SOFTWARE\Policies\Claude egressProxyUrl value).
  Restart-Service AgentDesktop -ErrorAction Stop
  $caPem = Join-Path $data 'state\intercept-ca.pem'
  $deadline = (Get-Date).AddSeconds(120)
  while (-not (Test-Path $caPem) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
  if (-not (Test-Path $caPem)) { throw "daemon did not create $caPem within 120 s" }

  # 6. Trust the CA now, and keep it trusted (rotation, reinstall).
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scripts 'Sync-InterceptCaTrust.ps1') -Mode Remediate
  if ($LASTEXITCODE -ne 0) { throw 'Sync-InterceptCaTrust.ps1 failed' }

  $taskName = 'AgentDesktop-InterceptCA-Trust'
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $scripts 'Sync-InterceptCaTrust.ps1')`" -Mode Remediate")
  $triggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)))
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Force `
    -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) | Out-Null

  # 7. Marker read by Detect-AgentDesktop.ps1. Written last: it means "complete".
  $key = 'HKLM:\SOFTWARE\AgentDesktop\IntuneDeployment'
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty $key -Name Version -Value $pkg.version
  Set-ItemProperty $key -Name ConfigSha256 -Value $pkg.configSha256
  Set-ItemProperty $key -Name InstalledUtc -Value (Get-Date).ToUniversalTime().ToString('o')

  Write-Output "Agent Desktop $($pkg.version) installed; Claude Desktop must be restarted to use the proxy."
  exit 0
}
catch {
  Write-Error $_
  exit 1
}
finally { Stop-Transcript | Out-Null }
