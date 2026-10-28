<#
  Intune Win32 uninstall command. Removes the MSI, the CA trust, the scheduled
  task and the marker. Keeps %ProgramData%\AgentDesktop (device identity), as
  the MSI does. The daemon removes the registry policy when it stops managing it;
  this script also removes it if the daemon left it behind.
#>
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkg = Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json

# Stop managing Claude Desktop first, so the daemon removes its own policy value.
$config = Join-Path $env:ProgramData 'AgentDesktop\config.yaml'
if (Test-Path $config) {
  '{}' | Set-Content $config
  Restart-Service AgentDesktop -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 10
}

Unregister-ScheduledTask -TaskName 'AgentDesktop-InterceptCA-Trust' -Confirm:$false -ErrorAction SilentlyContinue

$p = Start-Process msiexec.exe -Wait -PassThru -NoNewWindow -ArgumentList @(
  '/x', "`"$(Join-Path $root 'agentdesktop.msi')`"", '/qn', '/norestart')

Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject.StartsWith('CN=agentdesktop intercept CA') } |
  Remove-Item -Force

$policy = 'HKLM:\SOFTWARE\Policies\Claude'
if ((Get-ItemProperty $policy -ErrorAction SilentlyContinue).egressProxyUrl -like 'http://127.0.0.1:*') {
  Remove-ItemProperty $policy -Name egressProxyUrl -ErrorAction SilentlyContinue
}
Remove-Item 'HKLM:\SOFTWARE\AgentDesktop\IntuneDeployment' -Recurse -Force -ErrorAction SilentlyContinue

exit $(if ($p.ExitCode -in 0, 3010, 1605) { 0 } else { $p.ExitCode })
