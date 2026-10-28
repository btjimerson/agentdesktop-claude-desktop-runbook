<#
  Intune Win32 detection rule (custom script). Intune treats exit 0 AND any
  stdout as "installed". Build-IntuneWinPackage.ps1 stamps the two values below.
  Changing the config changes ConfigSha256, so a required assignment reinstalls.
#>
$ExpectedVersion = '__VERSION__'
$ExpectedConfigSha256 = '__CONFIG_SHA256__'

$key = 'HKLM:\SOFTWARE\AgentDesktop\IntuneDeployment'
$marker = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
$service = Get-Service -Name AgentDesktop -ErrorAction SilentlyContinue

if ($marker -and $service -and
    $marker.Version -eq $ExpectedVersion -and
    $marker.ConfigSha256 -eq $ExpectedConfigSha256) {
  Write-Output "Agent Desktop $ExpectedVersion present, config $($ExpectedConfigSha256.Substring(0, 8))"
  exit 0
}
exit 1
