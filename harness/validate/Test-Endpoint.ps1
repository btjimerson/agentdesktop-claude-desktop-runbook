<#
.SYNOPSIS
  Validates a Windows device after the Intune deployment. Run elevated, on the
  pilot device (or push it as an Intune Remediation/Platform script and read
  the JSON evidence from %ProgramData%\AgentDesktop\logs).

.DESCRIPTION
  Each check prints PASS/FAIL/INFO and is recorded in an evidence JSON file.
  Exit code = number of FAIL checks.

  -ExpectSignedIn   A user has signed in to the gateway (Entra) on this device;
                    requests through the listener must then reach the gateway.
  -ExpectedVersion  Agent Desktop version (default 0.6.0).
#>
[CmdletBinding()]
param(
  [string]$ExpectedVersion = '0.6.0',
  [string]$ProxyHost = '127.0.0.1',
  [int]$ProxyPort = 18471,
  [switch]$ExpectSignedIn,
  [string]$EvidenceDir = (Join-Path $env:ProgramData 'AgentDesktop\logs')
)
$ErrorActionPreference = 'Stop'
$data = Join-Path $env:ProgramData 'AgentDesktop'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result($name, $status, $detail = '') {
  $results.Add([ordered]@{ check = $name; status = $status; detail = $detail })
  $color = @{ PASS = 'Green'; FAIL = 'Red'; INFO = 'Yellow' }[$status]
  Write-Host ('{0,-5} {1}{2}' -f $status, $name, $(if ($detail) { " - $detail" })) -ForegroundColor $color
}
function Check($name, [scriptblock]$test) {
  # A test returns $true or a detail string to pass, and throws to fail.
  try { $r = & $test; Add-Result $name PASS ($(if ($r -is [string]) { $r })) }
  catch { Add-Result $name FAIL $_.Exception.Message }
}

function Get-DaemonInfo {
  $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'agentdesktop', 'InOut')
  try {
    $pipe.Connect(5000)
    $req = [Text.Encoding]::ASCII.GetBytes("GET /v1/daemon-info HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n")
    $pipe.Write($req, 0, $req.Length); $pipe.Flush()
    $ms = [System.IO.MemoryStream]::new(); $pipe.CopyTo($ms)
    $text = [Text.Encoding]::UTF8.GetString($ms.ToArray())
    $body = $text.Substring($text.IndexOf("`r`n`r`n") + 4)
    # Tolerate chunked encoding: take the outermost JSON object.
    ($body.Substring($body.IndexOf('{'), $body.LastIndexOf('}') - $body.IndexOf('{') + 1)) | ConvertFrom-Json
  } finally { $pipe.Dispose() }
}

# --- Install -------------------------------------------------------------------
Check 'AgentDesktop service is running' {
  $s = Get-Service AgentDesktop; if ($s.Status -eq 'Running') { $true } else { throw "status $($s.Status)" } }
Check "agentdesktop.exe is $ExpectedVersion" {
  $exe = Join-Path $env:ProgramFiles 'Agent Desktop\agentdesktop.exe'
  $v = (& $exe --version) -join ' '; if ($v -match [regex]::Escape($ExpectedVersion)) { $v } else { throw "got '$v'" } }
Check 'Intune marker matches the deployed config' {
  $k = Get-ItemProperty 'HKLM:\SOFTWARE\AgentDesktop\IntuneDeployment'
  $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $data 'config.yaml')).Hash.ToLowerInvariant()
  if ($k.ConfigSha256 -eq $actual) { "config sha256 $($actual.Substring(0, 12))" } else { throw "marker $($k.ConfigSha256) vs file $actual" } }
Check 'config.yaml selects intercept mode with Entra' {
  $c = Get-Content (Join-Path $data 'config.yaml') -Raw
  if ($c -match 'gatewayMode:\s*intercept' -and $c -match 'login\.microsoftonline\.com/[0-9a-f-]{36}/v2\.0' -and $c -match 'access_as_user') { $true } else { throw 'missing intercept/Entra settings' } }

# --- Daemon --------------------------------------------------------------------
$info = $null
Check 'daemon API answers on \\.\pipe\agentdesktop' { $script:info = Get-DaemonInfo; $true }
Check 'intercept listener is bound on loopback' {
  $i = $info.intercept
  if ($i.enabled -and $i.bound -and $i.listen -eq "${ProxyHost}:$ProxyPort") { $i.listen } else { throw "enabled=$($i.enabled) bound=$($i.bound) listen=$($i.listen) error=$($i.error)" } }
Check 'listener port is owned by the AgentDesktop service process' {
  $c = Get-NetTCPConnection -State Listen -LocalPort $ProxyPort -LocalAddress $ProxyHost
  $svcPid = (Get-CimInstance Win32_Service -Filter "Name='AgentDesktop'").ProcessId
  if ($c.OwningProcess -eq $svcPid) { "pid $svcPid" } else { throw "owner pid $($c.OwningProcess), service pid $svcPid" } }

# --- Claude Desktop pin --------------------------------------------------------
Check 'policy HKLM\SOFTWARE\Policies\Claude egressProxyUrl is pinned' {
  $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Claude' -ErrorAction Stop).egressProxyUrl
  if ($v -eq "http://${ProxyHost}:$ProxyPort") { $v } else { throw "got '$v'" } }
Check 'no inference* policy values (Claude Desktop stays on claude.ai sign-in)' {
  $names = (Get-Item 'HKLM:\SOFTWARE\Policies\Claude').Property | Where-Object { $_ -like 'inference*' }
  if (-not $names) { $true } else { throw "found: $($names -join ', ')" } }

# --- CA trust ------------------------------------------------------------------
$caCert = $null
Check 'intercept CA is trusted in LocalMachine\Root' {
  $pem = Join-Path $data 'state\intercept-ca.pem'
  $b64 = ((Get-Content $pem -Raw) -replace '-----[A-Z ]+-----', '' -replace '\s', '')
  $script:caCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($b64))
  $hit = Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $caCert.Thumbprint
  if ($hit) { "$($caCert.Subject) valid to $($caCert.NotAfter.ToString('yyyy-MM-dd'))" } else { throw 'not in store' } }
Check 'CA SHA-256 matches daemon-info' {
  $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($caCert.RawData)) -replace '-', ''
  if ($info.intercept.caSha256 -replace '[:\s]', '' -ieq $sha) { $sha.Substring(0, 16) } else { throw "daemon $($info.intercept.caSha256) vs file $sha" } }
Check 'only one intercept CA is trusted (no stale rotations)' {
  $n = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject.StartsWith('CN=agentdesktop intercept CA') }).Count
  if ($n -eq 1) { $true } else { throw "$n certificates" } }
Check 'CA trust scheduled task exists (SYSTEM)' {
  $t = Get-ScheduledTask -TaskName 'AgentDesktop-InterceptCA-Trust'
  if ($t.Principal.UserId -eq 'SYSTEM') { $true } else { throw "runs as $($t.Principal.UserId)" } }
Check 'Sync-InterceptCaTrust.ps1 -Mode Detect passes' {
  $o = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $data 'scripts\Sync-InterceptCaTrust.ps1') -Mode Detect
  if ($LASTEXITCODE -eq 0) { $true } else { throw "$o" } }

# --- TLS through the listener (what Claude Desktop does) ----------------------
function Open-Tunnel($target) {
  $tcp = [System.Net.Sockets.TcpClient]::new($ProxyHost, $ProxyPort)
  $s = $tcp.GetStream(); $s.ReadTimeout = 15000
  $w = [Text.Encoding]::ASCII.GetBytes("CONNECT ${target}:443 HTTP/1.1`r`nHost: ${target}:443`r`n`r`n"); $s.Write($w, 0, $w.Length)
  $buf = [byte[]]::new(512); $n = $s.Read($buf, 0, 512)
  $status = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r`n")[0]
  [pscustomobject]@{ Tcp = $tcp; Stream = $s; Status = $status }
}
function Get-TlsFacts($target) {
  $t = Open-Tunnel $target
  try {
    if ($t.Status -notmatch ' 200') { throw "CONNECT answered '$($t.Status)'" }
    $errors = $null
    $cb = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $script:errors = $e; $true }
    $ssl = [System.Net.Security.SslStream]::new($t.Stream, $false, $cb)
    $ssl.AuthenticateAsClient($target)
    $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
    $ssl.Write([Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: $target`r`nConnection: close`r`n`r`n"))
    $buf = [byte[]]::new(256); $n = $ssl.Read($buf, 0, 256)
    [pscustomobject]@{ Issuer = $leaf.Issuer; Errors = "$errors"; FirstLine = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "`r`n")[0] }
  } finally { $t.Tcp.Dispose() }
}
foreach ($h in 'claude.ai', 'api.anthropic.com') {
  Check "$h via the listener is served with the intercept CA and a valid chain" {
    $f = Get-TlsFacts $h
    if ($f.Issuer -like '*agentdesktop intercept CA*' -and $f.Errors -eq 'None') { "issuer $($f.Issuer)" } else { throw "issuer '$($f.Issuer)' errors '$($f.Errors)'" } }
}
Check 'other hosts are tunnelled, not intercepted (login.microsoftonline.com)' {
  $f = Get-TlsFacts 'login.microsoftonline.com'
  if ($f.Issuer -notlike '*agentdesktop*' -and $f.Errors -eq 'None') { "issuer $($f.Issuer)" } else { throw "issuer '$($f.Issuer)' errors '$($f.Errors)'" } }
Check 'non-443 port on an intercepted host is refused' {
  $tcp = [System.Net.Sockets.TcpClient]::new($ProxyHost, $ProxyPort); $s = $tcp.GetStream()
  $w = [Text.Encoding]::ASCII.GetBytes("CONNECT claude.ai:8443 HTTP/1.1`r`nHost: claude.ai:8443`r`n`r`n"); $s.Write($w, 0, $w.Length)
  $b = [byte[]]::new(256); $n = $s.Read($b, 0, 256); $tcp.Dispose()
  $line = ([Text.Encoding]::ASCII.GetString($b, 0, $n) -split "`r`n")[0]
  if ($line -notmatch ' 200') { $line } else { throw 'CONNECT to claude.ai:8443 was allowed' } }

# --- Gateway -------------------------------------------------------------------
$info = Get-DaemonInfo
if ($ExpectSignedIn) {
  Check 'request through the listener reaches the gateway (not 502/401)' {
    $f = Get-TlsFacts 'claude.ai'
    if ($f.FirstLine -match ' (502|401) ') { throw "got '$($f.FirstLine)'; daemon: $($info.intercept.lastFailure)" } else { $f.FirstLine } }
  Check 'daemon counts forwarded requests' { if ($info.intercept.forwarded -gt 0) { "forwarded=$($info.intercept.forwarded)" } else { throw "forwarded=0 lastFailure=$($info.intercept.lastFailure)" } }
} else {
  Check 'signed out: request fails closed with 502 (nothing connects directly)' {
    $f = Get-TlsFacts 'claude.ai'
    if ($f.FirstLine -match ' 502 ') { $f.FirstLine } else { throw "got '$($f.FirstLine)'" } }
}

# --- Claude Desktop (best effort) ---------------------------------------------
$log = Get-ChildItem 'C:\Users\*\AppData\Roaming\Claude\logs\main.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log) {
  $text = Get-Content $log.FullName -Tail 2000 -ErrorAction SilentlyContinue
  $pinned = $text | Select-String -SimpleMatch "pinned to fixed proxy at ${ProxyHost}:$ProxyPort" | Select-Object -First 1
  $tls = ($text | Select-String -Pattern 'ERR_CERT|ERR_SSL').Count
  Add-Result 'Claude Desktop main.log shows the pinned proxy' $(if ($pinned) { 'PASS' } else { 'INFO' }) $log.FullName
  Add-Result 'Claude Desktop main.log has no ERR_CERT/ERR_SSL' $(if ($tls -eq 0) { 'PASS' } else { 'FAIL' }) "$tls lines"
} else { Add-Result 'Claude Desktop main.log' INFO 'not found; start Claude Desktop once and re-run (log path is a best guess)' }

$fails = @($results | Where-Object status -eq 'FAIL').Count
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$file = Join-Path $EvidenceDir ("validation-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMddTHHmmss'))
[ordered]@{ computer = $env:COMPUTERNAME; utc = (Get-Date).ToUniversalTime().ToString('o'); expectSignedIn = [bool]$ExpectSignedIn
  failures = $fails; daemonInfo = $info; results = $results } | ConvertTo-Json -Depth 8 | Set-Content $file
Write-Host "`n$fails failure(s). Evidence: $file"
exit $fails
