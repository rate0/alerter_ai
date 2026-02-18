# Check Elastic stack access - localhost and WiFi IP
# Run: .\check-access.ps1

$wifiIp = "192.168.8.54"
$ports = @(
    @{ Name = "Kibana"; Port = 5601; Path = "/" },
    @{ Name = "Elasticsearch"; Port = 9200; Path = "/"; Auth = "elastic:changeme" },
    @{ Name = "Fleet"; Port = 8220; Path = "/" },
    @{ Name = "APM"; Port = 8200; Path = "/" }
)

Write-Host "=== Localhost (127.0.0.1) ===" -ForegroundColor Cyan
foreach ($p in $ports) {
    $url = "https://127.0.0.1:$($p.Port)$($p.Path)"
    $arg = @("-k", "-s", "-o", "NUL", "-w", "%{http_code}", "--connect-timeout", "4", $url)
    if ($p.Auth) { $arg = @("-k", "-s", "-o", "NUL", "-w", "%{http_code}", "--connect-timeout", "4", "-u", $p.Auth, $url) }
    $code = & curl.exe @arg 2>$null
    $ok = $code -match "^\d{3}$"
    $status = if ($ok) { "OK ($code)" } else { "FAIL / timeout" }
    Write-Host "  $($p.Name) :$($p.Port) -> $status"
}

Write-Host "`n=== WiFi IP ($wifiIp) - from this PC (hairpin may fail) ===" -ForegroundColor Cyan
foreach ($p in $ports) {
    $url = "https://${wifiIp}:$($p.Port)$($p.Path)"
    $arg = @("-k", "-s", "-o", "NUL", "-w", "%{http_code}", "--connect-timeout", "4", $url)
    if ($p.Auth) { $arg = @("-k", "-s", "-o", "NUL", "-w", "%{http_code}", "--connect-timeout", "4", "-u", $p.Auth, $url) }
    $code = & curl.exe @arg 2>$null
    $ok = $code -match "^\d{3}$"
    $status = if ($ok) { "OK ($code)" } else { "timeout/FAIL (normal from same PC)" }
    Write-Host "  $($p.Name) :$($p.Port) -> $status"
}

Write-Host "`n=== Portproxy rules ===" -ForegroundColor Cyan
netsh interface portproxy show all 2>$null

Write-Host "`nFrom phone in WiFi use: https://${wifiIp}:5601 (Kibana), https://${wifiIp}:8220 (Fleet)" -ForegroundColor Green
