Set-Location -Path $PSScriptRoot
$basePath = "logs"
$todayFile = "$basePath\rdp_logons_today.csv"
$archiveFile = "$basePath\rdp_logons_archive.csv"
$lastTimeFile = "$basePath\rdplogon_last_time.txt"

if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -ItemType Directory | Out-Null
}

if (Test-Path $lastTimeFile) {
    $lastRun = Get-Content $lastTimeFile | Get-Date
} else {
    $lastRun = (Get-Date).AddDays(-1)
}

$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$lastRun}
$rdps = foreach ($e in $events) {
    $p = $e.Properties
    if ($p[8].Value -eq 10) {
        [PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            UserName    = $p[5].Value
            IPAddress   = $p[18].Value
        }
    }
}

if ($rdps) {
    $rdps | Export-Csv -Path $todayFile -NoTypeInformation
    $rdps | Export-Csv -Path $archiveFile -NoTypeInformation -Append
}

(Get-Date).ToString("o") | Out-File $lastTimeFile -Force
