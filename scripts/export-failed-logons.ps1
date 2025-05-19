Set-Location -Path $PSScriptRoot
$basePath = "logs"
$todayFile = "$basePath\failed_logons_today.csv"
$archiveFile = "$basePath\failed_logons_archive.csv"
$lastTimeFile = "$basePath\failedlogon_last_time.txt"

if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -ItemType Directory | Out-Null
}

if (Test-Path $lastTimeFile) {
    $lastRun = Get-Content $lastTimeFile | Get-Date
} else {
    $lastRun = (Get-Date).AddDays(-1)
}

$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$lastRun}
$entries = foreach ($e in $events) {
    $p = $e.Properties
    [PSCustomObject]@{
        TimeCreated   = $e.TimeCreated
        UserName      = $p[5].Value
        Workstation   = $p[11].Value
        IPAddress     = $p[19].Value
        FailureReason = $p[23].Value
    }
}

if ($entries) {
    $entries | Export-Csv -Path $todayFile -NoTypeInformation
    $entries | Export-Csv -Path $archiveFile -NoTypeInformation -Append
}

(Get-Date).ToString("o") | Out-File $lastTimeFile -Force
