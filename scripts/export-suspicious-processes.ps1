$blacklist = @("mimikatz.exe", "procdump.exe", "netcat.exe")
$basePath = "logs"
$todayFile = "$basePath\suspicious_processes_today.csv"
$archiveFile = "$basePath\suspicious_processes_archive.csv"
$lastTimeFile = "$basePath\suspicious_last_time.txt"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path $basePath)) {
    New-Item -Path $basePath -ItemType Directory | Out-Null
}

if (Test-Path $lastTimeFile) {
    $lastRun = Get-Content $lastTimeFile | Get-Date
} else {
    $lastRun = (Get-Date).AddDays(-1)
}

$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$lastRun}
$matches = foreach ($event in $events) {
    $cmd = $event.Properties[5].Value
    foreach ($bad in $blacklist) {
        if ($cmd -like "*$bad*") {
            [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                User        = $event.Properties[1].Value
                CommandLine = $cmd
            }
        }
    }
}

if ($matches) {
    $matches | Export-Csv -Path $todayFile -NoTypeInformation
    $matches | Export-Csv -Path $archiveFile -NoTypeInformation -Append
}

(Get-Date).ToString("o") | Out-File $lastTimeFile -Force
