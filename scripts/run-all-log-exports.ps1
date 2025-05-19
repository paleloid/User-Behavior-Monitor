Set-Location -Path $PSScriptRoot
& "scripts/export-failed-logons.ps1"
& "scripts/export-suspicious-processes.ps1"
& "scripts/export-rdp-logons.ps1"
