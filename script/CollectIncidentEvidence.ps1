<#
.SYNOPSIS
    Automated evidence collection for incident response
.DESCRIPTION
    Collects comprehensive forensic evidence during security incidents
.PARAMETER IncidentID
    Incident identifier (auto-generated if not provided)
.PARAMETER OutputPath
    Base path for output (default: C:\IncidentResponse)
.EXAMPLE
    .\CollectIncidentEvidence.ps1 -IncidentID "INC-SEC-20251217-001"
.NOTES
    Requires: Administrator privileges
    Author: CISO
    Version: 1.0
#>

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$IncidentID = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IncidentResponse"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    Add-Content -Path "$script:outputDir\collection.log" -Value $logMessage
}

Write-Host @"

================================================
    INCIDENT RESPONSE EVIDENCE COLLECTION
            Version 1.0
================================================

"@ -ForegroundColor Cyan

$script:outputDir = Join-Path $OutputPath $IncidentID

if (-not (Test-Path $script:outputDir)) {
    New-Item -ItemType Directory -Path $script:outputDir -Force | Out-Null
}

Write-Host "[*] Output Directory: $script:outputDir`n" -ForegroundColor Yellow
Write-Log "Starting evidence collection for incident: $IncidentID"

Write-Host "[1/10] Collecting system information..." -ForegroundColor Green
$sysPath = New-Item -ItemType Directory -Path "$script:outputDir\01_System" -Force
Get-ComputerInfo | Out-File "$sysPath\computerinfo.txt"
Get-HotFix | Export-Csv "$sysPath\patches.csv" -NoTypeInformation
Write-Log "System information collected"

Write-Host "[2/10] Collecting network information..." -ForegroundColor Green
$netPath = New-Item -ItemType Directory -Path "$script:outputDir\02_Network" -Force
ipconfig /all | Out-File "$netPath\ipconfig.txt"
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Export-Csv "$netPath\tcp_connections.csv" -NoTypeInformation
Get-DnsClientCache | Export-Csv "$netPath\dns_cache.csv" -NoTypeInformation
netstat -ano | Out-File "$netPath\netstat.txt"
arp -a | Out-File "$netPath\arp.txt"
Write-Log "Network information collected"

Write-Host "[3/10] Collecting process information..." -ForegroundColor Green
$procPath = New-Item -ItemType Directory -Path "$script:outputDir\03_Processes" -Force
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Id = $_.Id
        Path = $_.Path
        Company = $_.Company
        StartTime = $_.StartTime
        SHA256 = (Get-FileHash -Path $_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    }
} | Export-Csv "$procPath\processes.csv" -NoTypeInformation
tasklist /v | Out-File "$procPath\tasklist.txt"
Write-Log "Process information collected"

Write-Host "[4/10] Collecting service information..." -ForegroundColor Green
$svcPath = New-Item -ItemType Directory -Path "$script:outputDir\04_Services" -Force
Get-Service | Export-Csv "$svcPath\services.csv" -NoTypeInformation
Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName | Export-Csv "$svcPath\services_detail.csv" -NoTypeInformation
Write-Log "Service information collected"

Write-Host "[5/10] Collecting user information..." -ForegroundColor Green
$userPath = New-Item -ItemType Directory -Path "$script:outputDir\05_Users" -Force
Get-LocalUser | Export-Csv "$userPath\local_users.csv" -NoTypeInformation
Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Export-Csv "$userPath\administrators.csv" -NoTypeInformation
net user | Out-File "$userPath\net_users.txt"
quser | Out-File "$userPath\logged_users.txt"
Write-Log "User information collected"

Write-Host "[6/10] Collecting file system information..." -ForegroundColor Green
$filePath = New-Item -ItemType Directory -Path "$script:outputDir\06_FileSystem" -Force
$recentFiles = Get-ChildItem -Path "C:\Users\*\AppData\Local\Temp", "C:\Windows\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | Select-Object FullName, Length, CreationTime, LastWriteTime
$recentFiles | Export-Csv "$filePath\recent_files.csv" -NoTypeInformation
Write-Log "File system information collected"

Write-Host "[7/10] Collecting registry information..." -ForegroundColor Green
$regPath = New-Item -ItemType Directory -Path "$script:outputDir\07_Registry" -Force
$runKeys = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($key in $runKeys) {
    $keyName = $key -replace ':', '' -replace '\\', '_'
    Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ConvertTo-Json | Out-File "$regPath\$keyName.json"
}
Write-Log "Registry information collected"

Write-Host "[8/10] Collecting event logs..." -ForegroundColor Green
$eventPath = New-Item -ItemType Directory -Path "$script:outputDir\08_EventLogs" -Force
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4672} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Export-Csv "$eventPath\security_events.csv" -NoTypeInformation
wevtutil qe Security /c:100 /rd:true /f:text | Out-File "$eventPath\security_recent.txt"
Write-Log "Event logs collected"

Write-Host "[9/10] Collecting scheduled tasks..." -ForegroundColor Green
$taskPath = New-Item -ItemType Directory -Path "$script:outputDir\09_ScheduledTasks" -Force
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State, @{Name="Actions";Expression={$_.Actions.Execute}} | Export-Csv "$taskPath\scheduled_tasks.csv" -NoTypeInformation
schtasks /query /fo LIST /v | Out-File "$taskPath\schtasks.txt"
Write-Log "Scheduled tasks collected"

Write-Host "[10/10] Creating summary..." -ForegroundColor Green
$summary = @"
EVIDENCE COLLECTION SUMMARY
===========================

Incident ID: $IncidentID
Collection Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer Name: $env:COMPUTERNAME
IP Address: $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"})[0].IPAddress)
Collected By: $env:USERNAME

COLLECTION STATUS:
- System Information: COMPLETE
- Network Information: COMPLETE
- Process Information: COMPLETE
- Service Information: COMPLETE
- User Information: COMPLETE
- File System Information: COMPLETE
- Registry Information: COMPLETE
- Event Logs: COMPLETE
- Scheduled Tasks: COMPLETE

OUTPUT LOCATION: $script:outputDir

NEXT STEPS:
1. Review collected data
2. Compress folder for archival
3. Transfer to secure storage
4. Update incident report

"@
$summary | Out-File "$script:outputDir\SUMMARY.txt"
Write-Log "Summary created"

Write-Host "`n[+] Evidence collection completed successfully!" -ForegroundColor Green
Write-Host "[*] Output directory: $script:outputDir" -ForegroundColor Yellow
Write-Host "[*] Please compress and secure this folder" -ForegroundColor Yellow
Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
