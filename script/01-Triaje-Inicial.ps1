#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IncidentResponse\Triaje_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$ErrorActionPreference = "Continue"

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Start-Transcript -Path "$OutputPath\triaje.log"

Write-Host "=== TRIAJE INICIAL DE INCIDENTE ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Equipo: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Usuario: $env:USERNAME`n" -ForegroundColor Yellow

$info = @{
    Timestamp = Get-Date
    Computer = $env:COMPUTERNAME
    Usuario = $env:USERNAME
    Dominio = $env:USERDOMAIN
    IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"})[0].IPAddress
}

$info | ConvertTo-Json | Out-File "$OutputPath\info_basica.json"

Write-Host "[1/8] Procesos activos sospechosos..." -ForegroundColor Green
Get-Process | Where-Object {$_.Company -eq $null -and $_.Path} | 
    Select-Object ProcessName, Id, Path, StartTime |
    Export-Csv "$OutputPath\procesos_sin_firma.csv" -NoTypeInformation

Get-Process | Where-Object {$_.Path -like "*\Temp\*" -or $_.Path -like "*\AppData\Local\Temp\*"} |
    Select-Object ProcessName, Id, Path |
    Export-Csv "$OutputPath\procesos_desde_temp.csv" -NoTypeInformation

Write-Host "[2/8] Conexiones de red activas..." -ForegroundColor Green
Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.RemoteAddress -notlike "127.*"} |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, 
        @{Name="Proceso";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Export-Csv "$OutputPath\conexiones_establecidas.csv" -NoTypeInformation

Write-Host "[3/8] Servicios sospechosos..." -ForegroundColor Green
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -ne "Automatic"} |
    Select-Object Name, DisplayName, Status, StartType |
    Export-Csv "$OutputPath\servicios_no_automaticos.csv" -NoTypeInformation

Write-Host "[4/8] Tareas programadas recientes..." -ForegroundColor Green
Get-ScheduledTask | Where-Object {
    $_.State -ne "Disabled" -and 
    $_.TaskPath -notlike "\Microsoft\*"
} | Select-Object TaskName, TaskPath, State |
Export-Csv "$OutputPath\tareas_no_microsoft.csv" -NoTypeInformation

Write-Host "[5/8] Usuarios logueados..." -ForegroundColor Green
query user 2>&1 | Out-File "$OutputPath\usuarios_logueados.txt"

Write-Host "[6/8] Eventos de seguridad recientes (últimas 24h)..." -ForegroundColor Green
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624,4625,4648,4672,4720
    StartTime=(Get-Date).AddHours(-24)
} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{Name="Evento";Expression={
        switch($_.Id) {
            4624 {"Logon exitoso"}
            4625 {"Logon fallido"}
            4648 {"Logon con credenciales explícitas"}
            4672 {"Privilegios especiales asignados"}
            4720 {"Cuenta creada"}
        }
    }}, Message |
    Export-Csv "$OutputPath\eventos_seguridad_24h.csv" -NoTypeInformation

Write-Host "[7/8] Archivos recientes en Temp (última semana)..." -ForegroundColor Green
Get-ChildItem C:\Users\*\AppData\Local\Temp, C:\Windows\Temp -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7) -and !$_.PSIsContainer} |
    Select-Object FullName, Length, CreationTime, LastWriteTime |
    Sort-Object LastWriteTime -Descending |
    Export-Csv "$OutputPath\archivos_temp_recientes.csv" -NoTypeInformation

Write-Host "[8/8] Verificando persistencia básica..." -ForegroundColor Green
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $keyName = $key -replace ':', '' -replace '\\', '_'
        Get-ItemProperty -Path $key | 
            ConvertTo-Json | 
            Out-File "$OutputPath\registry_$keyName.json"
    }
}

$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -ErrorAction SilentlyContinue |
            Select-Object Name, FullName, CreationTime, LastWriteTime |
            Export-Csv "$OutputPath\startup_$(Split-Path $folder -Leaf).csv" -NoTypeInformation
    }
}

Stop-Transcript

Write-Host "`n=== TRIAJE COMPLETADO ===" -ForegroundColor Cyan
Write-Host "Evidencia guardada en: $OutputPath" -ForegroundColor Yellow

Write-Host "`n=== REVISAR INMEDIATAMENTE ===" -ForegroundColor Red
Write-Host "1. procesos_sin_firma.csv - Procesos sin firma digital" -ForegroundColor Yellow
Write-Host "2. procesos_desde_temp.csv - Procesos ejecutándose desde carpetas temporales" -ForegroundColor Yellow
Write-Host "3. conexiones_establecidas.csv - Conexiones de red activas" -ForegroundColor Yellow
Write-Host "4. eventos_seguridad_24h.csv - Eventos de autenticación recientes" -ForegroundColor Yellow

Write-Host "`nPresione Enter para salir..."
Read-Host
