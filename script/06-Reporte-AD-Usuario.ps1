#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

param(
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IncidentResponse\AD-Report_$Username_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$ErrorActionPreference = "Continue"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "[ERROR] No se pudo cargar el módulo ActiveDirectory" -ForegroundColor Red
    Write-Host "        Instale RSAT o ejecute desde un controlador de dominio" -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Start-Transcript -Path "$OutputPath\reporte_ad.log"

Write-Host "=== REPORTE DE USUARIO EN ACTIVE DIRECTORY ===" -ForegroundColor Cyan
Write-Host "Usuario investigado: $Username" -ForegroundColor Yellow
Write-Host "Timestamp: $(Get-Date)`n" -ForegroundColor Yellow

try {
    $user = Get-ADUser -Identity $Username -Properties * -ErrorAction Stop
} catch {
    Write-Host "[ERROR] Usuario '$Username' no encontrado en Active Directory" -ForegroundColor Red
    Stop-Transcript
    exit 1
}

Write-Host "[1/8] Información básica del usuario..." -ForegroundColor Green

$basicInfo = [PSCustomObject]@{
    SamAccountName = $user.SamAccountName
    DisplayName = $user.DisplayName
    EmailAddress = $user.EmailAddress
    DistinguishedName = $user.DistinguishedName
    Enabled = $user.Enabled
    LockedOut = $user.LockedOut
    PasswordExpired = $user.PasswordExpired
    PasswordNeverExpires = $user.PasswordNeverExpires
    PasswordLastSet = $user.PasswordLastSet
    LastLogonDate = $user.LastLogonDate
    LastBadPasswordAttempt = $user.LastBadPasswordAttempt
    BadLogonCount = $user.BadLogonCount
    Created = $user.Created
    Modified = $user.Modified
    Description = $user.Description
}

$basicInfo | Format-List
$basicInfo | ConvertTo-Json | Out-File "$OutputPath\info_basica.json"

Write-Host "[2/8] Membresía de grupos..." -ForegroundColor Green

$groups = Get-ADPrincipalGroupMembership -Identity $Username | 
    Select-Object Name, GroupCategory, GroupScope, DistinguishedName

Write-Host "    Usuario pertenece a $($groups.Count) grupos:" -ForegroundColor Gray
$groups | Format-Table Name, GroupCategory -AutoSize
$groups | Export-Csv "$OutputPath\grupos.csv" -NoTypeInformation

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", 
                      "Administrators", "Account Operators", "Backup Operators")

$isPrivileged = $groups | Where-Object {$privilegedGroups -contains $_.Name}

if ($isPrivileged) {
    Write-Host "    [!] USUARIO CON PRIVILEGIOS ELEVADOS:" -ForegroundColor Red
    $isPrivileged | ForEach-Object {
        Write-Host "        - $($_.Name)" -ForegroundColor Yellow
    }
}

Write-Host "`n[3/8] Intentos de autenticación fallidos recientes..." -ForegroundColor Green

$failedLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Properties[5].Value -eq $Username
} | Select-Object TimeCreated, 
    @{Name="SourceIP";Expression={$_.Properties[19].Value}},
    @{Name="FailureReason";Expression={$_.Properties[8].Value}},
    @{Name="WorkstationName";Expression={$_.Properties[13].Value}}

if ($failedLogons) {
    Write-Host "    [!] $($failedLogons.Count) intentos fallidos en los últimos 7 días" -ForegroundColor Yellow
    $failedLogons | Format-Table TimeCreated, SourceIP, FailureReason -AutoSize
    $failedLogons | Export-Csv "$OutputPath\intentos_fallidos.csv" -NoTypeInformation
} else {
    Write-Host "    [OK] No se encontraron intentos fallidos recientes" -ForegroundColor Green
}

Write-Host "`n[4/8] Autenticaciones exitosas recientes..." -ForegroundColor Green

$successLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
    StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Properties[5].Value -eq $Username
} | Select-Object TimeCreated,
    @{Name="LogonType";Expression={$_.Properties[8].Value}},
    @{Name="SourceIP";Expression={$_.Properties[18].Value}},
    @{Name="WorkstationName";Expression={$_.Properties[11].Value}}

if ($successLogons) {
    Write-Host "    Autenticaciones exitosas: $($successLogons.Count)" -ForegroundColor Gray
    
    $uniqueIPs = $successLogons | Select-Object -ExpandProperty SourceIP -Unique
    Write-Host "    IPs únicas: $($uniqueIPs.Count)" -ForegroundColor Gray
    
    $successLogons | Group-Object SourceIP | 
        Sort-Object Count -Descending | 
        Select-Object @{Name="IP";Expression={$_.Name}}, Count |
        Format-Table -AutoSize
    
    $successLogons | Export-Csv "$OutputPath\autenticaciones_exitosas.csv" -NoTypeInformation
}

Write-Host "`n[5/8] Cambios recientes en la cuenta..." -ForegroundColor Green

$accountChanges = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4738,4720,4722,4723,4724,4725,4726
    StartTime=(Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -like "*$Username*"
} | Select-Object TimeCreated, Id,
    @{Name="Evento";Expression={
        switch($_.Id) {
            4720 {"Cuenta creada"}
            4722 {"Cuenta habilitada"}
            4723 {"Intento cambio contraseña"}
            4724 {"Contraseña reseteada"}
            4725 {"Cuenta deshabilitada"}
            4726 {"Cuenta eliminada"}
            4738 {"Cuenta modificada"}
        }
    }}, Message

if ($accountChanges) {
    Write-Host "    [!] $($accountChanges.Count) cambios detectados:" -ForegroundColor Yellow
    $accountChanges | Format-Table TimeCreated, Evento -AutoSize
    $accountChanges | Export-Csv "$OutputPath\cambios_cuenta.csv" -NoTypeInformation
} else {
    Write-Host "    [OK] No se detectaron cambios recientes" -ForegroundColor Green
}

Write-Host "`n[6/8] Equipos donde se autenticó recientemente..." -ForegroundColor Green

$computers = $successLogons | 
    Where-Object {$_.WorkstationName -and $_.WorkstationName -ne "-"} |
    Select-Object WorkstationName -Unique

if ($computers) {
    Write-Host "    Equipos únicos: $($computers.Count)" -ForegroundColor Gray
    $computers | ForEach-Object { 
        Write-Host "        - $($_.WorkstationName)" -ForegroundColor Gray 
    }
    $computers | Export-Csv "$OutputPath\equipos_usados.csv" -NoTypeInformation
}

Write-Host "`n[7/8] Acceso a recursos compartidos..." -ForegroundColor Green

$shareAccess = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=5140
    StartTime=(Get-Date).AddDays(-7)
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Properties[1].Value -eq "$env:USERDOMAIN\$Username"
} | Select-Object TimeCreated,
    @{Name="ShareName";Expression={$_.Properties[4].Value}},
    @{Name="SourceIP";Expression={$_.Properties[2].Value}}

if ($shareAccess) {
    Write-Host "    [!] $($shareAccess.Count) accesos a recursos compartidos" -ForegroundColor Yellow
    
    $shareAccess | Group-Object ShareName | 
        Sort-Object Count -Descending |
        Select-Object @{Name="Recurso";Expression={$_.Name}}, Count |
        Format-Table -AutoSize
    
    $shareAccess | Export-Csv "$OutputPath\acceso_recursos.csv" -NoTypeInformation
}

Write-Host "`n[8/8] Verificando sesiones activas..." -ForegroundColor Green

$activeSessions = quser 2>&1 | Select-String $Username

if ($activeSessions) {
    Write-Host "    [!] Usuario tiene sesiones activas:" -ForegroundColor Red
    $activeSessions | ForEach-Object {
        Write-Host "        $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "    [OK] No hay sesiones activas" -ForegroundColor Green
}

$summary = @"
=== RESUMEN DEL REPORTE ===
Usuario: $Username
Generado: $(Get-Date)
Ejecutado por: $env:USERNAME desde $env:COMPUTERNAME

INFORMACIÓN BÁSICA:
- Cuenta habilitada: $($user.Enabled)
- Cuenta bloqueada: $($user.LockedOut)
- Último logon: $($user.LastLogonDate)
- Contraseña cambiada: $($user.PasswordLastSet)
- Intentos fallidos: $($user.BadLogonCount)

ACTIVIDAD RECIENTE (7 días):
- Autenticaciones exitosas: $($successLogons.Count)
- Intentos fallidos: $($failedLogons.Count)
- IPs únicas usadas: $($uniqueIPs.Count)
- Equipos únicos: $($computers.Count)
- Accesos a recursos: $($shareAccess.Count)

GRUPOS DE SEGURIDAD:
- Total de grupos: $($groups.Count)
- Grupos privilegiados: $(if($isPrivileged){$isPrivileged.Count}else{0})

ALERTAS:
$(if($isPrivileged){"- [!] Usuario con privilegios elevados"}else{"- [OK] Sin privilegios elevados"})
$(if($user.LockedOut){"- [!] Cuenta bloqueada"}else{"- [OK] Cuenta no bloqueada"})
$(if($failedLogons.Count -gt 10){"- [!] Más de 10 intentos fallidos"}else{"- [OK] Intentos fallidos normales"})
$(if($activeSessions){"- [!] Sesiones activas detectadas"}else{"- [OK] Sin sesiones activas"})

ARCHIVOS GENERADOS:
- info_basica.json
- grupos.csv
- autenticaciones_exitosas.csv
$(if($failedLogons){"- intentos_fallidos.csv"}else{""})
$(if($accountChanges){"- cambios_cuenta.csv"}else{""})
$(if($computers){"- equipos_usados.csv"}else{""})
$(if($shareAccess){"- acceso_recursos.csv"}else{""})

RECOMENDACIONES:
$(if($isPrivileged){"- Revisar necesidad de privilegios elevados"}else{""})
$(if($user.PasswordNeverExpires){"- Cambiar política de expiración de contraseña"}else{""})
$(if($failedLogons.Count -gt 10){"- Investigar intentos fallidos excesivos"}else{""})
$(if($user.LockedOut){"- Desbloquear cuenta tras investigación"}else{""})
"@

$summary | Out-File "$OutputPath\RESUMEN.txt"

Stop-Transcript

Write-Host "`n=== REPORTE COMPLETADO ===" -ForegroundColor Cyan
Write-Host "Archivos guardados en: $OutputPath" -ForegroundColor Yellow

if ($isPrivileged -or $user.LockedOut -or $failedLogons.Count -gt 10) {
    Write-Host "`n[!] REVISAR ALERTAS EN RESUMEN.txt" -ForegroundColor Red
}

Write-Host "`nPresione Enter para salir..."
Read-Host
