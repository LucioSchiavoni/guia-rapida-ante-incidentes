#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Revert = $false
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = "C:\IncidentResponse\Aislamiento_$timestamp.log"

function Write-Log {
    param($Message)
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $entry
    Add-Content -Path $logPath -Value $entry
}

New-Item -ItemType Directory -Path "C:\IncidentResponse" -Force -ErrorAction SilentlyContinue | Out-Null

if ($Revert) {
    Write-Host "`n=== REVERTIR AISLAMIENTO ===" -ForegroundColor Green
    Write-Log "Iniciando reversión de aislamiento"
    
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Disabled"}
    
    if ($adapters.Count -eq 0) {
        Write-Host "No hay adaptadores deshabilitados" -ForegroundColor Yellow
        exit
    }
    
    Write-Host "`nAdaptadores deshabilitados encontrados:"
    $adapters | Format-Table Name, InterfaceDescription, MacAddress -AutoSize
    
    if (!$Force) {
        $confirm = Read-Host "`n¿Confirma habilitar todos los adaptadores? (SI/NO)"
        if ($confirm -ne "SI") {
            Write-Host "Operación cancelada" -ForegroundColor Yellow
            exit
        }
    }
    
    foreach ($adapter in $adapters) {
        Write-Log "Habilitando adaptador: $($adapter.Name)"
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false
        Write-Host "[OK] Habilitado: $($adapter.Name)" -ForegroundColor Green
    }
    
    Write-Host "`n=== ADAPTADORES HABILITADOS ===" -ForegroundColor Green
    Get-NetAdapter | Format-Table Name, Status, MacAddress -AutoSize
    Write-Log "Reversión completada"
    
} else {
    Write-Host "`n" -NoNewline
    Write-Host "================================================" -ForegroundColor Red -BackgroundColor White
    Write-Host "   AISLAMIENTO DE RED - RESPUESTA A INCIDENTE  " -ForegroundColor Red -BackgroundColor White
    Write-Host "================================================" -ForegroundColor Red -BackgroundColor White
    Write-Host ""
    
    Write-Host "ADVERTENCIA:" -ForegroundColor Yellow -NoNewline
    Write-Host " Este script desconectará el equipo de la red"
    Write-Host "Equipo: $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "Usuario: $env:USERNAME" -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Cyan
    
    Write-Log "Iniciando aislamiento de red"
    Write-Log "Equipo: $env:COMPUTERNAME"
    Write-Log "Usuario: $env:USERNAME"
    
    Write-Host "`nCapturando estado PRE-aislamiento..." -ForegroundColor Yellow
    $preState = Get-NetAdapter | Select-Object Name, Status, MacAddress, LinkSpeed
    $preState | Export-Csv "C:\IncidentResponse\adaptadores_pre_$timestamp.csv" -NoTypeInformation
    $preState | Format-Table -AutoSize
    Write-Log "Estado pre-aislamiento capturado"
    
    $activeAdapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    
    if ($activeAdapters.Count -eq 0) {
        Write-Host "`n[!] No hay adaptadores activos para aislar" -ForegroundColor Yellow
        Write-Log "No hay adaptadores activos"
        exit
    }
    
    if (!$Force) {
        Write-Host "`n¿CONFIRMA EL AISLAMIENTO DE RED? (escriba 'SI' en mayúsculas): " -ForegroundColor Red -NoNewline
        $confirmation = Read-Host
        
        if ($confirmation -ne "SI") {
            Write-Host "`nOperación CANCELADA por el usuario" -ForegroundColor Yellow
            Write-Log "Aislamiento cancelado por usuario"
            exit
        }
    }
    
    Write-Host "`n=== DESHABILITANDO ADAPTADORES ===" -ForegroundColor Red
    Write-Log "Iniciando deshabilitación de adaptadores"
    
    foreach ($adapter in $activeAdapters) {
        Write-Host "  [-] Deshabilitando: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Yellow
        Write-Log "Deshabilitando: $($adapter.Name) - MAC: $($adapter.MacAddress)"
        
        try {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
            Write-Host "      [OK] Deshabilitado exitosamente" -ForegroundColor Green
            Write-Log "Deshabilitado exitosamente: $($adapter.Name)"
        } catch {
            Write-Host "      [ERROR] No se pudo deshabilitar: $_" -ForegroundColor Red
            Write-Log "ERROR deshabilitando $($adapter.Name): $_"
        }
    }
    
    Start-Sleep -Seconds 2
    
    Write-Host "`n=== VERIFICACIÓN POST-AISLAMIENTO ===" -ForegroundColor Cyan
    $postState = Get-NetAdapter
    $postState | Format-Table Name, Status, MacAddress -AutoSize
    
    $postState | Export-Csv "C:\IncidentResponse\adaptadores_post_$timestamp.csv" -NoTypeInformation
    Write-Log "Estado post-aislamiento capturado"
    
    $stillActive = $postState | Where-Object {$_.Status -eq "Up"}
    if ($stillActive.Count -eq 0) {
        Write-Host "`n[OK] EQUIPO COMPLETAMENTE AISLADO" -ForegroundColor Green -BackgroundColor Black
        Write-Log "Aislamiento exitoso - Todos los adaptadores deshabilitados"
    } else {
        Write-Host "`n[!] ADVERTENCIA: Algunos adaptadores siguen activos:" -ForegroundColor Red
        $stillActive | Format-Table Name, Status -AutoSize
        Write-Log "ADVERTENCIA: Adaptadores aún activos: $($stillActive.Name -join ', ')"
    }
    
    Write-Host "`n=== EQUIPO AISLADO ===" -ForegroundColor Green
    Write-Host "Fecha/Hora: $(Get-Date)" -ForegroundColor Yellow
    Write-Host "Log guardado en: $logPath" -ForegroundColor Yellow
    
    Write-Host "`n=== PRÓXIMOS PASOS ===" -ForegroundColor Cyan
    Write-Host "1. Ejecutar script de captura de evidencia"
    Write-Host "2. Análisis forense del equipo"
    Write-Host "3. Documentar en formulario de incidente"
    
    Write-Host "`n=== PARA REVERTIR ===" -ForegroundColor Red
    Write-Host "Ejecute: .\02-Aislamiento-Red.ps1 -Revert"
    Write-Host "O manualmente: Get-NetAdapter | Enable-NetAdapter"
    
    Write-Log "Aislamiento completado"
}

Write-Host "`nPresione Enter para salir..."
Read-Host
