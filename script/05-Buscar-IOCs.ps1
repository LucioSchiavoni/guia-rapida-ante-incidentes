#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\IncidentResponse\IOC-Search_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    
    [Parameter(Mandatory=$false)]
    [string[]]$IPAddresses = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$FileHashes = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$Domains = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$FileNames = @()
)

$ErrorActionPreference = "Continue"

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
Start-Transcript -Path "$OutputPath\busqueda_iocs.log"

Write-Host "=== BÚSQUEDA DE INDICADORES DE COMPROMISO (IOCs) ===" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Equipo: $env:COMPUTERNAME`n" -ForegroundColor Yellow

$findings = @{
    IPMatches = @()
    HashMatches = @()
    DomainMatches = @()
    FileMatches = @()
}

if ($IPAddresses.Count -gt 0) {
    Write-Host "[*] Buscando conexiones a IPs sospechosas..." -ForegroundColor Green
    Write-Host "    IPs objetivo: $($IPAddresses -join ', ')" -ForegroundColor Gray
    
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
    
    foreach ($ip in $IPAddresses) {
        $matches = $connections | Where-Object {$_.RemoteAddress -eq $ip}
        
        if ($matches) {
            Write-Host "    [!] ENCONTRADO: Conexiones activas a $ip" -ForegroundColor Red
            
            foreach ($conn in $matches) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $finding = [PSCustomObject]@{
                    IP = $ip
                    LocalPort = $conn.LocalPort
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    ProcessID = $conn.OwningProcess
                    ProcessName = $proc.ProcessName
                    ProcessPath = $proc.Path
                    Timestamp = Get-Date
                }
                $findings.IPMatches += $finding
                Write-Host "        Proceso: $($proc.ProcessName) (PID: $($conn.OwningProcess))" -ForegroundColor Yellow
            }
        }
    }
    
    $findings.IPMatches | Export-Csv "$OutputPath\ip_matches.csv" -NoTypeInformation
    
    Write-Host "`n[*] Verificando DNS cache..." -ForegroundColor Green
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($ip in $IPAddresses) {
        $dnsMatches = $dnsCache | Where-Object {$_.Data -eq $ip}
        if ($dnsMatches) {
            Write-Host "    [!] IP $ip encontrada en DNS cache" -ForegroundColor Red
            $dnsMatches | Select-Object Name, Data, TimeToLive | 
                Export-Csv "$OutputPath\dns_ip_matches.csv" -NoTypeInformation -Append
        }
    }
}

if ($FileHashes.Count -gt 0) {
    Write-Host "`n[*] Buscando archivos por hash SHA256..." -ForegroundColor Green
    Write-Host "    Hashes objetivo: $($FileHashes.Count) hashes" -ForegroundColor Gray
    
    $searchPaths = @(
        "C:\Users\*\AppData\Local\Temp",
        "C:\Users\*\AppData\Roaming",
        "C:\Users\*\Downloads",
        "C:\Windows\Temp",
        "C:\ProgramData"
    )
    
    $allFiles = @()
    foreach ($path in $searchPaths) {
        Write-Host "    Escaneando: $path" -ForegroundColor Gray
        $files = Get-ChildItem -Path $path -Recurse -File -Force -ErrorAction SilentlyContinue
        $allFiles += $files
    }
    
    Write-Host "    Calculando hashes de $($allFiles.Count) archivos..." -ForegroundColor Gray
    
    $counter = 0
    foreach ($file in $allFiles) {
        $counter++
        if ($counter % 100 -eq 0) {
            Write-Host "    Progreso: $counter/$($allFiles.Count)" -ForegroundColor DarkGray
        }
        
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        
        if ($hash -and $FileHashes -contains $hash) {
            Write-Host "    [!] HASH ENCONTRADO: $($file.FullName)" -ForegroundColor Red
            
            $finding = [PSCustomObject]@{
                Hash = $hash
                FilePath = $file.FullName
                FileName = $file.Name
                Size = $file.Length
                CreationTime = $file.CreationTime
                LastWriteTime = $file.LastWriteTime
                LastAccessTime = $file.LastAccessTime
                Timestamp = Get-Date
            }
            $findings.HashMatches += $finding
        }
    }
    
    $findings.HashMatches | Export-Csv "$OutputPath\hash_matches.csv" -NoTypeInformation
}

if ($Domains.Count -gt 0) {
    Write-Host "`n[*] Buscando dominios sospechosos en DNS cache..." -ForegroundColor Green
    Write-Host "    Dominios objetivo: $($Domains -join ', ')" -ForegroundColor Gray
    
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    
    foreach ($domain in $Domains) {
        $matches = $dnsCache | Where-Object {$_.Name -like "*$domain*"}
        
        if ($matches) {
            Write-Host "    [!] ENCONTRADO: $domain en DNS cache" -ForegroundColor Red
            
            foreach ($match in $matches) {
                $finding = [PSCustomObject]@{
                    Domain = $domain
                    FullName = $match.Name
                    Type = $match.Type
                    Data = $match.Data
                    TimeToLive = $match.TimeToLive
                    Timestamp = Get-Date
                }
                $findings.DomainMatches += $finding
            }
        }
    }
    
    $findings.DomainMatches | Export-Csv "$OutputPath\domain_matches.csv" -NoTypeInformation
}

if ($FileNames.Count -gt 0) {
    Write-Host "`n[*] Buscando archivos por nombre..." -ForegroundColor Green
    Write-Host "    Nombres objetivo: $($FileNames -join ', ')" -ForegroundColor Gray
    
    $searchPaths = @(
        "C:\Users",
        "C:\Windows\Temp",
        "C:\ProgramData"
    )
    
    foreach ($fileName in $FileNames) {
        foreach ($path in $searchPaths) {
            $matches = Get-ChildItem -Path $path -Recurse -File -Filter $fileName -Force -ErrorAction SilentlyContinue
            
            foreach ($match in $matches) {
                Write-Host "    [!] ENCONTRADO: $($match.FullName)" -ForegroundColor Red
                
                $hash = (Get-FileHash -Path $match.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                
                $finding = [PSCustomObject]@{
                    SearchTerm = $fileName
                    FilePath = $match.FullName
                    Size = $match.Length
                    CreationTime = $match.CreationTime
                    LastWriteTime = $match.LastWriteTime
                    Hash = $hash
                    Timestamp = Get-Date
                }
                $findings.FileMatches += $finding
            }
        }
    }
    
    $findings.FileMatches | Export-Csv "$OutputPath\file_matches.csv" -NoTypeInformation
}

Write-Host "`n[*] Verificando procesos en ejecución..." -ForegroundColor Green
$suspiciousProcesses = Get-Process | Where-Object {
    $_.Path -and (
        $_.Path -like "*\Temp\*" -or
        $_.Path -like "*\AppData\Local\Temp\*" -or
        $_.Company -eq $null
    )
} | Select-Object ProcessName, Id, Path, StartTime

if ($suspiciousProcesses) {
    Write-Host "    [!] Procesos sospechosos detectados:" -ForegroundColor Red
    $suspiciousProcesses | ForEach-Object {
        Write-Host "        $($_.ProcessName) - $($_.Path)" -ForegroundColor Yellow
    }
    $suspiciousProcesses | Export-Csv "$OutputPath\procesos_sospechosos.csv" -NoTypeInformation
}

$summary = @"
=== RESUMEN DE BÚSQUEDA DE IOCs ===
Timestamp: $(Get-Date)
Equipo: $env:COMPUTERNAME

RESULTADOS:
- IPs sospechosas encontradas: $($findings.IPMatches.Count)
- Hashes coincidentes: $($findings.HashMatches.Count)
- Dominios encontrados: $($findings.DomainMatches.Count)
- Archivos encontrados: $($findings.FileMatches.Count)
- Procesos sospechosos: $($suspiciousProcesses.Count)

ARCHIVOS GENERADOS:
"@

if ($findings.IPMatches.Count -gt 0) { $summary += "`n- ip_matches.csv" }
if ($findings.HashMatches.Count -gt 0) { $summary += "`n- hash_matches.csv" }
if ($findings.DomainMatches.Count -gt 0) { $summary += "`n- domain_matches.csv" }
if ($findings.FileMatches.Count -gt 0) { $summary += "`n- file_matches.csv" }
if ($suspiciousProcesses.Count -gt 0) { $summary += "`n- procesos_sospechosos.csv" }

$summary | Out-File "$OutputPath\RESUMEN.txt"

Stop-Transcript

Write-Host "`n=== BÚSQUEDA COMPLETADA ===" -ForegroundColor Cyan
Write-Host "Resultados guardados en: $OutputPath" -ForegroundColor Yellow

if ($findings.IPMatches.Count -gt 0 -or $findings.HashMatches.Count -gt 0 -or 
    $findings.DomainMatches.Count -gt 0 -or $findings.FileMatches.Count -gt 0) {
    Write-Host "`n[!] SE ENCONTRARON COINCIDENCIAS - REVISAR INMEDIATAMENTE" -ForegroundColor Red
} else {
    Write-Host "`n[OK] No se encontraron coincidencias con los IOCs proporcionados" -ForegroundColor Green
}

Write-Host "`nPresione Enter para salir..."
Read-Host
