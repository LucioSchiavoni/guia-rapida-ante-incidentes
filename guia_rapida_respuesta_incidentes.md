# GUÍA RÁPIDA DE RESPUESTA A INCIDENTES
## Cheat Sheet para CISO y Equipo de Seguridad

---

## PRIMEROS PASOS (Primeros 5 minutos)

```
1. NO APAGAR EQUIPOS (evidencia en memoria)
2. DOCUMENTAR TODO
3. NOTIFICAR A CISO si severidad ≥ ALTA
4. COMENZAR CONTENCIÓN
```

---

## CLASIFICACIÓN RÁPIDA DE SEVERIDAD

| Indicador | CRÍTICO | ALTO | MEDIO | BAJO |
|-----------|---------|------|-------|------|
| Sistemas afectados | >10 o críticos | 5-10 | 2-4 | 1 |
| Datos comprometidos | Sí, sensibles | Posible | Poco probable | No |
| Propagación | Activa | Contenida | Limitada | Sin propagación |
| Tiempo de respuesta | INMEDIATO | <1h | <4h | <24h |

---

##  COMANDOS FORENSES ESENCIALES

### Windows - Información Básica
```powershell
# Información del sistema
systeminfo
hostname
whoami
ipconfig /all

# Procesos sospechosos
Get-Process | Where-Object {$_.Company -eq $null} | Select Name, Id, Path
tasklist /v
wmic process list full

# Conexiones de red
netstat -ano
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}

# Usuarios locales
net user
net localgroup administrators
Get-LocalUser | Where-Object {$_.Enabled -eq $True}

# Servicios en ejecución
Get-Service | Where-Object {$_.Status -eq "Running" -and $_.StartType -ne "Automatic"}
sc query type= service state= all

# Tareas programadas sospechosas
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select TaskName, TaskPath
schtasks /query /fo LIST /v

# Autoruns
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Archivos recientes en Temp
Get-ChildItem C:\Users\*\AppData\Local\Temp -Recurse -Force | 
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)}

# DNS Cache
ipconfig /displaydns
Get-DnsClientCache

# Eventos críticos de seguridad
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625,4672,4720} -MaxEvents 50
```

### Active Directory - Auditoría
```powershell
# Último inicio de sesión de usuario
Get-ADUser -Identity <username> -Properties LastLogon, LastLogonDate, PasswordLastSet

# Cambios recientes en AD
Get-ADReplicationAttributeMetadata -Object "<DN>" -Server <DC> | 
  Where-Object {$_.LastOriginatingChangeTime -gt (Get-Date).AddDays(-7)}

# Usuarios bloqueados
Search-ADAccount -LockedOut

# Intentos de autenticación fallidos
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 100

# Grupos de alto privilegio
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive

# Cuentas deshabilitadas recientemente
Search-ADAccount -AccountDisabled | 
  Where-Object {$_.Modified -gt (Get-Date).AddDays(-7)}
```

---

## CONTENCIÓN RÁPIDA

### Aislar Equipo en FortiGate
```
# Vía CLI
config user quarantine
    edit <mac-address>
        set quarantine enable
    next
end

# Verificar
diagnose user quarantine list
```

### Bloquear Usuario en AD
```powershell
# Deshabilitar cuenta
Disable-ADAccount -Identity <username>

# Cerrar sesiones activas
quser /server:<servidor>
logoff <session_id> /server:<servidor>

# Forzar cambio de contraseña
Set-ADUser -Identity <username> -ChangePasswordAtLogon $true

# Revocar tickets Kerberos
klist purge -li 0x3e7
```

### Bloquear IP/Dominio en FortiGate
```
# Crear objeto de dirección
config firewall address
    edit "blocked-host-<nombre>"
        set subnet <IP>/32
    next
end

# Aplicar en política (deny)
config firewall policy
    edit <policy-id>
        set action deny
        set srcaddr "blocked-host-<nombre>"
        set dstintf "any"
        set schedule "always"
        set service "ALL"
    next
end
```

### Bloquear Remitente en Zimbra
```bash
# Agregar a blacklist
zmprov ma postmaster@dominio.gob zimbraMailAddressBlacklist <email-malicioso>

# Eliminar correos de todos los buzones
for mailbox in $(zmprov getAllMailboxes); do
    zmmailbox -z -m $mailbox search -t message "from:<email-malicioso>" | 
    grep "^Id:" | awk '{print $2}' | 
    while read msgid; do
        zmmailbox -z -m $mailbox deleteMessage $msgid
    done
done
```

---

## QUERIES ÚTILES EN GRAYLOG

### Intentos de autenticación fallidos
```
event_id:4625 AND _exists_:target_user_name
```

### Autenticación exitosa fuera de horario
```
event_id:4624 AND timestamp:[20:00 TO 06:00] AND NOT source_ip:172.24.0.0/16
```

### Ejecución de PowerShell sospechoso
```
(powershell OR pwsh) AND (encoded OR bypass OR hidden OR downloadstring)
```

### Movimiento lateral (Pass-the-Hash)
```
event_id:4648 AND logon_type:3 AND NOT target_server_name:<servidor-autorizado>
```

### Acceso a recursos compartidos
```
event_id:5140 AND share_name:* AND NOT share_name:IPC$
```

### Cambios en grupos de alto privilegio
```
event_id:4728 OR event_id:4732 OR event_id:4756
```

### Creación de cuentas
```
event_id:4720
```

### Conexiones salientes sospechosas
```
dst_port:(4444 OR 4443 OR 8443 OR 31337) AND NOT dst_ip:172.24.0.0/16
```

### Tráfico DNS inusual
```
dns_query_type:TXT OR (dns_query_length:>100)
```

---

## ANÁLISIS DE PHISHING

### Encabezados críticos a revisar
```
Return-Path:              → Email real del remitente
Authentication-Results:   → SPF, DKIM, DMARC
X-Originating-IP:        → IP de origen
Received:                → Ruta completa del correo
Message-ID:              → Identificador único
X-Mailer:                → Cliente de correo usado
```

### Verificar URL sin hacer clic
```bash
# Usar curl con headers
curl -I <URL>

# O usar online:
# - urlscan.io
# - virustotal.com
# - hybrid-analysis.com
```

### Extraer URLs de correo
```bash
# Linux/WSL
grep -Eo 'https?://[^ ]+' email.eml

# PowerShell
Select-String -Path email.eml -Pattern 'https?://[^\s]+' -AllMatches
```

---

## INDICADORES DE COMPROMISO (IOCs)

### Archivos sospechosos
```
Ubicaciones comunes:
- C:\Users\<user>\AppData\Local\Temp
- C:\Users\<user>\AppData\Roaming
- C:\Windows\Temp
- C:\ProgramData
- C:\Users\Public

Extensiones dobles:
- .pdf.exe
- .doc.exe
- .jpg.exe

Nombres aleatorios:
- asdfjkl.exe
- temp12345.exe
- update_v123.exe
```

### Procesos sospechosos
```
Legítimos usados por malware:
- powershell.exe (con parámetros encoded/hidden)
- cmd.exe (ejecutando scripts)
- wscript.exe / cscript.exe
- rundll32.exe
- regsvr32.exe
- mshta.exe

Ubicaciones inusuales:
- Ejecutándose desde Temp
- Ejecutándose desde AppData
- Sin firma digital
```

### Persistencia común
```
Registry Run Keys:
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

Startup Folder:
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup

Scheduled Tasks:
C:\Windows\System32\Tasks

Services:
HKLM\System\CurrentControlSet\Services

WMI Event Subscriptions:
Get-WmiObject -Namespace root\subscription -Class __EventFilter
```

---

## CONTACTOS DE EMERGENCIA RÁPIDOS

```
CISO:                [Tu número]
Director TI:         [Número]
Soporte 24/7:        [Número]

Antivirus Soporte:   [Número]
ISP Emergencias:     [Número]
Consultoría Forense: [Número]
```

---

## DECISIONES RÁPIDAS

### ¿Aislar o no aislar?
```
AISLAR INMEDIATAMENTE si:
✓ Ransomware confirmado
✓ Propagación activa
✓ Conexión a C&C activa
✓ Exfiltración en progreso
✓ Servidor crítico comprometido

NO AISLAR (aún) si:
✓ Solo detección de antivirus contenida
✓ Necesitas observar comportamiento
✓ Sistema crítico que no puede caerse
  (coordinar ventana de mantenimiento)
```

### ¿Limpieza o Reimagen?
```
LIMPIEZA:
- Detección única
- Malware conocido y simple
- Sistema no crítico
- Usuario puede quedarse sin equipo

REIMAGEN:
- Múltiples detecciones
- Comportamiento persistente
- Ransomware (aunque esté contenido)
- Rootkit sospechado
- Sistema crítico comprometido
- Después de 2 intentos de limpieza fallidos
```

### ¿Notificar o no notificar?
```
NOTIFICAR SIEMPRE:
✓ Severidad CRÍTICO/ALTO
✓ Datos sensibles involucrados
✓ Múltiples usuarios/sistemas
✓ Posible impacto legal
✓ Requiere recursos adicionales

NOTIFICAR AL CIERRE:
- Incidentes BAJO/MEDIO rutinarios
- Detecciones contenidas
- Falsos positivos confirmados
```

---

## HERRAMIENTAS RÁPIDAS

### Análisis de hash
```bash
# Calcular SHA256
certutil -hashfile <archivo> SHA256
Get-FileHash -Path <archivo> -Algorithm SHA256

# Verificar en VirusTotal
# https://www.virustotal.com
```

### Captura de memoria
```powershell
# Windows (requiere privilegios)
# Usar herramientas como:
# - Magnet RAM Capture
# - DumpIt
# - FTK Imager

# Verificar procesos en memoria
Get-Process | Where-Object {$_.Path} | Select Name, Path
```

### Verificar integridad de archivos
```powershell
# SFC para archivos de sistema
sfc /scannow

# DISM para imagen de Windows
DISM /Online /Cleanup-Image /CheckHealth
```

---

## PLANTILLA DE COMUNICACIÓN URGENTE

```
ASUNTO: [URGENTE] Incidente de Seguridad - [TIPO] - [SEVERIDAD]

Incidente ID: INC-SEC-YYYYMMDD-###
Severidad: [CRÍTICO/ALTO/MEDIO/BAJO]
Detectado: [DD/MM/YYYY HH:MM]

SITUACIÓN:
[Breve descripción del incidente]

IMPACTO:
- Sistemas afectados: [Lista]
- Usuarios afectados: [Número]
- Servicios interrumpidos: [Lista]

ACCIONES TOMADAS:
- [Timestamp] [Acción]
- [Timestamp] [Acción]

ESTADO ACTUAL:
[Contenido/En investigación/Resuelto]

PRÓXIMOS PASOS:
1. [Acción]
2. [Acción]

CONTACTO:
[Nombre] - [Email] - [Tel]
```

---

## ERRORES COMUNES A EVITAR

```
 - Apagar el equipo sin recolectar evidencia
 - No documentar acciones tomadas
 - Modificar archivos sin hacer copia
 - Asumir que está "limpio" después de un escaneo
 - No cambiar credenciales después de compromiso
 - Olvidar revisar otros sistemas del mismo usuario
 - No bloquear IOCs en el perímetro
 - Restaurar desde backup sin verificar
 - No comunicar a stakeholders
 - Dar información técnica a atacantes (en phishing)
```

---

## RECURSOS ÚTILES

### Online
- VirusTotal: https://www.virustotal.com
- URLScan: https://urlscan.io
- Hybrid Analysis: https://www.hybrid-analysis.com
- AbuseIPDB: https://www.abuseipdb.com
- Have I Been Pwned: https://haveibeenpwned.com

### Herramientas
- Sysinternals Suite
- Autoruns
- Process Explorer
- Process Monitor
- TCPView

### Referencias
- MITRE ATT&CK: https://attack.mitre.org
- NIST Cybersecurity Framework
- SANS Incident Response Guide

---

## CHECKLIST MÍNIMO

```
ANTES DE CERRAR UN INCIDENTE:
☐ Amenaza erradicada confirmada
☐ Sistemas restaurados y verificados
☐ Credenciales cambiadas
☐ IOCs bloqueados en perímetro
☐ Monitoreo post-incidente configurado
☐ Documentación completa
☐ Stakeholders notificados
☐ Lecciones aprendidas documentadas
☐ Controles actualizados
☐ Usuario/equipo puede operar normalmente
```

---

*Mantener esta guía accesible en todo momento*  
*Actualizar después de cada incidente significativo*  
*Compartir con todo el equipo de seguridad*

**Última actualización:** Diciembre 2025
