# PROCEDIMIENTO DE RESPUESTA A INCIDENTES DE SEGURIDAD

**Documento:** PRO-SEC-001  
**Versión:** 1.0  
**Fecha:** Diciembre 2025  
**Responsable:** RSI  
**Clasificación:** Uso Interno

---

## 1. OBJETIVO Y ALCANCE

### 1.1 Objetivo
Establecer procedimientos estandarizados para la detección, respuesta, contención y remediación de incidentes de seguridad relacionados con malware, phishing y actividades maliciosas en la infraestructura institucional.

### 1.2 Alcance
Este procedimiento aplica a:
- Todos los equipos conectados a la red institucional
- Cuentas de correo institucionales (Zimbra)
- Sistemas críticos y servidores
- Usuarios finales y personal de TI

---

## 2. CLASIFICACIÓN DE INCIDENTES

### 2.1 Severidad

| Nivel | Descripción | Tiempo de Respuesta | Ejemplos |
|-------|-------------|---------------------|----------|
| **CRÍTICO** | Afectación masiva o sistemas críticos | Inmediato (< 15 min) | Ransomware, compromiso de DC/AD, exfiltración de datos |
| **ALTO** | Afectación significativa | < 1 hora | Malware con propagación activa, phishing masivo exitoso |
| **MEDIO** | Impacto limitado | < 4 horas | Malware aislado, phishing dirigido detectado |
| **BAJO** | Mínimo impacto | < 24 horas | Intentos de phishing bloqueados, detección de antivirus rutinaria |

### 2.2 Tipos de Incidentes

**A. MALWARE**
- Virus, troyanos, spyware
- Ransomware
- Rootkits
- Mineros de criptomonedas
- Backdoors

**B. PHISHING**
- Correos suplantando identidad institucional
- Enlaces maliciosos
- Adjuntos infectados
- Compromiso de credenciales

**C. ACTIVIDADES MALICIOSAS**
- Comandos sospechosos en sistemas
- Conexiones a C&C (Command and Control)
- Movimiento lateral no autorizado
- Escalación de privilegios
- Modificación de archivos de sistema

---

## 3. FLUJO GENERAL DE RESPUESTA

```
┌─────────────────┐
│   DETECCIÓN     │
│  - Antivirus    │
│  - Usuario      │
│  - Monitoreo    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  CLASIFICACIÓN  │
│   Y REGISTRO    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   CONTENCIÓN    │
│    INMEDIATA    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  INVESTIGACIÓN  │
│   Y ANÁLISIS    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ERRADICACIÓN   │
│ Y RECUPERACIÓN  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ DOCUMENTACIÓN   │
│  Y LECCIONES    │
└─────────────────┘
```

---

## 4. PROCEDIMIENTOS ESPECÍFICOS

## 4.1 RESPUESTA A DETECCIÓN DE ANTIVIRUS

### Cuando el antivirus detecta amenaza en un equipo:

#### PASO 1: Evaluación Inicial (< 5 minutos)
1. **Identificar el equipo afectado**
   - Nombre del equipo
   - Usuario actual
   - Ubicación física (piso/oficina)
   - Dirección IP y MAC

2. **Verificar la detección**
   - Revisar consola del antivirus
   - Verificar hash del archivo en VirusTotal
   - Confirmar si es falso positivo o amenaza real

3. **Determinar severidad**
   - ¿Está contenido o ejecutándose?
   - ¿Qué tipo de malware es?
   - ¿Afecta sistemas críticos?

#### PASO 2: Contención Inmediata (< 10 minutos)

**SI ES MALWARE ACTIVO O NO CONTENIDO:**

```bash
# 1. Aislar el equipo de la red
# Desde FortiGate:
config user quarantine
    edit <mac-address>
        set quarantine enable
    next
end

# 2. Bloquear la IP en el firewall si es necesario
config firewall address
    edit "infected-host-<IP>"
        set type ipmask
        set subnet <IP>/32
    next
end
```

**Acciones en el equipo:**
1. NO apagar el equipo (se pierde evidencia en memoria)
2. Desconectar cable de red físicamente
3. Deshabilitar WiFi si está presente
4. Tomar foto de la pantalla si hay mensajes visibles

**SI ESTÁ CONTENIDO POR ANTIVIRUS:**
1. Verificar que el archivo está en cuarentena
2. Marcar el equipo para análisis posterior
3. Continuar con investigación sin aislar

#### PASO 3: Recolección de Evidencia (< 30 minutos)

**Información del sistema:**
```powershell
# Ejecutar en PowerShell con privilegios administrativos

# 1. Procesos en ejecución
Get-Process | Select-Object Name, Id, Path, StartTime | Out-File C:\temp\processes.txt

# 2. Conexiones de red activas
netstat -ano > C:\temp\network_connections.txt

# 3. Tareas programadas sospechosas
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Out-File C:\temp\scheduled_tasks.txt

# 4. Servicios no estándar
Get-Service | Where-Object {$_.Status -eq "Running"} | Out-File C:\temp\services.txt

# 5. Archivos recientemente modificados en ubicaciones críticas
Get-ChildItem -Path C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | 
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | 
    Out-File C:\temp\recent_system_files.txt

# 6. Entradas de registro de autoarranque
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run | 
    Out-File C:\temp\registry_run.txt
```

**Logs a recolectar:**
1. Logs del antivirus (últimas 24 horas)
2. Logs de eventos de Windows:
   - Security
   - System
   - Application
3. Consultar Graylog para:
   - Conexiones de red del equipo
   - Intentos de autenticación
   - Actividad en AD relacionada con el usuario

**Query Graylog:**
```
(computer_name:"<NOMBRE-EQUIPO>" OR source_ip:"<IP-EQUIPO>") 
AND timestamp:[now-24h TO now]
```

#### PASO 4: Análisis Forense

**Indicadores de Compromiso (IOCs) a buscar:**

1. **Archivos sospechosos:**
   - Extensiones dobles (ej: documento.pdf.exe)
   - Ubicaciones inusuales (Temp, AppData, carpeta de usuario)
   - Nombres aleatorios o caracteres raros

2. **Comportamientos:**
   - Conexiones a IPs extranjeras
   - Múltiples intentos de conexión fallidos
   - Modificación de archivos de sistema
   - Creación de cuentas de usuario nuevas

3. **Persistencia:**
   - Claves de registro modificadas
   - Tareas programadas no autorizadas
   - Servicios desconocidos
   - Scripts de inicio

#### PASO 5: Erradicación

**Opción A: Limpieza (para infecciones leves)**
1. Ejecutar escaneo completo con antivirus actualizado
2. Utilizar herramientas especializadas si es necesario:
   - Malwarebytes
   - HitmanPro
   - ESET Online Scanner
3. Eliminar entradas de persistencia manualmente
4. Verificar que no quedan rastros

**Opción B: Reimagen (RECOMENDADO para severidad ALTA/CRÍTICA)**
1. Respaldar datos del usuario (después de escanear)
2. Realizar reimagen completa del sistema
3. Reinstalar aplicaciones desde fuentes confiables
4. Restaurar datos escaneados

#### PASO 6: Recuperación

1. **Cambio de credenciales:**
   ```powershell
   # Forzar cambio de contraseña del usuario en AD
   Set-ADUser -Identity <username> -ChangePasswordAtLogon $true
   
   # Revocar sesiones activas de Zimbra
   # (Realizar desde consola de administración Zimbra)
   ```

2. **Restablecer conexiones:**
   - Remover el equipo del aislamiento en FortiGate
   - Verificar conectividad
   - Probar acceso a recursos

3. **Monitoreo post-incidente:**
   - Seguimiento en Graylog durante 7 días
   - Verificación diaria de comportamiento del equipo
   - Escaneos programados adicionales

---

## 4.2 RESPUESTA A PHISHING

### Cuando se reporta correo de phishing:

#### PASO 1: Validación del Reporte (< 10 minutos)

1. **Solicitar al usuario:**
   - No hacer clic en enlaces
   - No descargar adjuntos
   - No responder al correo
   - Reenviar el correo como adjunto a seguridad@institucion.gob

2. **Análisis inicial:**
   - Verificar encabezados completos del correo
   - Identificar remitente real (campo Return-Path)
   - Analizar enlaces (usar herramientas como urlscan.io)
   - Verificar adjuntos en sandbox

**Análisis de encabezados en Zimbra:**
```
Authentication-Results: → Revisar SPF, DKIM, DMARC
Received: → Verificar ruta del correo
Return-Path: → Correo real del remitente
X-Originating-IP: → IP de origen
```

#### PASO 2: Determinar Alcance

**Consulta en Zimbra para ver afectación:**
```bash
# Buscar correos similares en el servidor
zmmailbox -z -m admin search -t message 'from:<email-sospechoso>'

# Ver cuántos usuarios lo recibieron
zmprov getAllMailboxes | while read user; do
    zmmailbox -z -m $user search "from:<email-sospechoso>" | grep -c "^Id:"
done
```

**Consultar en Graylog:**
```
application:"zimbra" AND from_address:"<email-sospechoso>"
```

#### PASO 3: Contención

**Clasificación de amenaza:**

| Acción del usuario | Severidad | Pasos siguientes |
|-------------------|-----------|------------------|
| Solo recibió, no abrió | BAJO | Eliminar correo, alertar usuario |
| Abrió, no hizo clic | MEDIO | Eliminar correo, monitoreo |
| Hizo clic en enlace | ALTO | Cambio credenciales, análisis equipo |
| Descargó y ejecutó adjunto | CRÍTICO | Aislamiento equipo, procedimiento malware |
| Ingresó credenciales | CRÍTICO | Bloqueo cuenta inmediato, auditoría |

**Acciones de contención inmediata:**

**A. Si usuario ingresó credenciales:**
```powershell
# 1. Bloquear cuenta de AD inmediatamente
Disable-ADAccount -Identity <username>

# 2. Cerrar todas las sesiones activas

# 3. Verificar accesos recientes
Get-ADUser -Identity <username> -Properties LastLogon, LastLogonDate

# 4. Revisar actividad en Graylog
```

**B. Bloquear remitente en Zimbra:**
```bash
# Agregar a lista negra
zmprov ma postmaster@dominio.gob zimbraMailAddressBlacklist <email-malicioso>

# Crear filtro global
zmprov mc default zimbraMailSieveScript '
require ["fileinto", "reject"];
if address :is "from" "<email-malicioso>" {
    discard;
    stop;
}
'
```

**C. Bloquear dominio/IP en FortiGate:**
```
config emailfilter profile
    edit "default"
        config black-list
            edit 1
                set email-pattern "*@<dominio-malicioso>"
            next
        end
    next
end
```

#### PASO 4: Eliminación Masiva

**Si múltiples usuarios afectados:**
```bash
# Script para eliminar correos de phishing de todos los buzones
#!/bin/bash

SEARCH_TERM="from:<email-sospechoso> OR subject:<asunto-sospechoso>"

zmprov getAllMailboxes | while read mailbox; do
    echo "Procesando: $mailbox"
    
    # Buscar y eliminar correos
    zmmailbox -z -m $mailbox search -t message "$SEARCH_TERM" | 
    grep "^Id:" | 
    awk '{print $2}' | 
    while read msgid; do
        zmmailbox -z -m $mailbox deleteMessage $msgid
        echo "  - Eliminado mensaje ID: $msgid"
    done
done
```

#### PASO 5: Comunicación

**Plantilla de alerta a usuarios:**

```
ASUNTO: [ALERTA SEGURIDAD] Campaña de Phishing Detectada

Estimado/a funcionario/a:

Se ha detectado una campaña de phishing dirigida a nuestra institución.

CARACTERÍSTICAS DEL CORREO MALICIOSO:
- Remitente: [especificar]
- Asunto: [especificar]
- Contenido: [breve descripción]

¿QUÉ HACER SI LO RECIBIÓ?
1. NO hacer clic en enlaces
2. NO descargar adjuntos
3. NO responder al correo
4. Reportar a: grp_seguridad@mec.gub.uy
5. Eliminar el correo

¿QUÉ HACER SI YA HIZO CLIC O INGRESÓ CREDENCIALES?
- Contactar INMEDIATAMENTE a la Oficina de Seguridad Informática
- Teléfono: Interno - 01336
- Email: grp_seguridad@mec.gub.uy

El correo malicioso ha sido bloqueado y eliminado de los servidores.

Atentamente,
Oficina de Seguridad Informática
```

---

## 4.3 RESPUESTA A ACTIVIDAD MALICIOSA DETECTADA

### Cuando se detecta comportamiento sospechoso:

#### PASO 1: Validación de Alerta

**Fuentes de detección:**
1. Alertas de Graylog
2. Logs de FortiGate (IPS/AV)
3. Reportes de usuarios
4. Monitoreo de Active Directory

**Verificar indicadores:**
```
# Consultas típicas en Graylog

# 1. Múltiples intentos de autenticación fallidos
event_id:4625 AND source_ip:<IP> AND _exists_:target_user_name

# 2. Ejecución de comandos sospechosos
(powershell OR cmd OR wscript) AND (encoded OR bypass OR hidden)

# 3. Accesos fuera de horario
timestamp:[<hora-inicio> TO <hora-fin>] AND event_id:4624

# 4. Movimiento lateral
event_id:4648 AND target_server_name:* AND NOT target_server_name:<servidor-autorizado>
```

#### PASO 2: Análisis de Impacto

**Preguntas clave:**
- ¿Qué sistema/usuario está afectado?
- ¿Cuándo comenzó la actividad?
- ¿Se ha propagado?
- ¿Qué datos han sido accedidos?
- ¿Hay exfiltración de información?

**Timeline de eventos:**
```
[Momento 0] Primera actividad sospechosa detectada
[+5 min]    Acceso a recurso sensible
[+10 min]   Conexión externa sospechosa
[+15 min]   Detección actual
```

#### PASO 3: Contención Según Tipo

**A. Compromiso de Cuenta:**
```powershell
# Bloquear cuenta
Disable-ADAccount -Identity <username>

# Listar sesiones activas
quser /server:<servidor>

# Cerrar sesiones
logoff <session_id> /server:<servidor>

# Verificar membresía de grupos
Get-ADPrincipalGroupMembership -Identity <username>

# Auditar cambios recientes en AD
Get-ADReplicationAttributeMetadata -Object "<DN-usuario>" -Server <DC>
```

**B. Compromiso de Servidor:**
1. Aislar servidor de red (si no es crítico)
2. Tomar snapshot de memoria con herramientas forenses
3. Recolectar logs antes de cualquier acción
4. Coordinar con responsables de servicio

**C. Conexión a C&C:**
```
# Bloquear IP/dominio en FortiGate
config firewall address
    edit "c2-server-<nombre>"
        set type fqdn
        set fqdn "<dominio-malicioso>"
    next
end

config firewall policy
    edit <policy-id>
        set action deny
        set srcaddr "all"
        set dstaddr "c2-server-<nombre>"
        set schedule "always"
        set service "ALL"
    next
end
```

#### PASO 4: Investigación Profunda

**Análisis forense a realizar:**

1. **Memoria volátil:**
   - Procesos inyectados
   - Conexiones de red ocultas
   - Módulos cargados no firmados

2. **Persistencia:**
   - Registro de Windows
   - Tareas programadas
   - Servicios
   - WMI subscriptions
   - Scripts de inicio

3. **Lateral movement:**
   - PsExec, WMI, PowerShell remoting
   - Pass-the-hash/ticket
   - Accesos SMB/RDP inusuales

4. **Data exfiltration:**
   - Transferencias de archivos grandes
   - Conexiones a servicios de almacenamiento cloud
   - Uso de protocolos de túneling

**Herramientas recomendadas:**
- Sysinternals Suite (ProcMon, Autoruns, TCPView)
- PowerShell scripts de auditoría
- Velociraptor para recolección de evidencia
- CrowdResponse para análisis rápido

---

## 5. COMUNICACIÓN Y ESCALAMIENTO

### 5.1 Matriz de Comunicación

| Severidad | Notificar a | Tiempo | Medio |
|-----------|-------------|--------|-------|
| CRÍTICO | CISO, Director TI, Director General | Inmediato | Llamada telefónica + email |
| ALTO | CISO, Director TI | < 30 min | Email + Mensaje |
| MEDIO | CISO, Supervisor TI | < 2 horas | Email |
| BAJO | Equipo de seguridad | < 24 horas | Registro en sistema |

### 5.2 Plantilla de Reporte de Incidente

```
REPORTE DE INCIDENTE DE SEGURIDAD
================================

INFORMACIÓN GENERAL
------------------
ID Incidente:    INC-SEC-[YYYYMMDD]-[###]
Fecha/Hora:      [DD/MM/YYYY HH:MM]
Detectado por:   [Nombre/Sistema]
Clasificación:   [CRÍTICO/ALTO/MEDIO/BAJO]
Tipo:            [MALWARE/PHISHING/ACTIVIDAD MALICIOSA]

DESCRIPCIÓN
-----------
[Descripción clara y concisa del incidente]

SISTEMAS/USUARIOS AFECTADOS
---------------------------
- Equipo(s):     [Lista]
- Usuario(s):    [Lista]
- Servicios:     [Lista]
- Datos:         [Descripción]

ACCIONES TOMADAS
----------------
[Timestamp] - [Acción realizada]
[Timestamp] - [Acción realizada]

ESTADO ACTUAL
-------------
[Contenido/En investigación/Resuelto]

IOCs IDENTIFICADOS
------------------
Hashes:          [Lista]
IPs:             [Lista]
Dominios:        [Lista]
Archivos:        [Lista]

PRÓXIMOS PASOS
--------------
1. [Acción pendiente]
2. [Acción pendiente]

RECOMENDACIONES
---------------
[Mejoras sugeridas para prevenir recurrencia]

RESPONSABLE DEL REPORTE
-----------------------
Nombre:          [Nombre]
Fecha:           [DD/MM/YYYY]
```

---

## 6. POST-INCIDENTE

### 6.1 Lecciones Aprendidas

**Reunión post-mortem (dentro de 7 días):**

Participantes:
- CISO
- Equipo de seguridad involucrado
- Responsables de sistemas afectados
- Representante de usuarios (si aplica)

Agenda:
1. Cronología detallada del incidente
2. ¿Qué funcionó bien?
3. ¿Qué se pudo hacer mejor?
4. ¿Qué controles fallaron?
5. Recomendaciones de mejora
6. Plan de acción

### 6.2 Actualización de Controles

**Áreas a revisar:**
- [ ] Reglas de firewall
- [ ] Firmas de antivirus
- [ ] Alertas en Graylog
- [ ] Políticas de correo
- [ ] Permisos de usuarios
- [ ] Configuraciones de sistemas
- [ ] Procedimientos documentados
- [ ] Capacitación de usuarios

### 6.3 Documentación

**Registros a mantener:**
1. Reporte completo del incidente
2. Logs recolectados (mínimo 90 días)
3. Evidencia forense (mínimo 1 año)
4. Comunicaciones relacionadas
5. Acciones correctivas implementadas

**Base de conocimiento:**
- Actualizar procedimientos según aprendizajes
- Documentar nuevos IOCs
- Agregar casos de uso a Graylog
- Actualizar runbooks

---

## 7. HERRAMIENTAS Y RECURSOS

### 7.1 Herramientas Institucionales

| Herramienta | Uso | Acceso |
|-------------|-----|--------|
| Graylog | Análisis de logs, correlación | https://graylog.institucion.local |
| FortiGate | Firewall, IPS, bloqueos | https://firewall.institucion.local |
| Antivirus Central | Gestión de endpoints | [Especificar] |
| Active Directory | Gestión de cuentas, auditoría | [Especificar] |
| Zimbra Admin | Gestión de correo | https://mail.institucion.gob:7071 |

### 7.2 Herramientas Externas

**Análisis de amenazas:**
- VirusTotal: https://www.virustotal.com
- URLScan.io: https://urlscan.io
- AbuseIPDB: https://www.abuseipdb.com
- Hybrid Analysis: https://www.hybrid-analysis.com
- Any.run: https://any.run

**Threat Intelligence:**
- AlienVault OTX: https://otx.alienvault.com
- ThreatCrowd: https://www.threatcrowd.org
- Shodan: https://www.shodan.io (para análisis de exposición)

**Herramientas forenses:**
- Sysinternals Suite
- KAPE (Kroll Artifact Parser and Extractor)
- Volatility (análisis de memoria)
- FTK Imager (adquisición de evidencia)

### 7.3 Scripts Útiles

**Recolección rápida de información (PowerShell):**
```powershell
# Script de recolección rápida de información forense
# Guardar como: CollectIncidentData.ps1

$outputDir = "C:\IncidentResponse_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $outputDir | Out-Null

Write-Host "[*] Recolectando información del sistema..."

# 1. Información del sistema
Get-ComputerInfo | Out-File "$outputDir\system_info.txt"

# 2. Procesos en ejecución con hashes
Get-Process | Where-Object {$_.Path} | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        ID = $_.Id
        Path = $_.Path
        Hash = (Get-FileHash -Path $_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        StartTime = $_.StartTime
    }
} | Export-Csv "$outputDir\processes.csv" -NoTypeInformation

# 3. Conexiones de red
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, 
    RemotePort, State, OwningProcess, 
    @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).Name}} | 
    Export-Csv "$outputDir\network_connections.csv" -NoTypeInformation

# 4. Servicios
Get-Service | Select-Object Name, DisplayName, Status, StartType, 
    @{Name="PathName";Expression={(Get-WmiObject Win32_Service -Filter "Name='$($_.Name)'").PathName}} | 
    Export-Csv "$outputDir\services.csv" -NoTypeInformation

# 5. Tareas programadas
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | 
    Select-Object TaskName, TaskPath, State, 
    @{Name="Actions";Expression={$_.Actions.Execute}} | 
    Export-Csv "$outputDir\scheduled_tasks.csv" -NoTypeInformation

# 6. Autorun entries
Get-CimInstance Win32_StartupCommand | 
    Select-Object Name, Command, Location, User | 
    Export-Csv "$outputDir\autoruns.csv" -NoTypeInformation

# 7. Usuarios locales
Get-LocalUser | Select-Object Name, Enabled, LastLogon, 
    PasswordLastSet, PasswordRequired | 
    Export-Csv "$outputDir\local_users.csv" -NoTypeInformation

# 8. Archivos recientes en ubicaciones sensibles
$sensitivePaths = @(
    "C:\Users\*\AppData\Roaming",
    "C:\Users\*\AppData\Local\Temp",
    "C:\Windows\Temp",
    "C:\ProgramData"
)

$recentFiles = @()
foreach ($path in $sensitivePaths) {
    $recentFiles += Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
        Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | 
        Select-Object FullName, Length, CreationTime, LastWriteTime, LastAccessTime
}
$recentFiles | Export-Csv "$outputDir\recent_files.csv" -NoTypeInformation

# 9. Eventos de seguridad recientes
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    StartTime=(Get-Date).AddDays(-1)
} -MaxEvents 1000 -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id, Message | 
    Export-Csv "$outputDir\security_events.csv" -NoTypeInformation

# 10. DNS Cache
Get-DnsClientCache | Export-Csv "$outputDir\dns_cache.csv" -NoTypeInformation

Write-Host "[+] Información recolectada en: $outputDir"
Write-Host "[*] Comprimir la carpeta y enviar a equipo de seguridad"
```

---

## 8. CHECKLIST DE RESPUESTA RÁPIDA

### Detección de Malware
- [ ] Identificar equipo y usuario afectado
- [ ] Verificar tipo y severidad de amenaza
- [ ] Aislar equipo si es necesario
- [ ] Recolectar evidencia básica
- [ ] Documentar hallazgos iniciales
- [ ] Consultar Graylog para contexto
- [ ] Escanear con herramientas adicionales
- [ ] Decidir: limpieza o reimagen
- [ ] Cambiar credenciales del usuario
- [ ] Monitoreo post-remediación
- [ ] Actualizar controles de prevención
- [ ] Documentar incidente completo

### Reporte de Phishing
- [ ] Obtener correo como adjunto (.eml)
- [ ] Analizar encabezados completos
- [ ] Verificar enlaces y adjuntos
- [ ] Determinar alcance (cuántos usuarios)
- [ ] Clasificar severidad según acciones de usuarios
- [ ] Bloquear remitente/dominio
- [ ] Eliminar correos de todos los buzones
- [ ] Si hubo compromiso: cambiar credenciales
- [ ] Si hubo ejecución: procedimiento de malware
- [ ] Comunicar a usuarios afectados
- [ ] Actualizar filtros de correo
- [ ] Documentar IOCs

### Actividad Maliciosa
- [ ] Validar alerta y descartar falso positivo
- [ ] Identificar sistema/usuario origen
- [ ] Determinar alcance y propagación
- [ ] Contener según tipo de amenaza
- [ ] Recolectar logs y evidencia
- [ ] Análisis de timeline de eventos
- [ ] Buscar indicadores de persistencia
- [ ] Verificar exfiltración de datos
- [ ] Bloquear IOCs en perímetro
- [ ] Remediar sistemas afectados
- [ ] Monitoreo extendido
- [ ] Lecciones aprendidas

---

## 9. CONTACTOS DE EMERGENCIA

| Rol | Nombre | Teléfono | Email |
|-----|--------|----------|-------|
| CISO | Daniel Nalotto - Lucio Schiavoni | 01336 | grp_seguridad@mec.gub.uy |

---

## 10. CONTROL DE VERSIONES

| Versión | Fecha | Cambios | Autor |
|---------|-------|---------|-------|
| 1.0 | Dic 2025 | Versión inicial | CISO |
| | | | |
| | | | |

---

## ANEXOS

### ANEXO A: Plantillas de Comunicación
### ANEXO B: Formularios de Registro
### ANEXO C: Matriz de Escalamiento Detallada
### ANEXO D: Configuraciones de Herramientas

---

**Fin del documento**

*Este procedimiento debe ser revisado y actualizado semestralmente o después de incidentes mayores.*
