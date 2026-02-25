# PLAYBOOK: RESPUESTA A RANSOMWARE

**Severidad:** CRÍTICO  
**Tiempo de respuesta:** INMEDIATO  
**Última actualización:** Febrero 2026

---

## INDICADORES DE RANSOMWARE

### Señales de Alerta
- Archivos con extensiones inusuales (.encrypted, .locked, .crypto, etc.)
- Notas de rescate (ransom notes) en desktop o carpetas
- Mensajes emergentes exigiendo pago
- Imposibilidad de abrir archivos conocidos
- Cambios masivos de nombres de archivos
- Procesos con alto uso de CPU/Disco de forma repentina
- Wallpaper cambiado con mensaje de rescate

### Archivos Típicos de Ransom Note
- README.txt / README.html
- HOW_TO_DECRYPT.txt
- YOUR_FILES_ARE_ENCRYPTED.txt
- DECRYPT_INSTRUCTIONS.html

---

## RESPUESTA INMEDIATA (Primeros 5 minutos)

### 1. AISLAR INMEDIATAMENTE 

## En caso de no poder aislar el equipo desde el antivirus ##

```powershell
# NO APAGAR EL EQUIPO - AISLAR
.\02-Aislamiento-Red.ps1 -Force
```

**Acciones manuales si el script no está disponible:**
1. Desconectar cable de red físicamente
2. Deshabilitar WiFi
3. NO apagar el equipo (evidencia en memoria)

### 2. NOTIFICACIÓN URGENTE

**Contactar INMEDIATAMENTE:**
- Seguridad: 01336

**Template de mensaje:**
```
URGENTE - RANSOMWARE DETECTADO
Equipo: [COMPUTERNAME]
Usuario: [USERNAME]
Ubicación: [OFICINA]
Hora detección: [HH:MM]
Estado: AISLADO
Extensión archivos: [.xxx]
```

### 3. DOCUMENTAR ESTADO INICIAL

- Tomar foto de la pantalla con el celular
- Anotar hora exacta de detección
- Identificar extensión de archivos cifrados
- Buscar nota de rescate (NO eliminarla)

---

## CONTENCIÓN (Primeros 15 minutos)

### Verificar Propagación

1. **Revisar otros equipos del usuario:**
```powershell
# En el equipo del usuario, identificar recursos compartidos accedidos
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=5140
    StartTime=(Get-Date).AddHours(-24)
} | Where-Object {$_.Properties[1].Value -like "*$env:USERNAME*"}
```

2. **Bloquear cuenta en AD:**
```powershell
Disable-ADAccount -Identity [username]
```

3. **Cerrar sesiones activas:**
```powershell
quser /server:[servidor-archivos]
logoff [session-id] /server:[servidor-archivos]
```

4. **Verificar servidores de archivos:**
```bash
# En Linux file server
tail -f /var/log/samba/log.[computername]
```

### Bloquear en FortiGate

```
# Via CLI SSH
config user quarantine
    edit [mac-address-del-equipo]
        set quarantine enable
    next
end

diagnose user quarantine list
```

---

## CAPTURA DE EVIDENCIA

### Script de Evidencia
```powershell
.\03-Captura-Evidencia.ps1 -IncidentID "INC-RANSOM-$(Get-Date -Format 'yyyyMMdd')-001"
```

### Evidencia Específica de Ransomware

1. **Capturar nota de rescate:**
```powershell
Copy-Item C:\Users\*\Desktop\*.txt -Destination C:\IncidentResponse\RansomNotes\
Copy-Item C:\Users\*\Desktop\*.html -Destination C:\IncidentResponse\RansomNotes\
```

2. **Identificar proceso malicioso:**
```powershell
Get-Process | Where-Object {$_.CPU -gt 20 -and $_.Path} | 
    Select-Object Name, Id, Path, CPU, StartTime |
    Export-Csv C:\IncidentResponse\procesos_alta_cpu.csv
```

3. **Capturar archivos cifrados de muestra:**
```powershell
# Copiar 5 archivos cifrados como muestra (NO MOVER originales)
$encryptedFiles = Get-ChildItem C:\Users\*\Documents -File | 
    Where-Object {$_.Extension -match '\.(encrypted|locked|crypto|crypt)$'} |
    Select-Object -First 5

foreach ($file in $encryptedFiles) {
    Copy-Item $file.FullName -Destination "C:\IncidentResponse\Samples\"
}
```

4. **Capturar hash del ransomware:**
```powershell
# Si se identifica el ejecutable
$ransomExe = Get-Process | Where-Object {$_.Path -like "*\Temp\*"} | 
    Select-Object -First 1 -ExpandProperty Path

if ($ransomExe) {
    Get-FileHash -Path $ransomExe -Algorithm SHA256 | 
        ConvertTo-Json | 
        Out-File C:\IncidentResponse\ransomware_hash.json
}
```

---

## IDENTIFICACIÓN

### Identificar Familia de Ransomware

1. **Analizar extensión de archivos:**
   - `.locky` → Locky
   - `.cerber` → Cerber
   - `.cryptolocker` → CryptoLocker
   - `.wannacry` / `.WNCRY` → WannaCry
   - `.encrypted` → Genérico (analizar nota)

2. **Usar ID Ransomware:**
   - Subir nota de rescate a: https://id-ransomware.malwarehunterteam.com/
   - Subir archivo cifrado de muestra

3. **Verificar en VirusTotal:**
```bash
# Hash del ejecutable
certutil -hashfile [archivo] SHA256
# Buscar en virustotal.com
```

### Determinar Vector de Entrada

**Revisar:**
1. Emails recientes del usuario (últimas 24h)
2. Descargas recientes
3. URLs visitadas
4. Dispositivos USB conectados

```powershell
# Emails recientes (si Zimbra accesible)
# Ver en Zimbra web: Search → Date:today

# Descargas
Get-ChildItem "$env:USERPROFILE\Downloads" | 
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} |
    Select-Object Name, LastWriteTime, @{Name="Hash";Expression={(Get-FileHash $_.FullName -Algorithm SHA256).Hash}}

# USB history
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* |
    Select-Object FriendlyName, Mfg
```

---

## ERRADICACIÓN Y RECUPERACIÓN

### NO Intentar Descifrar

- **NO pagar el rescate** (política institucional)
- **NO usar "decifradores" no verificados**
- Solo usar herramientas oficiales si la familia es conocida

### Reimagen Obligatoria

```
PARA RANSOMWARE: REIMAGEN COMPLETA ES OBLIGATORIA
No hay "limpieza" válida en ransomware
```

**Procedimiento:**
1. Verificar existencia de backups
2. Coordinar con usuario ventana de reimagen
3. Ejecutar reimagen con imagen limpia
4. Restaurar desde backup (verificar que backup sea anterior al cifrado)

### Recuperación de Datos

**Opciones en orden de preferencia:**

1. **Backup de red institucional:**
```bash
# Verificar snapshots disponibles
# En servidor de archivos
ls -la /path/to/shares/.snapshots/
```

2. **Shadow Copies (Windows):**
```powershell
# Verificar si el ransomware no eliminó shadow copies
vssadmin list shadows

# Restaurar archivo específico
vssadmin restore shadow /shadow=[ID] /to=C:\Recovery\
```

3. **Backup local del usuario** (si existe)

4. **Decryptor oficial** (solo si familia identificada y decryptor verificado)
   - No More Ransom Project: https://www.nomoreransom.org/
   - Verificar con antivirus vendor

---

## ACCIONES POST-RECUPERACIÓN

### 1. Cambio de Credenciales
```powershell
# Forzar cambio de contraseña
Set-ADUser -Identity [username] -ChangePasswordAtLogon $true

# Resetear contraseña actual
Set-ADAccountPassword -Identity [username] -Reset
```

### 2. Monitoreo Post-Incidente

**Durante 2 semanas:**
- Monitoreo diario de uso de CPU/disco del equipo
- Revisión de logs de acceso a recursos compartidos
- Verificación de archivos nuevos sospechosos

```
# Agregar alerta en Graylog
process_name:[ransomware_identificado] OR 
file_extension:(.encrypted OR .locked OR .crypto)
```

### 3. Bloquear IOCs

**En FortiGate:**
```
# Si se identificó dominio C&C
config firewall address
    edit "ransom-c2-[nombre]"
        set type fqdn
        set fqdn "[dominio-malicioso]"
    next
end

config firewall policy
    edit [policy-id]
        set action deny
        set dstaddr "ransom-c2-[nombre]"
    next
end
```

**En antivirus:**
- Agregar hash a blacklist
- Verificar firma actualizada

---

## COMUNICACIÓN

### Usuarios Afectados
```
Estimado/a [Usuario],

Su equipo fue afectado por un incidente de seguridad (ransomware) 
el día [FECHA] a las [HORA].

ACCIONES TOMADAS:
- Equipo aislado de la red
- Evidencia recolectada
- Credenciales reseteadas
- Reimagen programada

PRÓXIMOS PASOS:
1. Su equipo será reimaginado el [FECHA]
2. Debe cambiar su contraseña en el primer logon
3. Los archivos se recuperarán desde backup

Tiempo estimado de resolución: [PLAZO]

Si tiene preguntas, contacte a:
Equipo de Ciberseguridad - grp_seguridad@mec.gub.uy - 01336
```

### Dirección/Gerencia
```
ASUNTO: [CRÍTICO] Incidente Ransomware - Equipo [NOMBRE]

Severidad: CRÍTICA
Detectado: [DD/MM HH:MM]
Familia: [si se identificó]

SITUACIÓN:
- 1 equipo afectado: [NOMBRE]
- Usuario: [NOMBRE]
- Archivos cifrados: [CANTIDAD ESTIMADA]

CONTENCIÓN:
- Equipo aislado: [HH:MM]
- Cuenta bloqueada: [HH:MM]
- Propagación: CONTENIDA

RECUPERACIÓN:
- Backup disponible: [SÍ/NO]
- Pérdida de datos: [ESTIMADA]
- Reimagen programada: [FECHA]

PRÓXIMOS PASOS:
1. Análisis forense completo
2. Verificación de vector de entrada
3. Revisión de otros equipos del sector
4. Actualización de controles

```

---

## PREVENCIÓN FUTURA

### Controles a Implementar

1. **Email:**
   - Bloquear extensiones peligrosas en Zimbra (.exe, .scr, .vbs en attachments)
   - Agregar banner de warning en emails externos

2. **Endpoint:**
   - Verificar actualización de firmas antivirus
   - Habilitar ransomware protection en Windows Defender
   - Deshabilitar macros en Office por GPO

3. **Red:**
   - Segmentación de servidores de archivos
   - Rate limiting de modificaciones de archivos (si disponible)

4. **Backup:**
   - Verificar backups offsite
   - Probar restauración mensualmente
   - Immutable backups si es posible

5. **Capacitación:**
   - Sesión específica sobre ransomware
   - Simulacros de phishing

---

## CHECKLIST DE CIERRE

```
ANTES DE CERRAR EL INCIDENTE:

☐ Equipo reimaginado y funcional
☐ Datos restaurados desde backup
☐ Usuario puede trabajar normalmente
☐ Credenciales cambiadas
☐ Hash bloqueado en antivirus
☐ Dominio C&C bloqueado (si aplica)
☐ IOCs compartidos con equipo
☐ Monitoreo post-incidente configurado (2 semanas)
☐ Familia de ransomware identificada
☐ Vector de entrada documentado
☐ Lecciones aprendidas documentadas
☐ Controles actualizados
☐ Usuario capacitado
☐ Formulario de incidente completo
```

---

## RECURSOS

### Herramientas
- ID Ransomware: https://id-ransomware.malwarehunterteam.com/
- No More Ransom: https://www.nomoreransom.org/
- VirusTotal: https://www.virustotal.com/

### Referencias
- NIST Ransomware Guide
- CISA Ransomware Response
- SANS Ransomware Defense

---

**Última revisión:** Febrero 2026  
**Próxima revisión:** Agosto 2026  