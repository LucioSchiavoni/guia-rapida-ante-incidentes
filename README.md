# Guía de Respuesta a Incidentes de Seguridad - MEC

**Repositorio oficial** para procedimientos, scripts y documentación de respuesta a incidentes de seguridad del Ministerio de Educación y Cultura.

---

##  Contenido del Repositorio

###  Documentación Principal
- **[Procedimiento de Respuesta a Incidentes](procedimiento_respuesta_incidentes.md)** - Proceso completo paso a paso
- **[Guía Rápida](guia_rapida_respuesta_incidentes.md)** - Cheat sheet para consulta rápida
- **[Formulario de Registro](formulario_registro_incidente.md)** - Template para documentar incidentes

###  Scripts PowerShell
- `01-Triaje-Inicial.ps1` - Recolección rápida de evidencia inicial
- `02-Aislamiento-Red.ps1` - Aislamiento de equipo comprometido
- `03-Captura-Evidencia.ps1` (CollectIncidentEvidence.ps1) - Captura forense completa
- `05-Buscar-IOCs.ps1` - Búsqueda de indicadores de compromiso
- `06-Reporte-AD-Usuario.ps1` - Análisis de actividad de usuario en AD

###  Playbooks Específicos
- **[Playbook Ransomware](playbooks/playbook-ransomware.md)** - Respuesta específica a ransomware
- *Más playbooks en desarrollo...*

---

##  Inicio Rápido

### Preparación Inicial

1. **Clonar repositorio:**
```bash
git clone https://github.com/LucioSchiavoni/guia-rapida-ante-incidentes.git
cd guia-rapida-ante-incidentes
```

2. **Crear USB de Emergencia:**
   - Copiar carpeta `scripts/` a USB
   - Copiar `guia_rapida_respuesta_incidentes.md` impreso
   - Agregar herramientas: Sysinternals Suite
   - Etiquetar: "KIT RESPUESTA INCIDENTES"

3. **Configurar accesos:**
   - Verificar permisos de administrador
   - Confirmar acceso a AD (para scripts que lo requieren)
   - Verificar conectividad a Graylog

---

##  Uso de Scripts

### Script 1: Triaje Inicial
**Uso:** Primera acción ante reporte de incidente

```powershell
# Ejecutar desde PowerShell como Administrador
.\01-Triaje-Inicial.ps1

# Especificar carpeta de salida custom
.\01-Triaje-Inicial.ps1 -OutputPath "D:\Evidencia\Triaje"
```

**Recolecta:**
- Procesos sin firma digital
- Procesos desde carpetas Temp
- Conexiones de red activas
- Servicios sospechosos
- Tareas programadas no estándar
- Eventos de seguridad (últimas 24h)
- Archivos recientes en Temp
- Keys de persistencia en Registry

**Tiempo de ejecución:** ~2 minutos

---

### Script 2: Aislamiento de Red
**Uso:** Contención inmediata ante amenaza activa

```powershell
# Aislar equipo (requiere confirmación)
.\02-Aislamiento-Red.ps1

# Aislar sin confirmación (emergencia)
.\02-Aislamiento-Red.ps1 -Force

# Revertir aislamiento
.\02-Aislamiento-Red.ps1 -Revert
```

**Acciones:**
- Captura estado pre-aislamiento
- Deshabilita todos los adaptadores de red
- Genera log de la acción
- Proporciona comando de reversión

** ADVERTENCIA:** El equipo quedará sin red. Usar solo cuando sea necesario.

---

### Script 3: Captura de Evidencia
**Uso:** Recolección forense completa

```powershell
# Con ID de incidente personalizado
.\03-Captura-Evidencia.ps1 -IncidentID "INC-SEC-20260225-001"

# Con ruta personalizada
.\03-Captura-Evidencia.ps1 -OutputPath "E:\Forense"

# Combinado
.\03-Captura-Evidencia.ps1 -IncidentID "INC-SEC-20260225-001" -OutputPath "E:\Forense"
```

**Recolecta:**
- Información de sistema completa
- Configuración de red
- Procesos con hashes SHA256
- Servicios y su configuración
- Usuarios locales y administradores
- Archivos recientes (últimos 7 días)
- Registry Run keys
- Event logs (500 eventos recientes)
- Tareas programadas

**Tiempo de ejecución:** ~5-10 minutos  
**Tamaño típico:** 50-200 MB

---

### Script 4: Búsqueda de IOCs
**Uso:** Buscar indicadores específicos de compromiso

```powershell
# Buscar IPs sospechosas
.\05-Buscar-IOCs.ps1 -IPAddresses "192.168.100.50","10.0.0.15"

# Buscar hashes de archivos maliciosos
.\05-Buscar-IOCs.ps1 -FileHashes "a1b2c3d4...","e5f6g7h8..."

# Buscar dominios en DNS cache
.\05-Buscar-IOCs.ps1 -Domains "malicious.com","bad-site.net"

# Buscar archivos por nombre
.\05-Buscar-IOCs.ps1 -FileNames "malware.exe","ransomware.dll"

# Combinado
.\05-Buscar-IOCs.ps1 `
    -IPAddresses "192.168.100.50" `
    -FileHashes "a1b2c3..." `
    -Domains "malicious.com" `
    -FileNames "trojan.exe"
```

**Busca en:**
- Conexiones de red activas
- DNS cache
- Sistema de archivos (Temp, AppData, Downloads, ProgramData)
- Procesos en ejecución

**Tiempo de ejecución:** Variable (5-30 min según búsqueda)

---

### Script 5: Reporte de Usuario en AD
**Uso:** Investigar actividad de usuario comprometido

```powershell
# Requiere módulo ActiveDirectory
.\06-Reporte-AD-Usuario.ps1 -Username "jperez"

# Con ruta custom
.\06-Reporte-AD-Usuario.ps1 -Username "jperez" -OutputPath "D:\Investigacion"
```

** Requisitos:**
- Módulo ActiveDirectory instalado
- Permisos para consultar AD
- Ejecutar desde DC o equipo con RSAT

**Genera:**
- Información básica del usuario
- Membresía de grupos (alerta si es privilegiado)
- Intentos de autenticación fallidos (últimos 7 días)
- Autenticaciones exitosas con IPs origen
- Cambios recientes en la cuenta
- Equipos donde se autenticó
- Acceso a recursos compartidos
- Sesiones activas

**Tiempo de ejecución:** ~3-5 minutos

---

##  Flujo de Trabajo Típico

### Escenario: Reporte de Malware

```
1. Usuario reporta comportamiento sospechoso
   ↓
2. [Soporte IT] Ejecuta: 01-Triaje-Inicial.ps1
   ↓
3. [Soporte IT] Revisa archivos generados
   ↓
4. Si detecta procesos sospechosos → ESCALAR
   ↓
5. [CISO] Ejecuta: 02-Aislamiento-Red.ps1
   ↓
6. [CISO] Ejecuta: 03-Captura-Evidencia.ps1
   ↓
7. [CISO] Analiza evidencia
   ↓
8. Si se identifican IOCs → Ejecuta: 05-Buscar-IOCs.ps1 en otros equipos
   ↓
9. Si usuario comprometido → Ejecuta: 06-Reporte-AD-Usuario.ps1
   ↓
10. Documentar en formulario de incidente
```

---

##  Matriz de Decisión

| Situación | Script a usar | Urgencia |
|-----------|---------------|----------|
| Reporte inicial | 01-Triaje-Inicial.ps1 | Normal |
| Malware activo visible | 02-Aislamiento-Red.ps1 → 03-Captura-Evidencia.ps1 | URGENTE |
| Ransomware | 02-Aislamiento-Red.ps1 → Playbook Ransomware | CRÍTICO |
| Phishing confirmado | 06-Reporte-AD-Usuario.ps1 | Media |
| IOCs conocidos | 05-Buscar-IOCs.ps1 | Media |
| Post-incidente | 03-Captura-Evidencia.ps1 + Formulario | Normal |

---

##  Estructura de Carpetas Generada

Al ejecutar los scripts, se crea automáticamente:

```
C:\IncidentResponse\
├── Triaje_20260225_143000\
│   ├── triaje.log
│   ├── info_basica.json
│   ├── procesos_sin_firma.csv
│   ├── conexiones_establecidas.csv
│   └── ...
├── Aislamiento_20260225_143500.log
├── INC-SEC-20260225-001\
│   ├── collection.log
│   ├── SUMMARY.txt
│   ├── 01_System\
│   ├── 02_Network\
│   ├── 03_Processes\
│   └── ...
├── IOC-Search_20260225_144000\
│   ├── ip_matches.csv
│   ├── hash_matches.csv
│   └── ...
└── AD-Report_jperez_20260225_144500\
    ├── info_basica.json
    ├── grupos.csv
    └── ...
```

---

## Consideraciones Importantes

### Permisos
- Todos los scripts requieren **Administrador**
- Script de AD requiere módulo **ActiveDirectory**
- Verificar permisos de escritura en `C:\IncidentResponse`

### Espacio en Disco
- Triaje: ~5-10 MB
- Evidencia Completa: ~50-200 MB
- Búsqueda IOCs: ~10-50 MB
- Reporte AD: ~1-5 MB

### Tiempo de Ejecución
- En equipos lentos, puede tardar más
- Búsqueda de IOCs con hashes puede ser lenta
- Monitorear progreso en consola

### Red
- Script de aislamiento **desconecta el equipo**
- Ejecutar otros scripts ANTES de aislar si necesitas acceso a AD/red

---

##  Seguridad de los Scripts

### Integridad
Verificar hash SHA256 de scripts antes de usar:

```powershell
Get-FileHash .\*.ps1 -Algorithm SHA256
```

### Ejecución
Si aparece error de execution policy:

```powershell
# Temporal (solo sesión actual)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# O ejecutar con bypass
PowerShell.exe -ExecutionPolicy Bypass -File .\script.ps1
```

### Logs
Todos los scripts generan logs. Revisar en caso de errores.

---

**Dudas o problemas:**
- Equipo Seguridad: grp_seguridad@mec.gub.uy

---

##  Actualizaciones

**Última actualización:** Febrero 2026

**Próximas mejoras:**
- Playbook de phishing
- Playbook de compromiso de credenciales
- Script de análisis de memoria
- Integration con Graylog para búsqueda automatizada

---

## Checklist de Preparación

```
ANTES DE UN INCIDENTE:

☐ Scripts descargados y probados
☐ USB de emergencia preparado
☐ Guía rápida impresa
☐ Formulario impreso
☐ Contactos actualizados
☐ Permisos verificados
☐ Carpeta C:\IncidentResponse creada
☐ Equipo capacitado en uso de scripts
☐ Simulacro realizado
```

---

**Recuerda:** La rapidez en la respuesta es crítica. Familiarízate con los scripts ANTES del incidente.
