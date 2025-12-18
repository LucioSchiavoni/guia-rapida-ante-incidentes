# FORMULARIO DE REGISTRO DE INCIDENTE DE SEGURIDAD

**ID del Incidente:** INC-SEC-________-____  
**Fecha de creación:** ___/___/______ Hora: ___:___

---

## SECCIÓN 1: INFORMACIÓN BÁSICA

**Reportado por:**  
☐ Usuario final  
☐ Sistema automático (Antivirus/IPS)  
☐ Monitoreo (Graylog)  
☐ Equipo de TI  
☐ Otro: _________________

**Nombre del reportante:** _________________________________  
**Email:** _____________________ **Ext:** ______________

**Fecha/Hora del incidente:** ___/___/______ ___:___

**Fecha/Hora de detección:** ___/___/______ ___:___

---

## SECCIÓN 2: CLASIFICACIÓN

**Tipo de incidente:**  
☐ Malware (especificar): _______________________  
☐ Phishing  
☐ Ransomware  
☐ Acceso no autorizado  
☐ Compromiso de credenciales  
☐ Exfiltración de datos  
☐ Denegación de servicio  
☐ Actividad maliciosa (especificar): _______________________  
☐ Otro: _______________________

**Severidad inicial:**  
☐ CRÍTICO - Afectación masiva o sistemas críticos  
☐ ALTO - Afectación significativa  
☐ MEDIO - Impacto limitado  
☐ BAJO - Mínimo impacto

---

## SECCIÓN 3: SISTEMAS/USUARIOS AFECTADOS

**Equipos afectados:**

| Computer Name | IP Address | MAC Address | Usuario | Ubicación |
|---------------|------------|-------------|---------|-----------|
| | | | | |
| | | | | |
| | | | | |

**Servicios afectados:**  
☐ Correo electrónico (Zimbra)  
☐ Active Directory  
☐ Servidor de archivos  
☐ Aplicación crítica: _______________________  
☐ Red/Firewall  
☐ VPN  
☐ Otro: _______________________

**Usuarios afectados:** _____ usuarios aproximadamente

**¿Datos sensibles involucrados?**  
☐ Sí ☐ No ☐ En investigación

**Tipo de datos:**  
☐ Información personal  
☐ Información financiera  
☐ Información clasificada  
☐ Credenciales  
☐ Otro: _______________________

---

## SECCIÓN 4: DESCRIPCIÓN DEL INCIDENTE

**Descripción detallada:**  
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

**¿Cómo se detectó?**  
___________________________________________________________________________
___________________________________________________________________________

**Síntomas observados:**  
☐ Lentitud del sistema  
☐ Comportamiento inusual de aplicaciones  
☐ Archivos encriptados  
☐ Pérdida de acceso a archivos  
☐ Mensajes de error inusuales  
☐ Actividad de red sospechosa  
☐ Alertas del antivirus  
☐ Correo sospechoso  
☐ Otro: _______________________

---

## SECCIÓN 5: INDICADORES DE COMPROMISO (IOCs)

**Archivos maliciosos:**

| Nombre del archivo | Ubicación | Hash (SHA256) | Acción |
|-------------------|-----------|---------------|--------|
| | | | |
| | | | |

**IPs sospechosas:**

| IP Address | Puerto | Tipo de conexión | Bloqueada (S/N) |
|-----------|--------|------------------|-----------------|
| | | | |
| | | | |

**Dominios sospechosos:**

| Dominio | Relacionado con | Bloqueado (S/N) |
|---------|-----------------|-----------------|
| | | |
| | | |

**URLs maliciosas:**
___________________________________________________________________________
___________________________________________________________________________

**Cuentas comprometidas:**

| Usuario | Dominio | Acciones tomadas |
|---------|---------|------------------|
| | | |
| | | |

---

## SECCIÓN 6: ACCIONES INMEDIATAS TOMADAS

**Fecha/Hora: ___/___/______ ___:___**

☐ Equipo aislado de la red  
☐ Cuenta de usuario bloqueada  
☐ IP/Dominio bloqueado en firewall  
☐ Correos eliminados del servidor  
☐ Remitente bloqueado  
☐ Contraseñas cambiadas  
☐ Sesiones activas cerradas  
☐ Archivo puesto en cuarentena  
☐ Sistema apagado  
☐ Evidencia recolectada  

**Otras acciones:**
___________________________________________________________________________
___________________________________________________________________________

**Contención efectiva:** ☐ Sí ☐ No ☐ Parcial

---

## SECCIÓN 7: CRONOLOGÍA DE EVENTOS

| Fecha/Hora | Evento | Responsable |
|------------|--------|-------------|
| | Inicio estimado del incidente | |
| | Primera detección | |
| | Notificación al equipo de seguridad | |
| | Inicio de contención | |
| | | |
| | | |

---

## SECCIÓN 8: ANÁLISIS Y CAUSA RAÍZ

**Vector de ataque:**  
☐ Correo electrónico (phishing)  
☐ Navegación web (drive-by download)  
☐ Vulnerabilidad explotada  
☐ Credenciales comprometidas  
☐ Medios removibles (USB)  
☐ Software vulnerable  
☐ Ingeniería social  
☐ Desconocido  
☐ Otro: _______________________

**Causa raíz identificada:**
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

**Controles que fallaron:**
___________________________________________________________________________
___________________________________________________________________________

---

## SECCIÓN 9: REMEDIACIÓN

**Acciones de erradicación:**

☐ Limpieza con antivirus  
☐ Reimagen de sistema(s)  
☐ Reinstalación de aplicaciones  
☐ Remoción manual de persistencia  
☐ Actualización de sistemas  
☐ Parcheado de vulnerabilidades  

**Detalles:**
___________________________________________________________________________
___________________________________________________________________________

**Sistemas restaurados:** ☐ Sí ☐ No ☐ En proceso

**Fecha/Hora de restauración:** ___/___/______ ___:___

---

## SECCIÓN 10: VALIDACIÓN Y CIERRE

**Verificación post-remediación:**

☐ Escaneo completo sin detecciones  
☐ No se observa actividad sospechosa  
☐ Conexiones de red normales  
☐ Usuarios pueden trabajar normalmente  
☐ Monitoreo establecido (_____ días)  

**Estado final:**  
☐ RESUELTO - Sin actividad residual  
☐ MITIGADO - Riesgo reducido, monitoreo continuo  
☐ EN INVESTIGACIÓN - Requiere análisis adicional

**Fecha de cierre:** ___/___/______ ___:___

---

## SECCIÓN 11: COMUNICACIONES

**Notificaciones realizadas:**

| Fecha/Hora | Persona/Área notificada | Medio | Asunto |
|------------|-------------------------|-------|--------|
| | | | |
| | | | |

**Comunicación externa requerida:**  
☐ No  
☐ Sí - Proveedor de servicio  
☐ Sí - Autoridades  
☐ Sí - Usuarios afectados  
☐ Sí - Otro: _______________________

---

## SECCIÓN 12: LECCIONES APRENDIDAS

**¿Qué funcionó bien?**
___________________________________________________________________________
___________________________________________________________________________

**¿Qué se pudo hacer mejor?**
___________________________________________________________________________
___________________________________________________________________________

**Recomendaciones para prevenir recurrencia:**

1. ___________________________________________________________________
2. ___________________________________________________________________
3. ___________________________________________________________________

**Controles a implementar/mejorar:**

☐ Actualización de firmas de antivirus  
☐ Nuevas reglas de firewall  
☐ Alertas adicionales en Graylog  
☐ Políticas de correo reforzadas  
☐ Capacitación de usuarios  
☐ Actualización de procedimientos  
☐ Endurecimiento de sistemas  
☐ Otro: _______________________

---

## SECCIÓN 13: INFORMACIÓN ADICIONAL

**Costo estimado del incidente:**

| Concepto | Monto |
|----------|-------|
| Horas de personal | |
| Herramientas/servicios externos | |
| Datos/sistemas perdidos | |
| **Total estimado** | |

**Tiempo total de resolución:** _____ horas/días

**Archivos adjuntos:**  
☐ Logs recolectados  
☐ Capturas de pantalla  
☐ Análisis de malware  
☐ Evidencia forense  
☐ Comunicaciones relacionadas

**Ubicación de evidencia:** _______________________

---

## APROBACIONES

**Analista de Seguridad:**  
Nombre: _________________________ Fecha: ___/___/______  
Firma: _________________________

**CISO:**  
Nombre: _________________________ Fecha: ___/___/______  
Firma: _________________________

**Director de TI (si aplica para incidentes CRÍTICOS/ALTO):**  
Nombre: _________________________ Fecha: ___/___/______  
Firma: _________________________

---

## NOTAS ADICIONALES

___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________
___________________________________________________________________________

---

**Revisiones posteriores:**

| Fecha | Revisado por | Cambios |
|-------|--------------|---------|
| | | |
| | | |

---

*Documento confidencial - Solo para uso interno de la Oficina de Seguridad Informática*
