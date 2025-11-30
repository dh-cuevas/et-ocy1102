# Plan de Seguridad - Aplicación Flask

**Responsable:** DAVID H. CUEVAS SALGADO
**Fecha:** 30/11/2025  
**Versión:** 1.0

---

## 1- POLÍTICAS DE SEGURIDAD

### 1.1- Desarrollo Seguro:
- **SQL:** Hacer uso de consultas parametrizadas; no se puede hacer concatenación de strings.
- **Passwords:** Se debe implementar hashing de manera obligatoria con PBKDF2 o bcrypt; mínimo 8 caracteres.
- **Input:** Validación siempre en servidor; preferencia por whitelist sobre blacklist.
- **Secretos:** Las claves, tokens y/o contraseñas deben almacenarse y gestionarse únicamente mediante variables de entorno del sistema operativo.
- **Debug:** Debe estar desactivado en producción, es decir, FLASK_DEBUG=False.

### 1.2- Control de Código:
- El repositorio Git de hacerse implementando .gitignore para ocultar .env y archivos .db.
- El Pull Request es obligatorio con al menos un revisor.
- No hacer commits directos al main o rama principal.


### 1.3- Gestión de Sesiones:
- SECRET_KEY debe ser definido en variable de entorno.
- Las cookies van configuradas con HttpOnly=True, Secure=True, SameSite=Lax.
- Tiempo de expiración de sesión: 1 hora de inactividad.

---

## 2- PROCEDIMIENTOS

### 2.1- Pre-Deployment (Checklist):
- [ ] FLASK_DEBUG=False
- [ ] SECRET_KEY persistente configurada.
- [ ] HTTPS habilitado.
- [ ] Todas las queries parametrizadas.
- [ ] CSRF tokens activos.
- [ ] Rate limiting configurado.
- [ ] Headers de seguridad implementados.
- [ ] Backup de BD configurado.

### 2.2- Actualización de Dependencias:
- Frecuencia: Debe ser mensual.
- Herramienta: Para las dependencias pip install safety && safety check.
- Vulnerabilidades críticas: Corrección inmediata con plazo máximo de 24 horas (< 24h).

### 2.3- Backup:
- Base de datos: Hacer copia diaria automática, retención de 30 días.
- Código: Control continuo en Git.
- Prueba de restauración: Hacerla de manera mensual.

---

## 3- MONITOREO

### 3.1- Eventos a Monitorear:
| Evento                       | Severidad | Acción           |
|------------------------------|-----------|------------------|
| 5+ login fallidos (misma IP) |    ALTA   | Bloqueo + Alerta |
| Acceso no autorizado /admin  |    ALTA   | Alerta inmediata |
| Rate limit excedido          |   MEDIA   | Investigar IP    |
| Error 500 frecuente          |   MEDIA   | Revisar logs     |

### 3.2- Logging:
- Ubicación: logs/security.log
- Rotación: 10 MB, hasta 10 archivos de respaldo.
- Retención: 90 días.
- Eventos registrados: Logins exitosos/fallidos, accesos no autorizados, rate limits.

### 3.3- Alertas:
- Notificación por correo al equipo cuando:
	- Login fallido > 50/día.
	- Rate limit > 20/día.
	- Error 500 > 10/hora.

---

## 4- RESPUESTA A INCIDENTES

### 4.1- Clasificación:
| Nivel            | Ejemplo                  | Tiempo Respuesta |
|------------------|--------------------------|------------------|
| **P0 - Crítico** | SQL Injection explotado  |    < 15 min      |
| **P1 - Alto**    | Credenciales expuestas   |    < 1 hora      |
| **P2 - Medio**   | Vulnerabilidad detectada |   < 24 horas     |

### 4.2- Proceso de Respuesta (P0):
1. **Contención (0-30 min):**
	- Identificar vector de ataque.
	- Bloquear IP: sudo iptables -A INPUT -s <IP> -j DROP.
	- Capturar logs.

   
2. **Erradicación (30 min - 2h):**
	- Aplicar parche.
	- Realizar deploy urgente.
	- Verificar que el ataque esté detenido.


3. **Recuperación (2-4h):**
	- Restaurar desde backup si es necesario.
	- Cambiar credenciales comprometidas.
	- Monitorear actividad.


4. **Post-Mortem (24-48h):**
	- Documentar timeline del incidente.
	- Extraer lecciones aprendidas.
	- Actualizar runbook.


### 4.3- Contactos de Emergencia:
- **Security Lead:** security@empresa.com
- **DevOps:** devops@empresa.com
- **DBA:** dba@empresa.com

---

## 5- MÉTRICAS Y KPIs

### 5.1- Objetivos:
| Métrica                   | Objetivo |
|---------------------------|----------|
| Vulnerabilidades críticas |     0    |
| Uptime                    | > 99.5%  |
| Tiempo respuesta login    | < 200ms  |
| Cobertura tests seguridad |  > 30%   |

### 5.2- Revisión:
- **Mensual:** Hacer revisión de métricas y logs.
- **Trimestral:** Aplicar auditoría completa + Pentest.
- **Anual:** Realizar una actualización del plan.

---

## 6- CAPACITACIÓN

### 6.1- Obligatoria para Desarrolladores:
- OWASP Top 10 (anual)
- Secure Coding (semestral)
- Phishing Awareness (trimestral)

---

## APROBACIÓN

| Rol     | Nombre                             | Fecha      |
|---------|------------------------------------|------------|
| Auditor | David H. Cuevas Salgado            | 30/11/2025 |

**Próxima revisión:** 30/05/2026

