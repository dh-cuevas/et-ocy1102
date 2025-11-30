# Informe Final - Auditoría de Seguridad

**Estudiante:** DAVID H. CUEVAS SALGADO

**Asignatura:** OCY1102 - Ciberseguridad en Desarrollo  

**Evaluación:** Examen Final Transversal

**Institución:** Duoc UC  

**Fecha:** 30/11/2025

---

## Resumen Ejecutivo

Este proyecto consistió en una auditoría de seguridad completa sobre una aplicación web desarrollada en Python con Flask, identificando, explotando y corrigiendo vulnerabilidades críticas de seguridad. Se utilizó una metodología sistemática dividida en 8 fases, desde la preparación del entorno hasta la documentación final, aplicando las mejores prácticas de OWASP y principios de programación defensiva. La auditoría identificó 5 vulnerabilidades principales (SQL Injection, Stored XSS, CSRF, gestión insegura de sesiones y debug mode habilitado), todas fueron explotadas exitosamente para demostrar su impacto real, y posteriormente corregidas mediante la implementación de código seguro con controles de defensa en profundidad.

La fase de identificación utilizó OWASP ZAP Baseline Scan complementado con análisis manual exhaustivo del código fuente, detectando 14 alertas automáticas y clasificando las vulnerabilidades según CVSS 3.1 y CWE. La explotación demostró el impacto crítico de estas fallas: el SQL Injection permitió bypass completo de autenticación sin credenciales válidas, el XSS almacenado posibilitó la ejecución de JavaScript arbitrario en contexto de otros usuarios, el CSRF facilitó acciones no autorizadas mediante ingeniería social, la gestión insegura de sesiones causó invalidación masiva al reiniciar el servidor, y el debug mode expuso código fuente completo con stack traces de Werkzeug. Cada vulnerabilidad fue documentada técnicamente con scripts de explotación automatizados en Python, capturas de pantalla como evidencia, y análisis detallado del vector de ataque y su impacto en la tríada CIA (Confidencialidad, Integridad, Disponibilidad).

La remediación implementó una arquitectura de seguridad robusta reemplazando concatenación SQL por consultas parametrizadas, migrando SHA256 simple a PBKDF2-SHA256 con salt aleatorio, sanitizando todo input con la biblioteca bleach, implementando Flask-WTF para protección CSRF automática, externalizando la SECRET_KEY a variables de entorno con configuración segura de cookies, desactivando debug mode en producción con manejo personalizado de errores, y agregando 6 headers de seguridad críticos (X-Content-Type-Options, X-Frame-Options, HSTS, CSP, entre otros). Adicionalmente, se implementaron controles de seguridad adicionales incluyendo rate limiting con Flask-Limiter para prevenir brute force (5 intentos/min en login), logging comprehensivo de eventos de seguridad con RotatingFileHandler, validación avanzada de input mediante WTForms con expresiones regulares, y una clase InputValidator para defensa en profundidad.

El proyecto culminó con un plan de seguridad integral que establece políticas de desarrollo seguro (consultas parametrizadas obligatorias, hashing robusto de passwords, validación server-side), procedimientos operacionales (checklist pre-deployment de 8 items, actualización mensual de dependencias, backup diario automático), sistema de monitoreo (logging de 8 eventos críticos, alertas automatizadas, métricas y KPIs definidos), y protocolo de respuesta a incidentes clasificados en 4 niveles de prioridad (P0 crítico con respuesta en 15 minutos, hasta P2 medio en 24 horas). Los resultados demuestran la transición exitosa de una aplicación completamente vulnerable (5/5 vulnerabilidades críticas explotables) a una aplicación securizada con 0 vulnerabilidades críticas/altas, 100% de cumplimiento del checklist de seguridad, implementación de 15+ controles de seguridad, y arquitectura preparada para producción siguiendo el principio de defensa en profundidad y las mejores prácticas del OWASP Top 10 2021.

---

## Indicadores de Logro Cumplidos

### IL 1.3: Identificación de Causas Subyacentes
**LOGRADO:** Se identificaron las causas raíz de 5 vulnerabilidades con análisis técnico detallado:
- SQL Injection: Concatenación de strings en queries + validación basada en blacklist
- XSS: Uso de render_template_string sin sanitización + falta de CSP
- CSRF: Ausencia de tokens anti-CSRF + cookies sin SameSite
- Sesiones: SECRET_KEY volátil + falta de configuración de cookies
- Debug Mode: Configuración hardcodeada + sin manejo de errores

### IL 2.1: Técnicas de Codificación Segura
**LOGRADO:** Implementación de técnicas específicas:
- Validación de entrada con WTForms (DataRequired, Length, Regexp)
- Sanitización con biblioteca bleach (whitelist de tags)
- Consultas parametrizadas en todas las queries SQL
- Hashing PBKDF2-SHA256 con salt de 16 bytes
- Headers de seguridad (6 implementados)

### IL 3.2: Automatización y Monitoreo
**LOGRADO:** Técnicas de DevSecOps aplicadas:
- OWASP ZAP Baseline Scan automatizado
- Logging de eventos de seguridad (RotatingFileHandler)
- Rate limiting automático (Flask-Limiter)
- Alertas configuradas para eventos críticos
- Plan de monitoreo continuo documentado

---

## Resultados Cuantitativos

| Métrica                   | Antes | Después | Mejora |
|---------------------------|-------|---------|--------|
| Vulnerabilidades Críticas |   1   |    0    |  100%  |
| Vulnerabilidades Altas    |   1   |    0    |  100%  |
| Vulnerabilidades Medias   |   3   |    0    |  100%  |
| Headers de Seguridad      |   0   |    6    | +600%  |
| Controles Implementados   |   0   |   15+   |   N/A  |
| Cumplimiento Checklist    |  0%   |  100%   | +100%  |

---

## Estructura del Proyecto Final

\\\
et-ocy1102/
├── app/                                    # Aplicación vulnerable
│   ├── vulnerable_flask_app.py
│   ├── create_db.py
│   └── Dockerfile
├── security-audit/
│   ├── vulnerabilities/                    # Fase 2
│   │   ├── analisis-detallado.md          (5 vulnerabilidades)
│   │   ├── resumen-zap.md                 (14 alertas OWASP ZAP)
│   │   └── tabla-comparativa.md
│   ├── exploits/                           # Fase 3
│   │   ├── 01_sql_injection.py
│   │   ├── 02_stored_xss.py
│   │   ├── 03_csrf.py + csrf_attack.html
│   │   ├── 04_session_management.py
│   │   ├── 05_debug_mode.py
│   │   ├── explotacion-01-sqli.md
│   │   ├── explotacion-02-xss.md
│   │   ├── explotacion-03-csrf.md
│   │   ├── explotacion-04-sessions.md
│   │   └── explotacion-05-debug.md
│   ├── fixed-code/                         # Fase 4 y 5
│   │   ├── secure_flask_app.py            (Código corregido)
│   │   ├── enhanced_flask_app.py          (+ Rate limiting)
│   │   ├── create_secure_db.py
│   │   ├── generate_secret_key.py
│   │   ├── input_validator.py
│   │   ├── test_security_controls.py
│   │   ├── requirements.txt
│   │   ├── requirements-enhanced.txt
│   │   ├── .env.example
│   │   ├── templates/                      (6 templates HTML)
│   │   ├── DOCUMENTACION_CORRECCIONES.md
│   │   └── COMPARATIVA_CODIGO.md
│   ├── zap-reports/
│   │   ├── zap-baseline-report.html
│   │   └── zap-baseline-report.md
│   └── PLAN_SEGURIDAD.md                   # Fase 6
├── docs/
│   └── informe-final.md                    # Este documento
├── docker-compose.yml
└── README.md
\\\

---

## Herramientas y Tecnologías Utilizadas

**Análisis de Seguridad:**
- OWASP ZAP Baseline Scanner
- Análisis manual de código

**Desarrollo:**
- Python 3.11
- Flask 3.0.0
- SQLite3
- Docker

**Seguridad:**
- Flask-WTF (CSRF protection)
- Flask-Limiter (Rate limiting)
- Bleach (Sanitización HTML)
- Werkzeug Security (Password hashing)
- python-dotenv (Gestión de secretos)

**Control de Versiones:**
- Git/GitHub

---

## Lecciones Aprendidas

1. **La seguridad debe ser diseñada, no añadida:** Las vulnerabilidades surgen de decisiones de diseño incorrectas desde el inicio
2. **Defensa en profundidad es esencial:** Múltiples capas de seguridad previenen que una falla comprometa todo el sistema
3. **La validación client-side no es suficiente:** Toda validación debe replicarse en el servidor
4. **Los secretos nunca van en el código:** Variables de entorno y secrets managers son obligatorios
5. **El monitoreo es tan importante como la prevención:** Sin logs no hay visibilidad de ataques

---

## Recomendaciones Futuras

1. Implementar autenticación de dos factores (2FA)
2. Agregar Web Application Firewall (WAF)
3. Implementar Content Security Policy más restrictivo
4. Configurar honeypots para detección temprana
5. Automatizar escaneos de seguridad en CI/CD
6. Realizar penetration testing trimestral con equipo externo

---

## Conclusión

La auditoría demostró que la aplicación vulnerable contenía múltiples fallos críticos de seguridad que permitían comprometer completamente la confidencialidad, integridad y disponibilidad del sistema. Mediante la aplicación sistemática de principios de programación defensiva, validación rigurosa de input, arquitectura de seguridad en capas, y controles automatizados, se logró transformar la aplicación en un sistema robusto y seguro. El plan de seguridad establecido garantiza la sostenibilidad de estos controles mediante políticas claras, procedimientos documentados, monitoreo continuo y capacitación del equipo. Este proyecto valida la importancia de integrar la seguridad en todas las fases del ciclo de vida del desarrollo de software (SDLC), no como una actividad aislada sino como un componente fundamental de la calidad del producto.

---

**Auditor:** DAVID H. CUEVAS SALGADO 
**Fecha de Entrega:** 30/11/2025  
**Estado:** FINALIZADO

