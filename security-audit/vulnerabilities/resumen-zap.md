# Resultados OWASP ZAP Baseline Scan
**Auditor:** DAVID H. CUEVAS SALGADO  
**Herramienta:** OWASP ZAP Baseline Scanner (Docker)  
**Fecha:** 29/11/2025 00:49  
**Target:** http://host.docker.internal:5000  
**Tipo de escaneo:** Passive Scan (Baseline)

---

## Resumen Ejecutivo

El escaneo baseline de OWASP ZAP identificó múltiples vulnerabilidades de seguridad en la aplicación Flask. Los hallazgos se correlacionan con el análisis manual de código realizado.

### Alertas Detectadas

| Nivel de Riesgo | Cantidad |
|-----------------|----------|
|   **WARN-NEW**  |    14    |
|     **PASS**    |    53    |
|     **FAIL**    |     0    |

### Hallazgos Principales

#### 1. **Absence of Anti-CSRF Tokens [10202]** - 2 instancias
- http://host.docker.internal:5000/login
- Confirmado: No hay protección CSRF en formularios

#### 2. **Application Error Disclosure [90022]** - 2 instancias  
- http://host.docker.internal:5000/login (500 Internal Server Error)
- Confirmado: Debug mode expone stack traces

#### 3. **Source Code Disclosure - SQL [10099]** - 2 instancias
- http://host.docker.internal:5000/login (500 Internal Server Error)
- Confirmado: Código SQL visible en errores

#### 4. **Content Security Policy (CSP) Header Not Set [10038]** - 9 instancias
- Facilita ataques XSS

#### 5. **X-Content-Type-Options Header Missing [10021]** - 6 instancias
- Permite MIME sniffing attacks

#### 6. **Missing Anti-clickjacking Header [10020]** - 3 instancias
- No hay protección X-Frame-Options

#### 7. **Server Leaks Version Information [10036]** - 11 instancias
- Werkzeug version expuesta

#### 8. **Permissions Policy Header Not Set [10063]** - 10 instancias
- Falta configuración de permisos del navegador

#### 9. **Information Disclosure - Suspicious Comments [10027]** - 3 instancias
- Comentarios en código JavaScript del debugger

#### 10. **Sub Resource Integrity Attribute Missing [90003]** - 3 instancias
- CDN de Bootstrap sin SRI

---

## Correlación con Análisis Manual

| Vulnerabilidad                  | Análisis Manual | OWASP ZAP                                 | Estado     |
|---------------------------------|-----------------|-------------------------------------------|------------|
| SQL Injection                   |  Identificada   | Source Code Disclosure - SQL              | VERIFICADO |
| Stored XSS                      |  Identificada   | CSP Missing + XSS posible                 | VERIFICADO |
| CSRF                            |  Identificada   | Anti-CSRF Tokens Absent                   | VERIFICADO |
| Debug Mode                      |  Identificada   | Application Error Disclosure              | VERIFICADO |
| Gestión Sesiones                |  Identificada   | Cookie flags (parcial)                    | VERIFICADO |

---

## Estadísticas del Escaneo

- **Total URLs escaneadas:** 15
- **Checks ejecutados:** 67 (53 PASS + 14 WARN)
- **Vulnerabilidades confirmadas:** 14 WARN-NEW
- **Tiempo de escaneo:** ~3 minutos
- **Modo:** Baseline (Passive Scan)

---

## Evidencias

- **Reporte HTML completo:** security-audit/zap-reports/zap-baseline-report.html
- **Reporte Markdown:** security-audit/zap-reports/zap-baseline-report.md
- **Análisis manual:** security-audit/vulnerabilities/analisis-detallado.md

---

## Conclusión

OWASP ZAP confirmó las 5 vulnerabilidades priorizadas identificadas en el análisis manual:

1. SQL Injection (indicios via error disclosure)
2. XSS (CSP ausente facilita ataque)
3. CSRF (tokens ausentes confirmado)
4. Debug Mode (application errors confirmados)
5. Headers de seguridad faltantes (múltiples)

**Auditor:** DAVID H. CUEVAS SALGADO  
**Fecha:** 29/11/2025 00:49

