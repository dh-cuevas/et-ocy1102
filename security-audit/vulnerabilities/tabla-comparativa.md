# Tabla Comparativa de Vulnerabilidades Identificadas

| # | Vulnerabilidad            | Severidad | CWE     | OWASP Top 10 | CVSS  | Análisis Manual      | OWASP ZAP              | Prioridad                           |
|---|---------------------------|-----------|---------|--------------|-------|----------------------|------------------------|-------------------------------------|
| 1 | SQL Injection             |  Crítica  | CWE-89  |   A03:2021   |  9.8  | Detectada/Confirmada |  Detectada/Confirmada  | Nivel de prioridad para explotación |
| 2 | Stored XSS                |    Alta   | CWE-79  |   A03:2021   |  7.5  | Detectada/Confirmada |  Detectada/Confirmada  | Nivel de prioridad para explotación |
| 3 | CSRF                      |   Media   | CWE-352 |   A01:2021   |  6.5  | Detectada/Confirmada |  Detectada/Confirmada  | Nivel de prioridad para explotación |
| 4 | Gestión Sesiones Insegura |   Media   | CWE-330 |   A02:2021   |  5.3  | Detectada/Confirmada | Parcialmente detectada | Nivel de prioridad para explotación |
| 5 | Debug Mode Enabled        |   Media   | CWE-200 |   A05:2021   |  5.0  | Detectada/Confirmada |  Detectada/Confirmada  | Nivel de prioridad para explotación |

**Total de vulnerabilidades identificadas:** 5 (cumple requisito mínimo)  
**Vulnerabilidades a explotar:** 5  
**Herramientas utilizadas:** OWASP ZAP Baseline + Análisis Manual de Código  

**Auditor:** David H. Cuevas Salgado  
**Fecha:** 29/11/2025 00:55

