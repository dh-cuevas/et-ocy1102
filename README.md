# Examen Final - OCY1102 Ciberseguridad en Desarrollo

**ALUMNO** DAVID H. CUEVAS SALGADO 
**ASIGNATURA:** OCY1102 - CIBERSEGURIDAD EN DESARROLLO 
**EVALUACIÓN:** EXÁMEN TRANSVERSAL  
**INSTITUCIÓN:** DUOC UC
**FECHA:** 28/11/2025

## Descripción del Proyecto

Auditoría de seguridad completa sobre una aplicación web vulnerable desarrollada en Python con Flask. El objetivo es identificar, explotar y remediar vulnerabilidades de seguridad, además de crear un plan preventivo integral.

## Estructura del Proyecto

\\\
examen-final-ocy1102/
├── app/                          # Aplicación Flask vulnerable
│   ├── vulnerable_flask_app.py
│   ├── create_db.py
│   ├── requirements.txt
│   └── Dockerfile
├── security-audit/               # Auditoría de seguridad
│   ├── vulnerabilities/          # Documentación de vulnerabilidades
│   ├── exploits/                 # Scripts de explotación
│   ├── fixed-code/               # Código corregido
│   └── evidence/                 # Capturas y evidencias
├── docs/                         # Documentación
│   └── informe-final.md
├── docker-compose.yml
└── README.md
\\\

## Ejecución de la Aplicación Vulnerable

\\\ash
docker-compose up --build
\\\

Acceder en: http://localhost:5000

## Eases del Proyecto

- Fase 1: Preparación del Entorno.
- Fase 2: Análisis y Detección de Vulnerabilidades.
- Fase 3: Explotación de Vulnerabilidades.
- Fase 4: Desarrollo de Código Seguro.
- Fase 5: Controles de Seguridad Adicionales.
- Fase 6: Plan de Seguridad.
- Fase 7: Documentación Final.

---
**Última actualización:** 28/11/2025 22:32
