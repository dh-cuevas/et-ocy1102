# Examen Final - OCY1102 Ciberseguridad en Desarrollo
## Auditoria de Seguridad en Aplicación Web Flask

**ALUMNO** DAVID H. CUEVAS SALGADO 

**ASIGNATURA:** OCY1102 - CIBERSEGURIDAD EN DESARROLLO 

**EVALUACIÓN:** EXÁMEN TRANSVERSAL  

**INSTITUCIÓN:** DUOC UC

**FECHA:** 28/11/2025

---

## Descripción del Proyecto

Auditoría de seguridad completa sobre una aplicación web vulnerable desarrollada en Python con Flask. 

---

## Objetivos

1. Analizar con herramientas OWASP ZAP Burp y Suite para identificar 5 fallos de seguridad.
2. Determinar las causas de los 5 de las vulnerabilidades que serán identificadas*.
3. Proponer y aplicar medidas correctivas mediante la implementación de programación defensiva y código seguro para las vulnerabilidades.
4. Implementar controles para prevenir ataques de penetración como SQL Injection, XSS y CSRF.
5. Crear un plan de seguridad que contenga políticas, monitoreo, y respuesta ante fallos de seguridad.
6. Documentar todo el proceso con evidencias.

---

## Estructura del Proyecto
```
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
```
---

## Tecnologías Utilizadas

### Aplicación
- **Python 3.11** - Lenguaje de programación
- **Flask 2.3.0** - Framework web
- **SQLite3** - Base de datos
- **Jinja2** - Motor de templates

### Herramientas de Seguridad
- **OWASP ZAP** - Escaneo de vulnerabilidades web
- **Docker** - Containerización de la aplicación
- **Git/GitHub** - Control de versiones

### Desarrollo
- **VS Code** - Editor de código
- **PowerShell** - Automatización de scripts
- **curl** - Pruebas de endpoints

---

## Cómo Ejecutar

### Requisitos previos
- Docker Desktop instalado
- Git instalado
- Python 3.11+ (opcional, para scripts locales)

## Ejecución de la Aplicación Vulnerable

\\\bash
# Clonar repositorio
git clone https://github.com/dh-cuevas/et-ocy1102.git
cd et-ocy1102

# Construir y ejecutar con Docker
docker-compose up --build -d

# Verificar que está corriendo
docker-compose ps
\\\

Acceder en: http://localhost:5000

### Credenciales de Prueba
- **Admin:** admin / password
- **User:** user / password

### Ejecución local
```bash
cd src
python create_db.py
python vulnerable_flask_app.py
```
### Detener Aplicación

\\\bash
docker-compose down
\\\

---

## Eases del Proyecto

- Fase 1: Preparación del Entorno.
- Fase 2: Análisis y Detección de Vulnerabilidades.
- Fase 3: Explotación de Vulnerabilidades.
- Fase 4: Desarrollo de Código Seguro.
- Fase 5: Controles de Seguridad Adicionales.
- Fase 6: Plan de Seguridad.
- Fase 7: Documentación Final.

---

## Vulnerabilidades Identificadas

1. **SQL Injection** (Crítica - CVSS 9.8)
2. **Stored Cross-Site Scripting - XSS** (Alta - CVSS 7.5)
3. **Cross-Site Request Forgery - CSRF** (Media - CVSS 6.5)
4. **Gestión Insegura de Sesiones** (Media - CVSS 5.3)
5. **Debug Mode Habilitado** (Media - CVSS 5.0)

---

**Última actualización:** 28/11/2025 22:32
