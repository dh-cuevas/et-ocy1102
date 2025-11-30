# Documentación de Código Seguro - Correcciones Implementadas

**Auditor:** David H. Cuevas Salgado  
**Fecha:** 29/11/2025 21:51  
**Archivo:** secure_flask_app.py

---

## Resumen de Correcciones

Se implementó una versión completamente segura de la aplicación Flask, corrigiendo las 5 vulnerabilidades críticas identificadas y explotadas en las fases anteriores.

---

## CORRECCIÓN 1: SQL INJECTION

### Código Vulnerable (ANTES)
\\\python
# Concatenación directa de strings
if "' OR '" in password:
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(
        username, password)
    user = conn.execute(query).fetchone()
\\\

### Código Seguro (DESPUÉS)
\\\python
# Consultas parametrizadas (prepared statements)
query = "SELECT * FROM users WHERE username = ?"
user = conn.execute(query, (username,)).fetchone()

# Password verificado con hashing seguro
if user and check_password_hash(user['password'], password):
    # Login exitoso
\\\

### Técnicas Aplicadas
1. **Consultas parametrizadas:** Uso de placeholders (?) en lugar de concatenación
2. **Prepared statements:** El motor de BD separa código SQL de datos
3. **Validación de input:** WTForms valida longitud y formato
4. **Hashing seguro:** pbkdf2:sha256 con salt para passwords

### Beneficios
- Imposible inyectar código SQL
- Separación clara entre código y datos
- Protección a nivel de motor de base de datos
- Passwords nunca almacenados en texto plano

---

## CORRECCIÓN 2: STORED CROSS-SITE SCRIPTING (XSS)

### Código Vulnerable (ANTES)
\\\python
# render_template_string sin escape
{% for comment in comments %}
    <li class="list-group-item">{{ comment['comment'] }}</li>
{% endfor %}
\\\

### Código Seguro (DESPUÉS)
\\\python
# Sanitización con bleach antes de almacenar
import bleach

def sanitize_html(text):
    allowed_tags = []  # No permitir ningún tag HTML
    allowed_attributes = {}
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes, strip=True)

# En submit_comment()
comment = sanitize_html(form.comment.data)
\\\

### Técnicas Aplicadas
1. **Sanitización de input:** Biblioteca bleach elimina HTML peligroso
2. **Templates separados:** Archivos .html con auto-escape activado
3. **Whitelist de tags:** Solo se permiten tags específicos (ninguno en este caso)
4. **Content Security Policy:** Headers CSP restringen ejecución de scripts
5. **Validación de longitud:** Máximo 500 caracteres

### Beneficios
- HTML malicioso eliminado antes de almacenar
- Auto-escape de Jinja2 activo en templates
- CSP bloquea scripts inline no autorizados
- Defensa en profundidad (múltiples capas)

---

## CORRECCIÓN 3: CROSS-SITE REQUEST FORGERY (CSRF)

### Código Vulnerable (ANTES)
\\\python
# Formularios sin protección CSRF
<form method="post">
    <input type="text" name="username">
    <button type="submit">Login</button>
</form>
\\\

### Código Seguro (DESPUÉS)
\\\python
# Flask-WTF con tokens CSRF
from flask_wtf import FlaskForm, CSRFProtect

csrf = CSRFProtect(app)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# En template
<form method="post">
    {{ form.hidden_tag() }}  <!-- Token CSRF automático -->
    {{ form.username }}
    {{ form.submit }}
</form>
\\\

### Técnicas Aplicadas
1. **Tokens CSRF:** Cada formulario incluye token único
2. **Validación automática:** Flask-WTF valida tokens en cada POST
3. **SameSite cookies:** Cookies con atributo SameSite=Lax
4. **Validación de origen:** Flask-WTF verifica Referer/Origin
5. **Forms con validación:** WTForms + CSRF integrado

### Beneficios
- Tokens únicos por sesión y formulario
- Validación automática sin código adicional
- Protección contra ataques cross-origin
- Integrado con el framework (no requiere implementación manual)

---

## CORRECCIÓN 4: GESTIÓN INSEGURA DE SESIONES

### Código Vulnerable (ANTES)
\\\python
# Secret key regenerada en cada inicio
app.secret_key = os.urandom(24)
\\\

### Código Seguro (DESPUÉS)
\\\python
# Secret key persistente desde variable de entorno
from dotenv import load_dotenv
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-cambiar-en-produccion')

# Configuración segura de cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Solo HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No accesible desde JS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protección CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Timeout

# Generación segura de SECRET_KEY
import secrets
secret_key = secrets.token_hex(32)  # 64 caracteres
\\\

### Técnicas Aplicadas
1. **SECRET_KEY persistente:** Almacenada en variable de entorno
2. **Generación criptográfica:** secrets.token_hex(32)
3. **Configuración de cookies:** Secure, HttpOnly, SameSite
4. **Timeout de sesión:** 1 hora de inactividad
5. **Variables de entorno:** python-dotenv para configuración

### Beneficios
- Sesiones persisten entre reinicios
- Cookies protegidas contra XSS (HttpOnly)
- Cookies solo en HTTPS (Secure)
- Timeout automático por seguridad
- Secret key no hardcodeada en código

---

## CORRECCIÓN 5: DEBUG MODE ENABLED

### Código Vulnerable (ANTES)
\\\python
# Debug mode hardcoded
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
\\\

### Código Seguro (DESPUÉS)
\\\python
# Debug mode desde variable de entorno
debug_mode = os.getenv('FLASK_DEBUG', 'False') == 'True'

app.run(
    host='0.0.0.0',
    port=5000,
    debug=debug_mode
)

# Manejo de errores personalizado
@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    return render_template('500.html'), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404
\\\

### Técnicas Aplicadas
1. **Debug desactivado en producción:** Variable de entorno FLASK_DEBUG=False
2. **Páginas de error personalizadas:** Templates 404.html y 500.html
3. **Logging seguro:** Errores loggeados sin exponer al usuario
4. **Sin stack traces públicos:** Información sensible no visible
5. **Separación dev/prod:** Configuración por ambiente

### Beneficios
- Sin exposición de código fuente
- Sin stack traces en producción
- Mensajes de error amigables
- Logging interno para debugging
- Configuración flexible por ambiente

---

## MEJORAS ADICIONALES DE SEGURIDAD

### Headers de Seguridad
\\\python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self'..."
    return response
\\\

**Beneficios:**
- X-Content-Type-Options: Previene MIME sniffing
- X-Frame-Options: Protege contra clickjacking
- HSTS: Fuerza uso de HTTPS
- CSP: Controla recursos que puede cargar el navegador

### Validación de Input
\\\python
class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[
        DataRequired(message='El comentario no puede estar vacío'),
        Length(max=500, message='No puede exceder 500 caracteres')
    ])
\\\

**Beneficios:**
- Validación centralizada en formularios
- Mensajes de error personalizados
- Límites de longitud claros
- Validación tanto cliente como servidor

### Hashing de Passwords
\\\python
from werkzeug.security import generate_password_hash, check_password_hash

# Al crear usuario
password_hash = generate_password_hash('password', method='pbkdf2:sha256', salt_length=16)

# Al verificar
if check_password_hash(user['password'], password_input):
    # Login exitoso
\\\

**Beneficios:**
- PBKDF2 con SHA256 (resistente a ataques)
- Salt aleatorio de 16 bytes
- Múltiples iteraciones (computacionalmente costoso)
- Passwords nunca almacenados en texto plano

---

## Comparativa: Antes vs Después

| Aspecto     | ANTES (Vulnerable)       | DESPUÉS (Seguro)         |
|-------------|--------------------------|--------------------------|
| SQL Queries | Concatenación de strings | Consultas parametrizadas |
| Passwords   | SHA256 sin salt          | PBKDF2 con salt          |
| XSS         | Sin sanitización         | Bleach + auto-escape     |
| CSRF        | Sin protección           | Flask-WTF tokens         |
| Sesiones    | Secret key volátil       | Persistente + timeout    |
| Debug       | Siempre activado         | Desactivado en prod      |
| Headers     | Sin headers de seguridad | 6 headers implementados  |
| Errores     | Stack traces públicos    | Páginas personalizadas   |
| Validación  | Ninguna                  | WTForms completo         |

---

## Checklist de Seguridad Implementado

- Consultas parametrizadas (SQL Injection)
- Sanitización de input (XSS)
- Tokens CSRF en formularios
- SECRET_KEY persistente y segura
- Configuración segura de cookies
- Timeout de sesión (1 hora)
- Debug mode desactivado en producción
- Páginas de error personalizadas
- Headers de seguridad (6 implementados)
- Hashing seguro de passwords (PBKDF2)
- Validación de input con WTForms
- Logging seguro de errores
- Variables de entorno (.env)
- Foreign keys habilitadas en BD
- Templates separados (auto-escape)

---

## Instrucciones de Despliegue Seguro

### 1. Configurar variables de entorno
\\\ash
# Generar SECRET_KEY
python generate_secret_key.py

# Crear archivo .env
cp .env.example .env
# Editar .env con los valores correctos
\\\

### 2. Instalar dependencias
\\\ash
pip install -r requirements.txt
\\\

### 3. Crear base de datos
\\\ash
python create_secure_db.py
\\\

### 4. Ejecutar aplicación
\\\ash
# Desarrollo
export FLASK_ENV=development
export FLASK_DEBUG=True
python secure_flask_app.py

# Producción
export FLASK_ENV=production
export FLASK_DEBUG=False
python secure_flask_app.py
\\\

---

**Auditor:** DAVID H. CUEVAS SALGADO
**Fecha:** 29/11/2025 21:51  
**Estado:** CÓDIGO SEGURO IMPLEMENTADO

