# Controles de Seguridad Adicionales - Fase 5

**Auditor:** David H. Cuevas Salgado  
**Fecha:** 30/11/2025 13:48

---

## Controles Implementados

### 1. RATE LIMITING - Protección contra Brute Force

**Biblioteca:** Flask-Limiter

**Configuración:**
\\\python
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)
\\\

**Límites Específicos:**
- **Login:** 5 intentos por minuto
- **Submit Comment:** 10 comentarios por minuto
- **Global:** 200 peticiones por día, 50 por hora

**Beneficios:**
- Previene ataques de fuerza bruta en login
- Evita spam de comentarios
- Protege contra DoS de aplicación
- Rate limit por IP
- Respuesta HTTP 429 cuando se excede

**Implementación:**
\\\python
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # ...
\\\

---

### 2. LOGGING DE EVENTOS DE SEGURIDAD

**Sistema:** Python logging + RotatingFileHandler

**Configuración:**
\\\python
file_handler = RotatingFileHandler(
    'logs/security.log',
    maxBytes=10240000,  # 10MB
    backupCount=10
)
\\\

**Eventos Loggeados:**
- Login exitoso/fallido
- Accesos no autorizados
- Publicación de comentarios
- Acceso al panel de administración
- Rate limit excedido
- Errores 404 y 500
- Sanitización de HTML detectada
- Logout de usuarios

**Formato de Log:**
\\\
[2024-11-29 15:30:45] INFO [SECURITY] LOGIN_SUCCESS | User: admin | IP: 192.168.1.100 | Details: Username: admin
[2024-11-29 15:31:12] WARNING [SECURITY] LOGIN_FAILED | User: anonymous | IP: 192.168.1.105 | Details: Username: hacker
[2024-11-29 15:32:00] WARNING [SECURITY] RATE_LIMIT_EXCEEDED | User: admin | IP: 192.168.1.100 | Details: Endpoint: login
\\\

**Función de Logging:**
\\\python
def log_security_event(event_type, details, severity='INFO'):
    log_message = f'[SECURITY] {event_type} | User: {session.get("username", "anonymous")} | IP: {request.remote_addr} | Details: {details}'
    
    if severity == 'WARNING':
        app.logger.warning(log_message)
    elif severity == 'ERROR':
        app.logger.error(log_message)
    else:
        app.logger.info(log_message)
\\\

---

### 3. VALIDACIÓN AVANZADA DE INPUT

**Biblioteca:** WTForms Validators + Regexp

**Validaciones Implementadas:**

#### Username
\\\python
username = StringField('Username', validators=[
    DataRequired(),
    Length(min=3, max=50),
    Regexp('^[a-zA-Z0-9_]+$', message='Solo letras, números y guión bajo')
])
\\\

- Solo alfanumérico + guión bajo
- Longitud 3-50 caracteres
- Sin espacios ni caracteres especiales

#### Password
\\\python
password = PasswordField('Password', validators=[
    DataRequired(),
    Length(min=8, message='Mínimo 8 caracteres')
])
\\\

- Mínimo 8 caracteres
- Campo requerido

#### Comment
\\\python
comment = TextAreaField('Comment', validators=[
    DataRequired(),
    Length(min=1, max=500),
    Regexp('^[^<>]*$', message='No se permiten < o >')
])
\\\

- Longitud 1-500 caracteres
- Sin caracteres < o > (prevención básica XSS)
- Validación adicional a sanitización

---

### 4. CLASE INPUTVALIDATOR

**Archivo:** input_validator.py

**Métodos:**

#### validate_username(username)
- Verifica formato alfanumérico
- Valida longitud
- Retorna (bool, mensaje)

#### validate_comment(comment)
- Detecta tags HTML
- Busca patrones peligrosos (script, javascript:, onerror)
- Valida longitud máxima

#### sanitize_sql_input(text)
- Capa adicional de protección
- Detecta keywords SQL peligrosos
- NOTA: Las consultas parametrizadas son la defensa principal

**Ejemplo de uso:**
\\\python
validator = InputValidator()
valid, message = validator.validate_comment(user_input)

if not valid:
    flash(message, 'danger')
    return redirect(url_for('dashboard'))
\\\

---

### 5. HEADERS DE SEGURIDAD ADICIONALES

**Nuevo header agregado:**
\\\python
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
\\\

**Beneficio:**
- Desactiva APIs del navegador no utilizadas
- Reduce superficie de ataque
- Previene acceso no autorizado a hardware

---

### 6. MANEJO DE ERRORES MEJORADO

**Error 429 - Too Many Requests:**
\\\python
@app.errorhandler(429)
def ratelimit_handler(e):
    log_security_event('RATE_LIMIT_EXCEEDED', f'Endpoint: {request.endpoint}', 'WARNING')
    return render_template('429.html'), 429
\\\

- Página personalizada cuando se excede rate limit
- Log del evento
- Información clara al usuario

---

## Matriz de Controles de Seguridad

| Control            | Vulnerabilidad Mitigada | Nivel | Status |
|--------------------|-------------------------|-------|--------|
| Rate Limiting      | Brute Force             | Alto  |   Ok   |
| Security Logging   | Auditoría               | Medio |   Ok   |
| Input Validation   | XSS, SQLi               | Alto  |   Ok   |
| Regexp Validators  | Injection               | Medio |   Ok   |
| Permissions-Policy | Privacy Leak            | Bajo  |   Ok   |
| Error 429 Handler  | DoS                     | Medio |   Ok   |

---

## Mejores Prácticas Aplicadas

1. **Defensa en Profundidad:** Múltiples capas de validación
2. **Principio de Mínimo Privilegio:** Rate limits restrictivos
3. **Logging Comprehensivo:** Todos los eventos de seguridad registrados
4. **Fail Secure:** Errores de validación bloquean acción
5. **Whitelist > Blacklist:** Validación positiva en inputs

---

## Instrucciones de Uso

### Ejecutar aplicación con controles adicionales:
\\\ash
# Instalar dependencias
pip install -r requirements-enhanced.txt

# Crear directorio de logs
mkdir logs

# Ejecutar aplicación
python enhanced_flask_app.py
\\\

### Probar Rate Limiting:
\\\ash
# Intentar login 6 veces rápidamente
for i in {1..6}; do
    curl -X POST http://localhost:5000/login -d "username=test&password=test"
done
# El 6to intento debería retornar 429
\\\

### Ver logs de seguridad:
\\\ash
tail -f logs/security.log
\\\

---

**Auditor:** DAVID H. CUEVAS SALGADO  
**Estado:** CONTROLES ADICIONALES IMPLEMENTADOS

