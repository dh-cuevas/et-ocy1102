# Aplicación Flask con Rate Limiting
# Auditor: DAVID H. CUEVAS SALGADO
# Control Adicional: Protección contra Brute Force

from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
from werkzeug.security import check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
import bleach
from dotenv import load_dotenv
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler

load_dotenv()

app = Flask(__name__)

# =============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# =============================================================================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-cambiar-en-produccion')
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

csrf = CSRFProtect(app)

# =============================================================================
# RATE LIMITING - Protección contra Brute Force
# =============================================================================
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# =============================================================================
# LOGGING DE SEGURIDAD
# =============================================================================
if not os.path.exists('logs'):
    os.mkdir('logs')

# Handler para archivo de log
file_handler = RotatingFileHandler(
    'logs/security.log',
    maxBytes=10240000,  # 10MB
    backupCount=10
)
file_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Aplicación Flask Segura iniciada')

# =============================================================================
# FORMULARIOS CON VALIDACIÓN AVANZADA
# =============================================================================
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='El usuario es requerido'),
        Length(min=3, max=50, message='Usuario debe tener entre 3 y 50 caracteres'),
        Regexp('^[a-zA-Z0-9_]+$', message='Solo letras, números y guión bajo permitidos')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='La contraseña es requerida'),
        Length(min=8, message='La contraseña debe tener al menos 8 caracteres')
    ])
    submit = SubmitField('Login')

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[
        DataRequired(message='El comentario no puede estar vacío'),
        Length(min=1, max=500, message='El comentario debe tener entre 1 y 500 caracteres'),
        Regexp('^[^<>]*$', message='No se permiten caracteres < o >')
    ])
    submit = SubmitField('Submit Comment')

# =============================================================================
# FUNCIONES AUXILIARES
# =============================================================================
def get_db_connection():
    conn = sqlite3.connect(os.getenv('DATABASE_PATH', 'secure_example.db'))
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def sanitize_html(text):
    allowed_tags = []
    allowed_attributes = {}
    sanitized = bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes, strip=True)
    # Logging de sanitización
    if text != sanitized:
        app.logger.warning(f'HTML sanitizado: Original length={len(text)}, Sanitized length={len(sanitized)}')
    return sanitized

def log_security_event(event_type, details, severity='INFO'):
    \"\"\"
    Registra eventos de seguridad importantes
    \"\"\"
    log_message = f'[SECURITY] {event_type} | User: {session.get("username", "anonymous")} | IP: {request.remote_addr} | Details: {details}'
    
    if severity == 'WARNING':
        app.logger.warning(log_message)
    elif severity == 'ERROR':
        app.logger.error(log_message)
    else:
        app.logger.info(log_message)

# =============================================================================
# SECURITY HEADERS
# =============================================================================
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com;"
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers.pop('Server', None)
    return response

# =============================================================================
# MANEJO DE ERRORES
# =============================================================================
@app.errorhandler(404)
def not_found_error(error):
    log_security_event('404_ERROR', f'Path: {request.path}', 'WARNING')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    log_security_event('500_ERROR', f'Error: {str(error)}', 'ERROR')
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    log_security_event('RATE_LIMIT_EXCEEDED', f'Endpoint: {request.endpoint}', 'WARNING')
    return render_template('429.html'), 429

# =============================================================================
# RUTAS DE LA APLICACIÓN
# =============================================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Máximo 5 intentos por minuto
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        conn = get_db_connection()
        query = "SELECT * FROM users WHERE username = ?"
        user = conn.execute(query, (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['username'] = user['username']
            session.permanent = True
            
            log_security_event('LOGIN_SUCCESS', f'Username: {username}', 'INFO')
            flash('Login exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_security_event('LOGIN_FAILED', f'Username: {username}', 'WARNING')
            flash('Credenciales inválidas', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        log_security_event('UNAUTHORIZED_ACCESS', 'Dashboard without login', 'WARNING')
        flash('Debes iniciar sesión primero', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    username = session.get('username', 'Usuario')
    
    conn = get_db_connection()
    comments = conn.execute(
        "SELECT comment, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    
    form = CommentForm()
    return render_template('dashboard.html', username=username, comments=comments, form=form)

@app.route('/submit_comment', methods=['POST'])
@limiter.limit("10 per minute")  # Máximo 10 comentarios por minuto
def submit_comment():
    if 'user_id' not in session:
        log_security_event('UNAUTHORIZED_COMMENT', 'Comment without login', 'WARNING')
        flash('Debes iniciar sesión primero', 'warning')
        return redirect(url_for('login'))
    
    form = CommentForm()
    
    if form.validate_on_submit():
        comment = sanitize_html(form.comment.data)
        user_id = session['user_id']
        
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO comments (user_id, comment) VALUES (?, ?)",
            (user_id, comment)
        )
        conn.commit()
        conn.close()
        
        log_security_event('COMMENT_POSTED', f'Length: {len(comment)}', 'INFO')
        flash('Comentario publicado exitosamente', 'success')
    else:
        log_security_event('COMMENT_VALIDATION_FAILED', f'Errors: {form.errors}', 'WARNING')
        flash('Error al publicar comentario', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        log_security_event('UNAUTHORIZED_ADMIN_ACCESS', f'User: {session.get("username", "unknown")}', 'WARNING')
        flash('Acceso denegado', 'danger')
        return redirect(url_for('login'))
    
    log_security_event('ADMIN_ACCESS', 'Admin panel accessed', 'INFO')
    return render_template('admin.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    log_security_event('LOGOUT', f'Username: {username}', 'INFO')
    flash('Sesión cerrada exitosamente', 'info')
    return redirect(url_for('index'))

# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================
if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'False') == 'True'
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_mode
    )
