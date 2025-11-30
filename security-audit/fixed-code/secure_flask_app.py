# Aplicación Flask SEGURA
# Auditor: DAVID H. CUEVAS SALGADO
# Fecha: 29/11/2025
# 
# VULNERABILIDADES CORREGIDAS:
# 1. SQL Injection → Consultas parametrizadas
# 2. XSS → Sanitización con bleach + escape automático
# 3. CSRF → Flask-WTF tokens
# 4. Sesiones → SECRET_KEY persistente + configuración segura
# 5. Debug Mode → Desactivado en producción

from flask import Flask, request, render_template, session, redirect, url_for, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from werkzeug.security import check_password_hash
import sqlite3
import os
import bleach
from dotenv import load_dotenv
from datetime import timedelta

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)

# =============================================================================
# FIX 4: GESTIÓN SEGURA DE SESIONES
# =============================================================================
# SECRET_KEY persistente desde variable de entorno
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-cambiar-en-produccion')

# Configuración segura de cookies de sesión
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# =============================================================================
# FIX 3: PROTECCIÓN CSRF
# =============================================================================
csrf = CSRFProtect(app)

# =============================================================================
# FORMULARIOS CON VALIDACIÓN Y CSRF
# =============================================================================
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='El usuario es requerido'),
        Length(min=3, max=50, message='Usuario debe tener entre 3 y 50 caracteres')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='La contraseña es requerida')
    ])
    submit = SubmitField('Login')

class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[
        DataRequired(message='El comentario no puede estar vacío'),
        Length(max=500, message='El comentario no puede exceder 500 caracteres')
    ])
    submit = SubmitField('Submit Comment')

# =============================================================================
# FUNCIONES AUXILIARES SEGURAS
# =============================================================================
def get_db_connection():
    \"\"\"Conexión segura a la base de datos con row_factory\"\"\"
    conn = sqlite3.connect(os.getenv('DATABASE_PATH', 'secure_example.db'))
    conn.row_factory = sqlite3.Row
    # Habilitar foreign keys
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def sanitize_html(text):
    \"\"\"
    FIX 2: PREVENCIÓN DE XSS
    Sanitiza HTML permitiendo solo tags seguros
    \"\"\"
    allowed_tags = []  # No permitir ningún tag HTML
    allowed_attributes = {}
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes, strip=True)

# =============================================================================
# SECURITY HEADERS
# =============================================================================
@app.after_request
def set_security_headers(response):
    \"\"\"Agregar headers de seguridad a todas las respuestas\"\"\"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://maxcdn.bootstrapcdn.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com;"
    # No exponer versión del servidor
    response.headers.pop('Server', None)
    return response

# =============================================================================
# MANEJO DE ERRORES PERSONALIZADO
# =============================================================================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    # FIX 5: No exponer stack trace en producción
    app.logger.error(f'Server Error: {error}')
    return render_template('500.html'), 500

# =============================================================================
# RUTAS DE LA APLICACIÓN
# =============================================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        conn = get_db_connection()
        
        # =================================================================
        # FIX 1: PREVENCIÓN DE SQL INJECTION
        # Uso de consultas parametrizadas (prepared statements)
        # =================================================================
        query = \"SELECT * FROM users WHERE username = ?\"
        user = conn.execute(query, (username,)).fetchone()
        conn.close()
        
        # Verificar password con hashing seguro
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['username'] = user['username']
            session.permanent = True
            flash('Login exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales inválidas', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    username = session.get('username', 'Usuario')
    
    conn = get_db_connection()
    
    # Consulta parametrizada segura
    comments = conn.execute(
        \"SELECT comment, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC\",
        (user_id,)
    ).fetchall()
    conn.close()
    
    form = CommentForm()
    return render_template('dashboard.html', username=username, comments=comments, form=form)

@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero', 'warning')
        return redirect(url_for('login'))
    
    form = CommentForm()
    
    if form.validate_on_submit():
        # =================================================================
        # FIX 2: PREVENCIÓN DE XSS
        # Sanitización del input antes de almacenar
        # =================================================================
        comment = sanitize_html(form.comment.data)
        user_id = session['user_id']
        
        conn = get_db_connection()
        # Consulta parametrizada
        conn.execute(
            \"INSERT INTO comments (user_id, comment) VALUES (?, ?)\",
            (user_id, comment)
        )
        conn.commit()
        conn.close()
        
        flash('Comentario publicado exitosamente', 'success')
    else:
        flash('Error al publicar comentario', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Acceso denegado', 'danger')
        return redirect(url_for('login'))
    
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada exitosamente', 'info')
    return redirect(url_for('index'))

# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================
if __name__ == '__main__':
    # FIX 5: DEBUG MODE DESACTIVADO EN PRODUCCIÓN
    debug_mode = os.getenv('FLASK_DEBUG', 'False') == 'True'
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_mode
    )
