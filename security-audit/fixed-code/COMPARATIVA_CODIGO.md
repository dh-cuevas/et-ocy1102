# Comparativa Código Vulnerable vs Código Seguro

**Auditor:** DAVID H. CUEVAS SALGADO
**Fecha:** 29/11/2025 21:54

---

## SQL INJECTION

### VULNERABLE
\\\python
# vulnerable_flask_app.py
if "' OR '" in password:
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(
        username, password)
    user = conn.execute(query).fetchone()
\\\

### SEGURO
\\\python
# secure_flask_app.py
query = "SELECT * FROM users WHERE username = ?"
user = conn.execute(query, (username,)).fetchone()

if user and check_password_hash(user['password'], password):
    # Login exitoso
\\\

---

## STORED XSS

### VULNERABLE
\\\python
# vulnerable_flask_app.py
comment = request.form['comment']
conn.execute("INSERT INTO comments (user_id, comment) VALUES (?, ?)", (user_id, comment))

# En template con render_template_string
{{ comment['comment'] }}  # Sin escape
\\\

### SEGURO
\\\python
# secure_flask_app.py
import bleach

def sanitize_html(text):
    return bleach.clean(text, tags=[], attributes={}, strip=True)

comment = sanitize_html(form.comment.data)
conn.execute("INSERT INTO comments (user_id, comment) VALUES (?, ?)", (user_id, comment))

# Template separado (.html) con auto-escape
{{ comment['comment'] }}  # Auto-escaped
\\\

---

## CSRF

### VULNERABLE
\\\html
<!-- vulnerable_flask_app.py -->
<form method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
\\\

### SEGURO
\\\python
# secure_flask_app.py
from flask_wtf import FlaskForm, CSRFProtect

csrf = CSRFProtect(app)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
\\\

\\\html
<!-- login.html -->
<form method="post">
    {{ form.hidden_tag() }}  <!-- Token CSRF -->
    {{ form.username(class="form-control") }}
    {{ form.password(class="form-control") }}
    {{ form.submit(class="btn btn-primary") }}
</form>
\\\

---

## GESTIÓN DE SESIONES

### VULNERABLE
\\\python
# vulnerable_flask_app.py
app.secret_key = os.urandom(24)  # Regenerada en cada inicio
\\\

### SEGURO
\\\python
# secure_flask_app.py
from dotenv import load_dotenv
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
\\\

---

## DEBUG MODE

### VULNERABLE
\\\python
# vulnerable_flask_app.py
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
\\\

### SEGURO
\\\python
# secure_flask_app.py
debug_mode = os.getenv('FLASK_DEBUG', 'False') == 'True'

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
\\\

---

## HASHING DE PASSWORDS

### VULNERABLE
\\\python
# create_db.py
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
\\\

### SEGURO
\\\python
# create_secure_db.py
from werkzeug.security import generate_password_hash

password_hash = generate_password_hash('password', method='pbkdf2:sha256', salt_length=16)
\\\

---

**Total de líneas de código refactorizadas:** ~300+  
**Vulnerabilidades corregidas:** 5/5 (100%)  
**Controles de seguridad agregados:** 15+

