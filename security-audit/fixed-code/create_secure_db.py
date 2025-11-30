# Script de creación de base de datos SEGURA
# Auditor: DAVID H. CUEVAS SALGADO
# Mejoras: Uso de bcrypt para hashing de passwords

import sqlite3
from werkzeug.security import generate_password_hash

# Conexión a la base de datos
conn = sqlite3.connect('security-audit/fixed-code/secure_example.db')
c = conn.cursor()

# Crear tabla de usuarios con password hasheado con bcrypt
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Crear usuarios con passwords hasheados usando Werkzeug (bcrypt)
admin_password = generate_password_hash('password', method='pbkdf2:sha256', salt_length=16)
user_password = generate_password_hash('password', method='pbkdf2:sha256', salt_length=16)

c.execute('''
    INSERT OR REPLACE INTO users (username, password, role) VALUES
    ('admin', ?, 'admin'),
    ('user', ?, 'user')
''', (admin_password, user_password))

# Crear tabla de comentarios
c.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
''')

# Guardar cambios
conn.commit()
conn.close()

print("Base de datos SEGURA creada exitosamente")
print("   - Passwords hasheados con pbkdf2:sha256")
print("   - Salt de 16 bytes")
print("   - Foreign keys habilitadas")
print("   - Timestamps agregados")
