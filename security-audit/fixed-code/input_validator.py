# Script de Validación Avanzada de Input
# Auditor: DAVID H. CUEVAS SALGADO

import re

class InputValidator:
    \"\"\"
    Clase para validación avanzada de inputs
    Implementa whitelist y blacklist patterns
    \"\"\"
    
    @staticmethod
    def validate_username(username):
        \"\"\"
        Valida username:
        - Solo alfanumérico y guión bajo
        - Longitud 3-50 caracteres
        - Sin caracteres especiales
        \"\"\"
        if not username or len(username) < 3 or len(username) > 50:
            return False, "Username debe tener entre 3 y 50 caracteres"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username solo puede contener letras, números y guión bajo"
        
        return True, "Valid"
    
    @staticmethod
    def validate_comment(comment):
        \"\"\"
        Valida comentarios:
        - Sin tags HTML
        - Longitud máxima 500 caracteres
        - Sin caracteres peligrosos
        \"\"\"
        if not comment or len(comment) > 500:
            return False, "Comentario debe tener entre 1 y 500 caracteres"
        
        # Detectar tags HTML
        if re.search(r'<[^>]+>', comment):
            return False, "No se permiten tags HTML"
        
        # Detectar scripts
        dangerous_patterns = [
            r'<script',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'onclick='
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                return False, f"Patrón peligroso detectado: {pattern}"
        
        return True, "Valid"
    
    @staticmethod
    def sanitize_sql_input(text):
        \"\"\"
        Sanitiza input para prevenir SQL Injection
        NOTA: Esto es una capa adicional, las consultas parametrizadas son la defensa principal
        \"\"\"
        dangerous_sql = [
            "';", "'--", "' OR", "' AND", "UNION", "DROP", "DELETE", "INSERT", 
            "UPDATE", "EXEC", "EXECUTE", "SCRIPT", "JAVASCRIPT"
        ]
        
        for pattern in dangerous_sql:
            if pattern.upper() in text.upper():
                return text.replace(pattern, ""), f"Patrón SQL peligroso removido: {pattern}"
        
        return text, "Clean"

# Ejemplos de uso
if __name__ == '__main__':
    validator = InputValidator()
    
    print("="*60)
    print("Ejemplos de Validación de Input")
    print("="*60)
    
    # Test username
    usernames = ['admin', 'user123', 'test_user', 'ab', 'admin<script>', 'user; DROP TABLE']
    
    print("\n[VALIDACIÓN DE USERNAMES]")
    for username in usernames:
        valid, message = validator.validate_username(username)
        status = "VALID" if valid else "INVALID"
        print(f"{status} | '{username}' | {message}")
    
    # Test comments
    comments = [
        'Comentario normal',
        '<script>alert("XSS")</script>',
        'Comentario con <b>HTML</b>',
        'x' * 501,  # Too long
        'Comentario con javascript:alert(1)'
    ]
    
    print("\n[VALIDACIÓN DE COMENTARIOS]")
    for comment in comments:
        valid, message = validator.validate_comment(comment)
        status = "VALID" if valid else "INVALID"
        preview = comment[:30] + '...' if len(comment) > 30 else comment
        print(f"{status} | '{preview}' | {message}")
    
    print("\n" + "="*60)
