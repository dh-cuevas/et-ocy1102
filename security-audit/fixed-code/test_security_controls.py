# Script de Prueba de Controles de Seguridad
# Auditor: DAVID H. CUEVAS SALGADO

import requests
import time

BASE_URL = 'http://localhost:5000'

print("="*60)
print("Prueba de Controles de Seguridad Adicionales")
print("="*60)

# Test 1: Rate Limiting en Login
print("\n[TEST 1] Rate Limiting - Login")
print("-"*60)

for i in range(1, 7):
    response = requests.post(
        f'{BASE_URL}/login',
        data={'username': 'test', 'password': 'test'},
        allow_redirects=False
    )
    print(f"Intento {i}: Status {response.status_code}")
    
    if response.status_code == 429:
        print("Rate limit funcionando correctamente")
        break
    
    time.sleep(1)

# Test 2: Validación de Input
print("\n[TEST 2] Validación de Input")
print("-"*60)

from input_validator import InputValidator

validator = InputValidator()

test_inputs = [
    ('admin', 'username'),
    ('test<script>', 'username'),
    ('Comentario válido', 'comment'),
    ('<script>alert("XSS")</script>', 'comment')
]

for input_text, input_type in test_inputs:
    if input_type == 'username':
        valid, msg = validator.validate_username(input_text)
    else:
        valid, msg = validator.validate_comment(input_text)
    
    status = "VALID" if valid else "BLOCKED"
    print(f"{status} | {input_type}: '{input_text[:30]}' | {msg}")

# Test 3: Verificar logs
print("\n[TEST 3] Verificar Logging")
print("-"*60)

import os

if os.path.exists('logs/security.log'):
    print("Archivo de logs creado")
    with open('logs/security.log', 'r') as f:
        lines = f.readlines()
        print(f"Total de eventos loggeados: {len(lines)}")
        if lines:
            print(f"Último evento: {lines[-1].strip()}")
else:
    print("Archivo de logs no encontrado")

print("\n" + "="*60)
print("Pruebas de Controles Completadas")
print("="*60)
