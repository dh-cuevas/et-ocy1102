# Script para generar SECRET_KEY segura
# Auditor: DAVID H. CUEVAS SALGADO

import secrets

print("="*60)
print("Generador de SECRET_KEY Segura")
print("="*60)

# Generar secret key criptográficamente segura
secret_key = secrets.token_hex(32)

print(f"\nSECRET_KEY generada (64 caracteres):")
print(f"{secret_key}")

print(f"\nAgrega esta línea a tu archivo .env:")
print(f"SECRET_KEY={secret_key}")

print("\n" + "="*60)
print("IMPORTANTE: NO compartas esta clave públicamente")
print("="*60)
