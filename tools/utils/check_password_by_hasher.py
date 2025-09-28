# Script de comparación
import time
import bcrypt
from argon2 import PasswordHasher

password = input("Escribe una 'contrasenia' para probar el rendimiento de la encryptacion. >>")

ph = PasswordHasher()

# Benchmark bcrypt
start = time.time()
bcrypt.hashpw(password.encode(), bcrypt.gensalt())
bcrypt_time = time.time() - start

# Benchmark Argon2  
start = time.time()
ph.hash(password)
argon2_time = time.time() - start

print(f"bcrypt: {bcrypt_time:.3f}s")
print(f"Argon2: {argon2_time:.3f}s")
print(f"Argon2 es {argon2_time/bcrypt_time:.1f}x más lento")
