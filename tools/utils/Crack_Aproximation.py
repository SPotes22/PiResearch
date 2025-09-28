# SPDX-License-Identifier: GPL-3.0-or-later
#
# Este archivo hace parte de Paranoid Vault.
# Copyright (C) 2025  Santiago Potes Giraldo
#
# Este programa es software libre: puede redistribuirlo y/o modificarlo
# bajo los términos de la Licencia Pública General de GNU publicada por
# la Free Software Foundation, ya sea la versión 3 de la Licencia, o
# (a su elección) cualquier versión posterior.
#
# Este programa se distribuye con la esperanza de que sea útil,
# pero SIN GARANTÍA ALGUNA; ni siquiera la garantía implícita
# de COMERCIABILIDAD o IDONEIDAD PARA UN PROPÓSITO PARTICULAR.
# Consulte la Licencia Pública General de GNU para más detalles.
#
# Debería haber recibido una copia de la Licencia Pública General de GNU
# junto con este programa. En caso contrario, consulte <https://www.gnu.org/licenses/>.

import math

def password_entropy(password):
    """Calcula la entropía estimada de una contraseña en bits."""
    charset_size = 0

    lowers = any(c.islower() for c in password)
    uppers = any(c.isupper() for c in password)
    digits = any(c.isdigit() for c in password)
    symbols = any(not c.isalnum() for c in password)

    if lowers:
        charset_size += 26
    if uppers:
        charset_size += 26
    if digits:
        charset_size += 10
    if symbols:
        # aprox cantidad de símbolos ASCII imprimibles
        charset_size += 32  

    entropy = math.log2(charset_size ** len(password))
    return entropy

def crack_time(password, guesses_per_second):
    """Devuelve el tiempo en segundos para crackear (en promedio)."""
    charset_size = 0

    lowers = any(c.islower() for c in password)
    uppers = any(c.isupper() for c in password)
    digits = any(c.isdigit() for c in password)
    symbols = any(not c.isalnum() for c in password)

    if lowers:
        charset_size += 26
    if uppers:
        charset_size += 26
    if digits:
        charset_size += 10
    if symbols:
        charset_size += 32

    total_combinations = charset_size ** len(password)
    # promedio: la mitad del espacio total
    avg_attempts = total_combinations / 2
    seconds = avg_attempts / guesses_per_second
    return seconds

# Ejemplo
password = input('entra la contrasenia a revisar >> ')
gps = 1e12  # velocidad estimada de un atacante con hardware especializado

entropy_bits = password_entropy(password)
time_seconds = crack_time(password, gps)

def human_time(seconds):
    units = [
        ("años", 60*60*24*365),
        ("días", 60*60*24),
        ("horas", 60*60),
        ("minutos", 60),
        ("segundos", 1)
    ]
    result = []
    for name, count in units:
        value = int(seconds // count)
        if value:
            seconds %= count
            result.append(f"{value} {name}")
    return ", ".join(result)

print(f"Contraseña: {password}")
print(f"Entropía estimada: {entropy_bits:.2f} bits")
print(f"Tiempo de crackeo estimado: {human_time(time_seconds)}")

