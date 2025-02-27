import os

def generar_clave(longitud=16):
    """Genera una clave aleatoria de 16, 24 o 32 bytes para AES."""
    if longitud not in [16, 24, 32]:
        raise ValueError("La clave debe tener 16, 24 o 32 bytes.")
    return os.urandom(longitud)

def generar_iv():
    """Genera un vector de inicialización (IV) aleatorio de 16 bytes para AES."""
    return os.urandom(16)

clave = generar_clave(16)  # Para AES-128
iv = generar_iv()

print(f"Clave: {clave.hex()}")
print(f"IV: {iv.hex()}")

