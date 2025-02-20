from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes


#Desplazamiento

def shift_cipher_encrypt(text, key):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + key) % 26 + base)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char
    return encrypted_text


# Permutacion
        
def cifrado_permutacion_encriptar(texto_plano, clave):
    permutacion = [int(x) - 1 for x in clave]
    longitud_bloque = len(permutacion)
    
    # Añadir espacios como relleno
    padding = (longitud_bloque - (len(texto_plano) % longitud_bloque)) % longitud_bloque
    texto_plano += ' ' * padding  # Relleno con espacios
    
    # Cifrar el texto
    bloques = [texto_plano[i:i+longitud_bloque] for i in range(0, len(texto_plano), longitud_bloque)]
    texto_cifrado = ''.join([''.join([bloque[i] for i in permutacion]) for bloque in bloques])
    
    # Eliminar los espacios adicionales antes de mostrar
    texto_cifrado_sin_espacios = texto_cifrado[:len(texto_plano) - padding]
    
    return texto_cifrado_sin_espacios

def cifrado_permutacion_desencriptar(texto_cifrado, clave):
    permutacion = [int(x) - 1 for x in clave]
    longitud_bloque = len(permutacion)
    
    # Añadir espacios temporalmente para completar los bloques
    padding = (longitud_bloque - (len(texto_cifrado) % longitud_bloque)) % longitud_bloque
    texto_cifrado += ' ' * padding  # Relleno con espacios
    
    # Calcular permutación inversa
    inversa = [0] * longitud_bloque
    for i, pos in enumerate(permutacion):
        inversa[pos] = i
    
    # Descifrar el texto
    bloques = [texto_cifrado[i:i+longitud_bloque] for i in range(0, len(texto_cifrado), longitud_bloque)]
    texto_plano = ''.join([''.join([bloque[i] for i in inversa]) for bloque in bloques])
    
    # Eliminar los espacios adicionales después de descifrar
    texto_plano = texto_plano.rstrip()
    
    return texto_plano


# Vigenere


def cifrado_vigenere_encriptar(texto_plano, clave):

    texto_encriptado = []
    clave = clave.upper()
    indice_clave = 0

    for caracter in texto_plano:
        if caracter.isalpha():
            desplazamiento = ord(clave[indice_clave]) - ord('A')
            if caracter.isupper():
                caracter_encriptado = chr(
                    (ord(caracter) - ord('A') + desplazamiento) % 26 + ord('A'))
            else:
                caracter_encriptado = chr(
                    (ord(caracter) - ord('a') + desplazamiento) % 26 + ord('a'))
            texto_encriptado.append(caracter_encriptado)
            indice_clave = (indice_clave + 1) % len(clave)
        else:
            # Caracteres no alfabéticos no se encriptan
            texto_encriptado.append(caracter)

    return ''.join(texto_encriptado)


def cifrado_vigenere_desencriptar(texto_cifrado, clave):

    texto_desencriptado = []
    clave = clave.upper()
    indice_clave = 0

    for caracter in texto_cifrado:
        if caracter.isalpha():
            desplazamiento = ord(clave[indice_clave]) - ord('A')
            if caracter.isupper():
                caracter_desencriptado = chr(
                    (ord(caracter) - ord('A') - desplazamiento) % 26 + ord('A'))
            else:
                caracter_desencriptado = chr(
                    (ord(caracter) - ord('a') - desplazamiento) % 26 + ord('a'))
            texto_desencriptado.append(caracter_desencriptado)
            indice_clave = (indice_clave + 1) % len(clave)
        else:
            # Caracteres no alfabéticos no se desencriptan
            texto_desencriptado.append(caracter)

    return ''.join(texto_desencriptado)




# ElGamal

def generate_keys(bits=512): # Genera una private key y una public

    key = ElGamal.generate(bits, get_random_bytes)
    return key, key.publickey()


def elgamal_encrypt(public_key, message):

    m = bytes_to_long(message.encode())
    k = randint(1, int(public_key.p - 2))

    p, g, y = int(public_key.p), int(public_key.g), int(public_key.y)

    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)


def elgamal_decrypt(private_key, ciphertext):

    c1, c2 = ciphertext

    p, x = int(private_key.p), int(private_key.x)

    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    return long_to_bytes(m).decode()
