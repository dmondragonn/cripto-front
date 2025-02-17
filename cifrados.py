from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes

                         
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

# Permutacion


def cifrado_permutacion_encriptar(texto_plano, clave):

    permutacion = [int(x) - 1 for x in clave]
    longitud_clave = len(permutacion)

    bloques = [texto_plano[i:i + longitud_clave]
               for i in range(0, len(texto_plano), longitud_clave)]

    texto_encriptado = []

    for bloque in bloques:

        bloque = bloque.ljust(longitud_clave)

        bloque_encriptado = ''.join(bloque[i] for i in permutacion)
        texto_encriptado.append(bloque_encriptado)

    return ''.join(texto_encriptado)


def cifrado_permutacion_desencriptar(texto_cifrado, clave):

    permutacion = [int(x) - 1 for x in clave]
    longitud_clave = len(permutacion)

    inversa_permutacion = [0] * longitud_clave
    for i, p in enumerate(permutacion):
        inversa_permutacion[p] = i

    bloques = [texto_cifrado[i:i + longitud_clave]
               for i in range(0, len(texto_cifrado), longitud_clave)]

    texto_desencriptado = []

    for bloque in bloques:

        bloque_desencriptado = ''.join(bloque[i] for i in inversa_permutacion)
        texto_desencriptado.append(bloque_desencriptado)

    return ''.join(texto_desencriptado).rstrip()

def generate_keys(bits=2048):  #Claves publicas y privadas
    key = ElGamal.generate(bits, get_random_bytes)
    return key, key.publickey()

def elgamal_encrypt(public_key, message): #Cifrado de mensaje Clave pública
    m = bytes_to_long(message.encode())  
    k = randint(1, public_key.p - 1)  # Generar número aleatorio k
    ciphertext = public_key.encrypt(m, k)  # Cifrar mensaje
    return ciphertext

def elgamal_decrypt(private_key, ciphertext):#Desceifrado 
    decrypted_m = private_key.decrypt(ciphertext)
    return long_to_bytes(decrypted_m).decode()
