import io
import json
import math
import random
import string
from os.path import join
from tempfile import gettempdir

import numpy as np
from PIL import Image, PngImagePlugin

from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_OAEP, DES3
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import hashlib


from sympy import Matrix

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




# ElGamal---------------

# Generación de claves
def generate_keys(bits=512):
    key = ElGamal.generate(bits, get_random_bytes)
    public_key = (int(key.p), int(key.g), int(key.y))  # Clave pública
    private_key = (int(key.x), int(key.p))  # Clave privada incluye 'x' y 'p'
    return public_key, private_key

# Cifrado
def elgamal_encrypt(public_key, message):
    p, g, y = public_key
    m = bytes_to_long(message.encode())  # Convierte texto a número
    if m >= p:
        raise ValueError("El mensaje es demasiado grande para el tamaño del primo.")

    k = randint(1, p - 2)  # Número aleatorio secreto
    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (m * pow(y, k, p)) % p  # c2 = m * y^k mod p
    return (c1, c2)

# Descifrado (solo requiere clave privada y texto cifrado)
def elgamal_decrypt(private_key, ciphertext):
    x, p = private_key  # Extraer x y p de la clave privada
    c1, c2 = ciphertext

    s = pow(c1, x, p)  # s = c1^x mod p
    s_inv = pow(s, -1, p)  # Inverso modular de s
    m = (c2 * s_inv) % p  # m = c2 * s^(-1) mod p
    return long_to_bytes(m).decode()  # Convierte número a texto

# cifrado RSA


def generar_claves_rsa():
    key = RSA.generate(2048)  # Clave de 2048 bits
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()

    # Guardar claves en archivos (opcional)
    with open("rsa_private.pem", "wb") as f:
        f.write(private_key_pem)

    with open("rsa_public.pem", "wb") as f:
        f.write(public_key_pem)

    print("✅ Claves RSA generadas.")
    return private_key_pem, public_key_pem

# cifrar un mensaje con RSA


def cifrar_rsa(mensaje, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(mensaje)

# descifrar un mensaje con RSA


def descifrar_rsa(ciphertext, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    decipher = PKCS1_OAEP.new(private_key)
    return decipher.decrypt(ciphertext)

# Firmar un mensaje con RSA


def firmar_rsa(mensaje, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    hash_obj = SHA256.new(mensaje)
    signer = pkcs1_15.new(private_key)
    return signer.sign(hash_obj)

#  Verificar la firma con RSA


def verificar_firma_rsa(mensaje, firma, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    hash_obj = SHA256.new(mensaje)
    verifier = pkcs1_15.new(public_key)

    try:
        verifier.verify(hash_obj, firma)
        return "✅ Firma válida."
    except ValueError:
        return "❌ Firma inválida."


# DSA
# Es un algoritmo de firma digital que usa para autenticcar mensajes

# 1️⃣ Generar claves DSA
def generar_claves_dsa():
    key = DSA.generate(2048)  # Clave de 2048 bits
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    print("✅ Claves DSA generadas.")
    return private_key_pem, public_key_pem

# 2️⃣ Firmar un mensaje con DSA


def firmar_dsa(mensaje, private_key_pem):
    private_key = DSA.import_key(private_key_pem)
    hash_obj = SHA256.new(mensaje)
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(hash_obj)

# 3️⃣ Verificar la firma con DSA


def verificar_firma_dsa(mensaje, firma, public_key_pem):
    public_key = DSA.import_key(public_key_pem)
    hash_obj = SHA256.new(mensaje)
    verifier = DSS.new(public_key, 'fips-186-3')

    try:
        verifier.verify(hash_obj, firma)
        return "✅ Firma válida."
    except ValueError:
        return "❌ Firma inválida."

########## Cifrado afín ###########

def affine_encryption(plaintext, a, b):
    """"
    Pasamos un texto plano a mayúsculas para que no genere errores.
    Definimos el alfabeto en mayúsculas.
    Obtenemos la longitud del alfabeto.
    Inicializamos una cadena vacía para almacenar el texto cifrado.
    Iteramos a través de cada carácter en el texto plano y si este esta dentro del alfabeto lo ciframos usando el index de caracter y la formula del cifrado afin.
    """
    plaintext = plaintext.upper()
    alphabet = string.ascii_uppercase
    m = len(alphabet)
    ciphertext = ''

    for char in plaintext:
        if char in alphabet:
            p = alphabet.index(char)
            c = (a * p + b) % m
            ciphertext += alphabet[c]
        else:
            ciphertext += char
    print(ciphertext)
    return ciphertext

def extended_gcd(a, b):
    """
    Calculo del máximo común divisor de dos números enteros a y b.
        Devuelve una tupla (g, x, y) tal que a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extended_gcd(b % a, a)
        return (g, y - (b // a) * x, x)
   
def modular_inverse(a, m):
    """
    Calcula el inverso multiplicativo de a en el módulo m utilizando el algoritmo de Euclides extendido.
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m
   
def affine_decrypt(ciphertext, a, b):
    """
    Descifra el texto cifrado obtenido con el cifrado afín, para lo que se necesita el texto cifrado, la clave a y la clave b.
    Se pasa el texto cifrado a mayúsculas para evitar errores.
    Se define el alfabeto en mayúsculas.
    Se obtiene la longitud del alfabeto.
    Se inicializa una cadena vacía para almacenar el texto descifrado.
    Se calcula el inverso multiplicativo de a en módulo m.
    Se itera a través de cada carácter en el texto cifrado y si este está dentro del alfabeto se descifra usando el index del carácter y la fórmula del descifrado afín.
    """
    ciphertext = ciphertext.upper()
    alphabet = string.ascii_uppercase
    m = len(alphabet)
    plaintext = ''
    a_inv = modular_inverse(a, m)
    for char in ciphertext:
        if char in alphabet:
            c = alphabet.index(char)
            p = (a_inv * (c - b)) % m
            plaintext += alphabet[p]
        else:
            plaintext += char
    return plaintext

########## Cifrado de Hill ###########

def hill_encriptar(message, key):
    """ Generar encripcion

    Args:
        message ( str ): Recibe frase a encriptar
        key ( array ): Recibe matriz llave
         

    Returns:
        str : Retorna cadena string encriptada
    """

    diccionario_encryt = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9, 'K': 10, 'L': 11,
            'M': 12, 'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21, 'W': 22, 'X': 23, 'Y': 24, 'Z': 25,
            '0':26, '1': 27, '2':28, '3':29, '4':30, '5':31, '6':32, '7':33, '8':34, '9':35, '.': 36, ',': 37, ':': 38, '?': 39 , ' ': 40}

    diccionario_decrypt = {'0' : 'A', '1': 'B', '2': 'C', '3': 'D', '4': 'E', '5': 'F', '6': 'G', '7': 'H', '8': 'I', '9': 'J', '10': 'K', '11': 'L', '12': 'M',
                '13': 'N', '14': 'O', '15': 'P', '16': 'Q', '17': 'R', '18': 'S', '19': 'T', '20': 'U', '21': 'V', '22': 'W', '23': 'X', '24': 'Y', '25': 'Z', '26': '0',
                '27': '1', '28': '2', '29': '3', '30': '4', '31': '5', '32' : '6', '33' : '7', '34' : '8', '35' : '9', '36' : '.', '37' : ',', '38' : ':', '39' : '?', '40' : ' '}

    ciphertext = ''

    matrix_mensaje = []
    list_temp = []
    ciphertext_temp = ''

    message = message.upper()

    if len(message) <= len(key):
        while len(message) < len(key):
            message = message + 'X'

        for i in range(0, len(message)):
            matrix_mensaje.append(diccionario_encryt[message[i]])

        matrix_mensaje = np.array(matrix_mensaje)
        cifrado = np.matmul(key, matrix_mensaje)
        cifrado = cifrado % 41

        for i in range(0, len(cifrado)):
            ciphertext += diccionario_decrypt[str(cifrado[i])]
    else:
        while len(message) % len(key) != 0:
            message = message + 'X'

        matrix_mensaje = [message[i:i + len(key)] for i in range(0,
                          len(message), len(key))]
        
        for bloque in matrix_mensaje:
            for i in range(0, len(bloque)):
                list_temp.append(diccionario_encryt[bloque[i]])

            matrix_encrypt = np.array(list_temp)
            cifrado = np.matmul(key, matrix_encrypt)

            cifrado = cifrado % 41

            for i in range(0, len(cifrado)):
                ciphertext_temp += diccionario_decrypt[str(cifrado[i])]

            matrix_encrypt = []
            list_temp = []

        ciphertext = ciphertext_temp
    print(ciphertext)
    return ciphertext


def hill_desencriptar(message, key):
    """ Generar descifrado

    Args:
        message ( str ): Recibe frase encriptada
        key ( array ): Recibe matriz llave
         

    Returns:
        str : Retorna cadena string desencriptada
    """
    diccionario_encryt = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9, 'K': 10, 'L': 11,
            'M': 12, 'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21, 'W': 22, 'X': 23, 'Y': 24, 'Z': 25,
            '0':26, '1': 27, '2':28, '3':29, '4':30, '5':31, '6':32, '7':33, '8':34, '9':35, '.': 36, ',': 37, ':': 38, '?': 39 , ' ': 40}

    diccionario_decrypt = {'0' : 'A', '1': 'B', '2': 'C', '3': 'D', '4': 'E', '5': 'F', '6': 'G', '7': 'H', '8': 'I', '9': 'J', '10': 'K', '11': 'L', '12': 'M',
                '13': 'N', '14': 'O', '15': 'P', '16': 'Q', '17': 'R', '18': 'S', '19': 'T', '20': 'U', '21': 'V', '22': 'W', '23': 'X', '24': 'Y', '25': 'Z', '26': '0',
                '27': '1', '28': '2', '29': '3', '30': '4', '31': '5', '32' : '6', '33' : '7', '34' : '8', '35' : '9', '36' : '.', '37' : ',', '38' : ':', '39' : '?', '40' : ' '}

    plaintext = ''
    matrix_mensaje = []
    plaintext_temp = ''
    list_temp = []
    matrix_inversa = []

    matrix_mensaje = [message[i:i + len(key)] for i in range(0,
                      len(message), len(key))]

    matrix_inversa = Matrix(key).inv_mod(41)
    matrix_inversa = np.array(matrix_inversa)
    matrix_inversa = matrix_inversa.astype(float)

    for bloque in matrix_mensaje:
        for i in range(0, len(bloque)):
            list_temp.append(diccionario_encryt[bloque[i]])

        matrix_encrypt = np.array(list_temp)

        cifrado = np.matmul(matrix_inversa, matrix_encrypt)

        cifrado = np.remainder(cifrado, 41).flatten()

        for i in range(0, len(cifrado)):
            plaintext_temp += diccionario_decrypt[str(int(cifrado[i]))]

        matrix_encrypt = []
        list_temp = []
    plaintext = plaintext_temp
    while plaintext[-1] == 'X':
        plaintext = plaintext.rstrip(plaintext[-1])

    print(plaintext)
    return plaintext

########## Cifrado multiplicativo ###########

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modular_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def multi_encrypt(plaintext, key):
    print("entre")
    if gcd(key, 26) != 1:
        raise ValueError("Key must be coprime to 26.")
    
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((key * (ord(char) - shift)) % 26 + shift)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    print(ciphertext)
    return ciphertext

def multi_decrypt(ciphertext, key):
    if gcd(key, 26) != 1:
        raise ValueError("Key must be coprime to 26.")
    
    key_inverse = modular_inverse(key, 26)
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            shift = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((key_inverse * (ord(char) - shift)) % 26 + shift)
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext

########## Cifrado DES-S ###########

########## Visual Triple DES ###########
# --- Funciones de padding PKCS7 ---
def pad_image_arr(arr, block_size=8):
    flat = arr.flatten()
    pad_len = block_size - (len(flat) % block_size)
    if pad_len == 0:
        pad_len = block_size
    padding = np.full((pad_len,), pad_len, dtype=np.uint8)
    padded = np.concatenate([flat, padding])
    return padded

def unpad_image_arr(arr):
    flat = arr.flatten()
    pad_len = int(flat[-1])
    return flat[:-pad_len]

# --- Funciones de encriptado y desencriptado 3DES ---
def encrypt_image(plain_img_arr, key, mode, **kwargs):
    modes = {
        "ECB": DES3.MODE_ECB,
        "CBC": DES3.MODE_CBC,
        "OFB": DES3.MODE_OFB,
        "CFB": DES3.MODE_CFB,
        "CTR": DES3.MODE_CTR,
    }
    mode_val = modes[mode]
    # Para modos que requieren IV o nonce, se esperan en kwargs
    if mode == "CTR":
        if "nonce" not in kwargs:
            raise ValueError("El modo CTR requiere un nonce.")
    elif mode in ["CBC", "OFB", "CFB"]:
        if "iv" not in kwargs:
            raise ValueError(f"El modo {mode} requiere un vector de inicialización (IV).")
    key = DES3.adjust_key_parity(key)
    # Se trabaja sobre la imagen aplanada (todos los bytes de la imagen)
    padded_arr = pad_image_arr(plain_img_arr, 8)
    des3 = DES3.new(key, mode_val, **kwargs)
    encrypted_bytes = des3.encrypt(padded_arr.tobytes())
    encrypted_arr = np.frombuffer(encrypted_bytes, dtype=np.uint8)
    # Se devuelve también la longitud con padding para reconstrucción
    return encrypted_arr, int(encrypted_arr.size)

def decrypt_image(cipher_img_arr, key, mode, **kwargs):
    modes = {
        "ECB": DES3.MODE_ECB,
        "CBC": DES3.MODE_CBC,
        "OFB": DES3.MODE_OFB,
        "CFB": DES3.MODE_CFB,
        "CTR": DES3.MODE_CTR,
    }
    mode_val = modes[mode]
    if mode == "CTR":
        if "nonce" not in kwargs:
            raise ValueError("El modo CTR requiere un nonce.")
    elif mode in ["CBC", "OFB", "CFB"]:
        if "iv" not in kwargs:
            raise ValueError(f"El modo {mode} requiere un vector de inicialización (IV).")
    key = DES3.adjust_key_parity(key)
    des3 = DES3.new(key, mode_val, **kwargs)
    cipher_bytes = cipher_img_arr.tobytes()
    decrypted_bytes = des3.decrypt(cipher_bytes)
    decrypted_arr = np.frombuffer(decrypted_bytes, dtype=np.uint8)
    unpadded = unpad_image_arr(decrypted_arr)
    return unpadded

# --- Funciones para incorporar metadatos en el PNG ---
def save_encrypted_image(encrypted_arr, padded_length, original_shape, save_path):
    """
    Para facilitar la reconstrucción, se guarda el arreglo cifrado (que es 1D)
    en un PNG "visual" con ancho fijo; los metadatos (longitud padded y forma original)
    se incorporan en el PNG usando PngInfo.
    """
    fixed_width = 256
    height_enc = math.ceil(encrypted_arr.size / fixed_width)
    total_pixels = height_enc * fixed_width
    if total_pixels > encrypted_arr.size:
        extra = np.zeros(total_pixels - encrypted_arr.size, dtype=np.uint8)
        encrypted_full = np.concatenate([encrypted_arr, extra])
    else:
        encrypted_full = encrypted_arr
    encrypted_img_visual = encrypted_full.reshape((height_enc, fixed_width))
    
    # Incrustar metadatos
    metadata = {"padded_length": padded_length, "original_shape": original_shape}
    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text("padded_length", str(padded_length))
    pnginfo.add_text("original_shape", json.dumps(original_shape))
    
    Image.fromarray(encrypted_img_visual).save(save_path, "PNG", pnginfo=pnginfo)
    return save_path

def load_encrypted_metadata(image):
    info = image.info
    padded_length = int(info.get("padded_length"))
    original_shape = json.loads(info.get("original_shape"))
    return padded_length, original_shape



##########DSA Firmas digitales############


def generar_llaves_dsa():
    """Genera par de llaves DSA (2048 bits)"""
    private_key = dsa.generate_private_key(key_size=2048)  # Cambiar 1024 → 2048
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_pem, public_pem

def firmar_archivo(archivo_bytes, private_key_pem):
    """Firma un archivo usando DSA con SHA-256"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    # Usar SHA-256 para DSA de 2048 bits
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())  # Cambiar SHA1 → SHA256
    hasher.update(archivo_bytes)
    hash_digest = hasher.finalize()
    
    return private_key.sign(
        hash_digest,
        algorithm=hashes.SHA256()  # Cambiar SHA1 → SHA256
    )

def verificar_firma(archivo_bytes, firma_bytes, public_key_pem):
    """Verifica una firma DSA con SHA-256"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        # Calcular hash SHA-256
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())  # Cambiar SHA1 → SHA256
        hasher.update(archivo_bytes)
        hash_digest = hasher.finalize()
        
        public_key.verify(
            firma_bytes,
            hash_digest,
            algorithm=hashes.SHA256()  # Cambiar SHA1 → SHA256
        )
        return True
    except Exception as e:
        print(f"Error en verificación: {str(e)}")
        return False