from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

# Desplazamiento


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


def shift_cipher_decrypt(text, key):
    return shift_cipher_encrypt(text, -key)


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


# ElGamal

def generate_keys(bits=512):  # Genera una private key y una public

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
