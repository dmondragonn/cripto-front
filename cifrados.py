from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sympy import Matrix

import numpy as np
import random
import string

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
    """ Generar desencriptacion

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

