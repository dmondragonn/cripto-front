from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/topics-detail")
def topics_detail():
    return render_template("topics-detail.html")


@app.route("/topics-listing")
def topics_listing():
    return render_template("topics-listing.html")

@app.route("/cpermutation")
def cpermutation():
    return render_template("cpermutation.html")

# funciones de cifrado

'''@app.route('/tipo')
def tipo_cifrado():
    if cliqueo cifrado por desplazamiento
        return 'Desplazamiento'
'''


@app.route('/encrypt', methods=['POST'])
def encrypt():
    mensaje = request.form.get('message', '').strip()
    if not mensaje:
        return render_template('topics-detail.html', error="El campo no puede estar vacío.")

    mensaje_cifrado = shift_cipher_encrypt(mensaje, 3)
    return render_template('topics-detail.html', encrypted_message=mensaje_cifrado)

# Desplazamiento


def shift_cipher_encrypt(text, key):
    encrypted_text = ""
    for char in text:
        if char.isalpha():  # Solo cifrar letras
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + key) % 26 + base)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char  # No cifrar caracteres especiales
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


if __name__ == "__main__":
    app.run(debug=True)
