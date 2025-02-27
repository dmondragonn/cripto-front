from flask import Flask, send_file, render_template, jsonify, request
import cifrados
import os
from os.path import join
from tempfile import gettempdir
import ast
import base64
import io
import json
import math
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from PIL import ImageOps
from io import BytesIO


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB máximo

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp"}


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


@app.route("/cdesplazamiento")
def cdesplazamiento():
    return render_template("cdesplazamiento.html")


@app.route("/cvigenere")
def cvigenere():
    return render_template("cvigenere.html")


@app.route("/cmultiplicative")
def cmultiplicative():
    return render_template("cmulti.html")


@app.route("/process-multiplicative", methods=['POST'])
def process_multiplicative():
    data = request.get_json()
    message = data['message']
    key = int(data['key'])
    action = data['action']

    if action == 'encrypt':
        result = cifrados.multi_encrypt(message, key)
    else:
        result = cifrados.multi_decrypt(message, key)

    return jsonify(result=result)


@app.route('/process-affine', methods=['POST'])
def process_affine():
    data = request.get_json()
    message = data['message']
    key1 = int(data['key1'])
    key2 = int(data['key2'])
    action = data['action']

    if action == 'encrypt':
        result = cifrados.affine_encryption(message, key1, key2)
    else:
        result = cifrados.affine_decrypt(message, key1, key2)

    return jsonify(result=result)


@app.route('/cifrado_afin')
def cafin():
    return render_template('cafin.html')


@app.route('/process-hill', methods=['POST'])
def process_hill():
    data = request.get_json()
    message = data['message']
    key = data['key']
    action = data['action']

    key_matrix = ast.literal_eval(key)
    print(key_matrix)

    if action == 'encrypt':
        result = cifrados.hill_encriptar(message, key_matrix)
    else:
        result = cifrados.hill_desencriptar(message, key_matrix)

    return jsonify(result=result)


@app.route('/chill')
def cifrado_hill():
    return render_template('chill.html')


@app.route('/hill-image')
def hill_image():
    return render_template('hill-image.html')


@app.route('/dsa')
def dsa():
    return render_template('dsa.html')


@app.route('/sha256')
def sha256():
    return render_template('sha256.html')


@app.route('/rsa')
def rsa():
    return render_template('rsa.html')


@app.route('/des3')
def des3():
    return render_template('des3.html')


@app.route('/sdes')
def sdes():
    return render_template('sdes.html')


@app.route('/elgamal')
def elgamal():
    return render_template('elgamal.html')


@app.route('/aes-images')
def aes_images():
    return render_template('aes-images.html')

# funciones de cifrado


'''@app.route('/tipo')
def tipo_cifrado():
    if cliqueo cifrado por desplazamiento
        return 'Desplazamiento'
'''


@app.route('/process-aes', methods=['POST'])
def process_aes():
    data = request.get_json()
    
    # Validación de campos
    required_fields = ['image', 'action', 'mode', 'key']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Mapeo de modos
    mode_mapping = {
        'ecb': AES.MODE_ECB,
        'cbc': AES.MODE_CBC,
        'cfb': AES.MODE_CFB,
        'ofb': AES.MODE_OFB
    }

    try:
        mode = mode_mapping[data['mode'].lower()]
    except KeyError:
        return jsonify({'error': 'Invalid mode'}), 400

    # Conversión de hexadecimal a bytes
    try:
        key = bytes.fromhex(data['key'])
        iv = bytes.fromhex(data['iv']) if data.get('iv') else None
    except ValueError:
        return jsonify({'error': 'Invalid hex format'}), 400

    # Validación de longitudes
    if len(key) not in [16, 24, 32]:
        return jsonify({'error': 'Key must be 16/24/32 bytes'}), 400

    if mode != AES.MODE_ECB:
        if not iv or len(iv) != 16:
            return jsonify({'error': 'IV required (16 bytes) for this mode'}), 400

    try:
        # Procesamiento de imagen
        image_data = base64.b64decode(data['image'])
        img = Image.open(BytesIO(image_data)).convert('RGBA')
        
        # Aplicar padding
        if img.width % 4 != 0:
            diff = 4 - (img.width % 4)
            img = ImageOps.expand(img, border=(0, 0, diff, 0), fill=0)

        # Cifrar/Descifrar
        cipher = AES.new(key, mode, iv) if iv else AES.new(key, mode)
        processed_img = img.copy()

        for y in range(img.height):
            row_pixels = []
            for x in range(img.width):
                row_pixels.extend(img.getpixel((x, y)))
                if len(row_pixels) == 16:
                    if data['action'] == 'encrypt':
                        processed_block = cipher.encrypt(bytes(row_pixels))
                    else:
                        processed_block = cipher.decrypt(bytes(row_pixels))
                    
                    for i in range(4):
                        px = tuple(processed_block[i*4:(i+1)*4])
                        processed_img.putpixel((x-3+i, y), px)
                    row_pixels = []

        # Convertir a base64
        buffered = BytesIO()
        processed_img.save(buffered, format="PNG")
        return jsonify({'processed_image': base64.b64encode(buffered.getvalue()).decode()})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def process_permutacion():
    try:
        data = request.get_json()
        mensaje = data.get("message", "").strip()
        clave = data.get("key", "").strip()
        action = data.get("action", "encrypt")

        # Validaciones
        if not mensaje or not clave:
            return jsonify({"error": "Todos los campos son requeridos"}), 400

        if not clave.isdigit():
            return jsonify({"error": "La clave debe ser numérica (ej: 231)"}), 400

        # Validar permutación válida
        longitud = len(clave)
        if sorted(clave) != sorted(str(i) for i in range(1, longitud+1)):
            return jsonify({"error": f"Clave inválida. Ejemplo: {''.join(map(str, range(1, longitud+1)))}"}), 400

        # Validar longitud en descifrado
        if action == "decrypt" and len(mensaje) % longitud != 0:
            return jsonify({"error": "Texto cifrado inválido (longitud incorrecta)"}), 400

        # Procesar
        if action == "encrypt":
            resultado = cifrados.cifrado_permutacion_encriptar(mensaje, clave)
        else:
            resultado = cifrados.cifrado_permutacion_desencriptar(
                mensaje, clave)

        return jsonify({"result": resultado})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ----------- Prueba ---------------------------------------


@app.route('/procesar-hill-img', methods=['POST'])
def upload_image():
    try:
        files = {
            "image": request.files.get("image"),
            "image1": request.files.get("image1"),
            "image2": request.files.get("image2"),
        }

        saved_files = {}

        for key, file in files.items():
            if file:
                filename = file.filename
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)
                saved_files[key] = file_path

        if not saved_files:
            return jsonify({"error": "No se recibieron archivos"}), 400

        return jsonify({"message": "Archivos guardados exitosamente", "files": saved_files}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/des3/encrypt', methods=['POST'])
def encrypt_r():
    # Verificar que se envíen key, mode y file
    if "key" in request.form and "mode" in request.form and "file" in request.files:
        key_hex = request.form["key"]
        mode = request.form["mode"].upper()
        img_file = request.files["file"]

        # Definir ruta temporal para la imagen
        file_type = img_file.filename.rsplit(
            ".", 1)[1].lower() if img_file.filename else "png"
        img_path = join(gettempdir(), f"plain_image.{file_type}")
        img_file.save(img_path)

        # Convertir la imagen a arreglo (PIL admite color o gris)
        plain_img_arr = np.array(Image.open(img_path))
        original_shape = plain_img_arr.shape

        # Convertir la clave de hexadecimal a bytes
        key = bytes.fromhex(key_hex)

        # Para modos que requieren IV o counter, se deben enviar en el formulario
        kwargs = {}
        if mode in ["CBC", "OFB", "CFB"]:
            if "initializationVector" in request.form:
                iv = bytes.fromhex(request.form["initializationVector"])
                kwargs["iv"] = iv
        elif mode == "CTR":
            if "counter" in request.form:
                ctr = bytes.fromhex(request.form["counter"])
                kwargs["nonce"] = ctr

        # Aplanar la imagen (trabaja sobre el flujo completo)
        plain_flat = plain_img_arr.flatten()

        # Encriptar la secuencia (la función retorna el arreglo cifrado y la longitud padded)
        encrypted_arr, padded_length = cifrados.encrypt_image(
            plain_flat, key, mode, **kwargs)
        # Guardar la imagen cifrada (visual) con metadatos embebidos
        encrypted_path = join(gettempdir(), "encrypted_image.png")
        cifrados.save_encrypted_image(
            encrypted_arr, padded_length, original_shape, encrypted_path)

        # Devolver el archivo cifrado al cliente
        return send_file(encrypted_path, mimetype='image/png')

    return jsonify({"error": "Faltan parámetros"}), 400


@app.route('/des3/decrypt', methods=['POST'])
def decrypt_r():
    if "key" in request.form and "mode" in request.form and "file" in request.files:
        key_hex = request.form["key"]
        mode = request.form["mode"].upper()
        img_file = request.files["file"]

        # Definir ruta temporal para la imagen cifrada
        file_type = img_file.filename.rsplit(
            ".", 1)[1].lower() if img_file.filename else "png"
        img_path = join(gettempdir(), f"encrypted_image.{file_type}")
        img_file.save(img_path)

        # Convertir la imagen cifrada usando PIL
        encrypted_image = Image.open(img_path)
        # Extraer metadatos embebidos
        padded_length, original_shape = cifrados.load_encrypted_metadata(
            encrypted_image)

        # Convertir la imagen cifrada visual a arreglo 1D
        encrypted_img_arr = np.array(encrypted_image).flatten()
        # Recortar la secuencia cifrada a la longitud real (con padding)
        encrypted_sequence = encrypted_img_arr[:padded_length]

        key = bytes.fromhex(key_hex)
        kwargs = {}
        if mode in ["CBC", "OFB", "CFB"]:
            if "initializationVector" in request.form:
                iv = bytes.fromhex(request.form["initializationVector"])
                kwargs["iv"] = iv
        elif mode == "CTR":
            if "counter" in request.form:
                ctr = bytes.fromhex(request.form["counter"])
                kwargs["nonce"] = ctr

        # Descifrar la secuencia
        decrypted_flat = cifrados.decrypt_image(
            encrypted_sequence, key, mode, **kwargs)
        total_pixels = np.prod(original_shape)
        decrypted_flat = decrypted_flat[:total_pixels]
        decrypted_img_arr = np.array(decrypted_flat).reshape(original_shape)

        # Guardar la imagen descifrada
        plain_path = join(gettempdir(), f"plain_image.{file_type}")
        Image.fromarray(decrypted_img_arr).save(plain_path, "PNG")

        return send_file(plain_path, mimetype='image/png')

    return jsonify({"error": "Faltan parámetros"}), 400


@app.route('/generar_llaves_elgamal', methods=['GET'])
def generar_llaves_elgamal():
    public_key, private_key = cifrados.generate_keys()
    return jsonify(
        public_key=str(public_key),
        private_key=str(private_key)
    )

# Ruta para procesar cifrado ElGamal


@app.route('/elgamal-encrypt', methods=['POST'])
def elgamal_encrypt():
    data = request.get_json()
    try:
        public_key = tuple(
            map(int, data['public_key'].strip('()').split(', ')))
        message = data['message']
        ciphertext = cifrados.elgamal_encrypt(public_key, message)
        return jsonify(ciphertext=str(ciphertext))
    except Exception as e:
        return jsonify(error=str(e)), 400

# Ruta para procesar descifrado ElGamal


@app.route('/elgamal-decrypt', methods=['POST'])
def elgamal_decrypt():
    data = request.get_json()
    try:
        private_key = tuple(
            map(int, data['private_key'].strip('()').split(', ')))
        ciphertext = tuple(
            map(int, data['ciphertext'].strip('()').split(', ')))
        plaintext = cifrados.elgamal_decrypt(private_key, ciphertext)
        return jsonify(plaintext=plaintext)
    except Exception as e:
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    app.run(debug=True)
