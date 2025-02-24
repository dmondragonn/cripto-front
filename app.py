from flask import Flask, render_template, jsonify, request
import cifrados
import os
import ast
app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


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


@app.route("/cafin")
def cafin():
    return render_template("cafin.html")
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


@app.route('/cifrado_hill')
def cifrado_hill():
    return render_template('chill.html')


@app.route('/hill-image')
def hill_image():
    return render_template('hill-image.html')

# funciones de cifrado


'''@app.route('/tipo')
def tipo_cifrado():
    if cliqueo cifrado por desplazamiento
        return 'Desplazamiento'
'''


@app.route('/process-desplazamiento', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        mensaje = data.get("message", "").strip()
        clave = data.get("key", 0)

        # Validaciones
        if not mensaje:
            return jsonify({"error": "El mensaje no puede estar vacío"}), 400

        if not isinstance(clave, int) or clave < 1 or clave > 25:
            return jsonify({"error": "La clave debe ser un número entre 1 y 25"}), 400

        # Cifrar
        mensaje_cifrado = cifrados.shift_cipher_encrypt(mensaje, clave)
        return jsonify({"encrypted_message": mensaje_cifrado})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/process-permutacion', methods=['POST'])
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



#----------- Prueba ---------------------------------------



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

if __name__ == "__main__":
    app.run(debug=True)
