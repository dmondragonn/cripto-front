from flask import Flask, render_template, jsonify, request
import cifrados
import os
<<<<<<< HEAD
=======
import ast

>>>>>>> main
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


@app.route("/cdesplazamiento")
def cdesplazamiento():
    return render_template("cdesplazamiento.html")


@app.route("/cvigenere")
def cvigenere():
    return render_template("cvigenere.html")


<<<<<<< HEAD
@app.route("/cafin")
def cafin():
    return render_template("cafin.html")
=======
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


@app.route('/cifrado_hill')
def cifrado_hill():
    return render_template('chill.html')


@app.route('/hill-image')
def hill_image():
    return render_template('hill-image.html')
>>>>>>> main


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

<<<<<<< HEAD
=======

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

@app.route('procesar-hill-img', methods=['POST'])

UPLOAD_FOLDER = 'uploads'  # Carpeta donde se guardarán los archivos
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Crea la carpeta si no existe
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def upload_image():
    if 'image' not in request.files:
        return jsonify({"error": "No se envió ninguna imagen"}), 400

    file = request.files['image']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)  # Guarda el archivo en la carpeta definida

    return jsonify({"message": f"Archivo {file.filename} subido exitosamente"}), 200



>>>>>>> main

if __name__ == "__main__":
    app.run(debug=True)
