from flask import Flask, render_template, jsonify, request
import cifrados
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


@app.route("/cafin")
def cafin():
    return render_template("cafin.html")


# funciones de cifrado


'''@app.route('/tipo')
def tipo_cifrado():
    if cliqueo cifrado por desplazamiento
        return 'Desplazamiento'
'''


@app.route('/encrypt', methods=['POST'])
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


if __name__ == "__main__":
    app.run(debug=True)
