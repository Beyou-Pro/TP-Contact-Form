# Fichier : app.py
from flask import Flask, request, render_template, jsonify
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
import sqlite3
import re

app = Flask(__name__)

# Clé de cryptage pour les messages sensibles
KEY = Fernet.generate_key()
cipher_suite = Fernet(KEY)

# Configuration de la base de données
def init_db():
    conn = sqlite3.connect('contact_form.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    message TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

init_db()

# Validation des entrées utilisateur
def validate_input(name, email, message):
    if not name or not email or not message:
        return False, "Tous les champs sont requis."

    # Validation de l'adresse e-mail
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, email):
        return False, "Adresse e-mail invalide."

    return True, "Entrées valides."

@app.route('/')
def index():
    return render_template('form.html')

@app.route('/submit', methods=['POST'])
def submit():
    try:
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Validation des données utilisateur
        is_valid, validation_message = validate_input(name, email, message)
        if not is_valid:
            return jsonify({"success": False, "message": validation_message}), 400

        # Cryptage du message
        encrypted_message = cipher_suite.encrypt(message.encode())

        # Enregistrement dans la base de données
        conn = sqlite3.connect('contact_form.db')
        c = conn.cursor()
        c.execute("INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)",
                  (name, email, encrypted_message))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Formulaire soumis avec succès."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)