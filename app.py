from flask import Flask, request, render_template, jsonify, session
from cryptography.fernet import Fernet
import sqlite3
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import os

app = Flask(__name__)

app.secret_key = os.getenv('ENCRYPTION_KEY')
if not app.secret_key and os.getenv('FLASK_ENV') == 'production':
    raise ValueError("FLASK_SECRET_KEY is not set for production!")

KEY = Fernet.generate_key()
cipher_suite = Fernet(KEY)

limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

DATABASE_PATH = os.getenv('DATABASE_PATH', 'contact_form.db')


def init_db():
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS contacts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL,
                            message TEXT NOT NULL
                        )''')
            conn.commit()
    except sqlite3.Error as e:
        app.logger.error(f"Database Initialization Error: {e}")


init_db()

def generate_csrf_token():
    if "_csrf_token" not in session:
        token = secrets.token_urlsafe(16)
        session['_csrf_token'] = token
    return session['_csrf_token']


def verify_csrf_token(token):
    return session.get('_csrf_token') == token

def validate_input(name, email, message):
    if not name or not email or not message:
        return False, "All fields are required."
    if len(name) > 100 or len(message) > 500:
        return False, "Name or message is too long."
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, email):
        return False, "Invalid email address."
    return True, "Valid input."


@app.route('/submit', methods=['POST'])
@limiter.limit("5 per minute")
def submit():
    csrf_token = request.form.get('csrf_token')
    if not verify_csrf_token(csrf_token):
        return jsonify({"success": False, "message": "Invalid CSRF token."}), 400

    try:
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        is_valid, validation_message = validate_input(name, email, message)
        if not is_valid:
            return jsonify({"success": False, "message": validation_message}), 400

        encrypted_message = cipher_suite.encrypt(message.encode())

        with sqlite3.connect(DATABASE_PATH) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)",
                      (name, email, encrypted_message.decode()))
            conn.commit()

        return jsonify({"success": True, "message": "Form successfully submitted."})

    except sqlite3.Error as e:
        app.logger.error(f"Database Error: {e}")
        return jsonify({"success": False, "message": "An error occurred while saving the form."}), 500
    except Exception as e:
        app.logger.error(f"Unexpected Error: {e}")
        return jsonify({"success": False, "message": "An unexpected error occurred."}), 500


@app.route('/')
def index():
    csrf_token = generate_csrf_token()
    return render_template('form.html', csrf_token=csrf_token)

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_ENV') == 'development')
