from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
import hashlib
import os
import base64
import sqlite3
from datetime import datetime
import fitz  # PyMuPDF for PDFs
from docx import Document
import pytesseract
from PIL import Image

app = Flask(__name__)
app.secret_key = 'your_secret_key'

output_folder = 'outputs'
os.makedirs(output_folder, exist_ok=True)
upload_folder = 'uploads'
os.makedirs(upload_folder, exist_ok=True)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx'}

def timestamped_filename(prefix):
    return os.path.join(output_folder, f"{prefix}_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt")

def write_output(prefix, data):
    with open(timestamped_filename(prefix), 'w') as f:
        f.write(data)

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT)''')
    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path):
    ext = file_path.rsplit('.', 1)[-1].lower()
    if ext == 'txt':
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    elif ext == 'pdf':
        text = ""
        doc = fitz.open(file_path)
        for page in doc:
            text += page.get_text()
        return text
    elif ext in ['doc', 'docx']:
        doc = Document(file_path)
        return '\n'.join([para.text for para in doc.paragraphs])
    else:
        return ""

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except:
            return "User already exists!"
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('start_project'))
        return "Invalid credentials!"
    return render_template('login.html')

@app.route('/start_project', methods=['GET', 'POST'])
def start_project():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        text_input = request.form.get('input_text', '')
        uploaded_file = request.files.get('input_file')

        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join(upload_folder, filename)
            uploaded_file.save(filepath)
            extracted_text = extract_text_from_file(filepath)
            session['input_text'] = extracted_text.strip()
        elif text_input:
            session['input_text'] = text_input.strip()
        else:
            return "No valid input provided."

        # Save the input text into input.txt
        with open("input.txt", "w", encoding="utf-8") as file:
            file.write(session['input_text'])

        return redirect(url_for('hashing'))

    return render_template('start_project.html')

@app.route('/hashing', methods=['GET', 'POST'])
def hashing():
    text = session.get('input_text', '')
    hashed_text = hashlib.sha256(text.encode()).hexdigest()
    write_output("hashing", hashed_text)
    session['hashed'] = hashed_text
    # Pass the original input text for potential display on encryption page
    return render_template('encryption.html', input_text=text)

def encrypt_aes(data, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

@app.route('/encryption', methods=['POST'])
def encryption():
    text = session.get('hashed', '')
    key = "16CharEncryptKey"
    encrypted_text = encrypt_aes(text, key)
    write_output("encryption", encrypted_text)
    session['encrypted'] = encrypted_text
    return render_template('detection.html')

@app.route('/detection', methods=['POST'])
def detection():
    data = session.get('encrypted', '')
    detected_text = f"DETECTED::{data[::-1]}"
    write_output("detection", detected_text)
    session['detected'] = detected_text
    return render_template('ecc.html')

@app.route('/ecc', methods=['POST'])
def ecc():
    data = session.get('detected', '')
    ecc_text = f"ECC_ENCODE::{''.join(reversed(data))}"
    write_output("ecc", ecc_text)
    session['ecc'] = ecc_text
    return render_template('restoration.html')

@app.route('/restoration', methods=['POST'])
def restoration():
    data = session.get('ecc', '')
    restored_text = f"RESTORED::{data.lower()}"
    write_output("restoration", restored_text)
    session['restored'] = restored_text
    return render_template('verification.html')

@app.route('/verification', methods=['POST'])
def verification():
    data = session.get('restored', '')
    verified_text = f"VERIFIED::{hashlib.md5(data.encode()).hexdigest()}"
    write_output("verification", verified_text)
    session['verified'] = verified_text
    return redirect(url_for('view_output'))

@app.route('/view_output', methods=['GET', 'POST'])
def view_output():
    outputs = {}
    error = None
    if request.method == 'POST':
        password = request.form['view_password']
        if password == '242016':
            for filename in sorted(os.listdir(output_folder)):
                with open(os.path.join(output_folder, filename), 'r') as file:
                    outputs[filename] = file.read()
        else:
            error = "Incorrect password."
    return render_template('view_output.html', outputs=outputs, error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run()
