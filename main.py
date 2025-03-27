import sqlite3
from flask import Flask, request, redirect, url_for, flash, session
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Define access levels
ACCESS_LEVELS = {
    "Omega": 4,        # Admin level
    "Alpha Prime": 3,
    "Alpha": 2,
    "Beta": 1,
    "Gamma": 0
}

# Initialize database connection
def get_db():
    conn = sqlite3.connect("secure_files.db")
    conn.row_factory = sqlite3.Row
    return conn

# Initialize users table
def init_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                     (name TEXT PRIMARY KEY, password TEXT, clearance_level TEXT)''')
    conn.commit()
    conn.close()

# Initialize admin account
def init_admin():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (name, password, clearance_level) VALUES (?, ?, ?)",
                   ("Admin", "9137", "Omega"))
    conn.commit()
    conn.close()

# Initialize encryption keys
def init_keys():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS encryption_keys
                     (clearance_level TEXT PRIMARY KEY, key TEXT)''')

    cursor.execute("SELECT * FROM encryption_keys")
    existing_keys = {row[0]: row[1] for row in cursor.fetchall()}

    KEYS = {}
    for level in ACCESS_LEVELS:
        if level not in existing_keys:
            key = Fernet.generate_key()
            cursor.execute("INSERT INTO encryption_keys VALUES (?, ?)", (level, key.decode()))
            KEYS[level] = key
        else:
            KEYS[level] = existing_keys[level].encode()

    conn.commit()
    conn.close()
    return {level: Fernet(KEYS[level]) for level in KEYS}

# Initialize files table
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            encrypted_data BLOB,
            clearance_level TEXT
        )
    ''')
    conn.commit()
    conn.close()

CIPHERS = init_keys()
init_users()
init_admin()
init_db()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name'].strip()
        password = request.form['password'].strip()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT clearance_level FROM users WHERE name = ? AND password = ?", (name, password))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return "Access denied! Unauthorized user or incorrect password."
        else:
            session['name'] = name
            session['clearance'] = user['clearance_level']
            return f"Welcome, {name}! You have {session['clearance']} clearance."

    return "Enter your full name and password to log in."

@app.route('/dashboard')
def dashboard():
    if 'name' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, clearance_level FROM files")
    all_files = cursor.fetchall()
    conn.close()

    accessible_files = [f"{file['filename']} (Clearance: {file['clearance_level']})"
                        for file in all_files
                        if ACCESS_LEVELS[session['clearance']] >= ACCESS_LEVELS[file['clearance_level']]]

    return "Your accessible files: " + ", ".join(accessible_files) if accessible_files else "No files available."

@app.route('/create', methods=['POST'])
def create_file():
    if 'name' not in session:
        return redirect(url_for('login'))

    filename = request.form['filename'].strip()
    content = request.form['content']

    encrypted_content = CIPHERS[session['clearance']].encrypt(content.encode())

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (filename, encrypted_data, clearance_level) VALUES (?, ?, ?)",
                   (filename, encrypted_content, session['clearance']))
    conn.commit()
    conn.close()

    return f'File "{filename}" has been encrypted and stored.'

@app.route('/retrieve', methods=['POST'])
def retrieve_file():
    if 'name' not in session:
        return redirect(url_for('login'))

    filename = request.form['filename']

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_data, clearance_level FROM files WHERE filename = ?", (filename,))
    file = cursor.fetchone()
    conn.close()

    if file:
        if ACCESS_LEVELS[session['clearance']] >= ACCESS_LEVELS[file['clearance_level']]:
            try:
                decrypted_content = CIPHERS[file['clearance_level']].decrypt(file['encrypted_data']).decode()
                return f'File content: {decrypted_content}'
            except:
                return 'Error decrypting file.'
        else:
            return 'Access denied! Your clearance level is too low.'
    else:
        return 'File not found.'

@app.route('/manage_users', methods=['POST'])
def manage_users():
    if 'name' not in session or session['clearance'] != 'Omega':
        return "Only Omega users can manage users."

    name = request.form['name'].strip()
    password = request.form['password'].strip()
    clearance = request.form['clearance'].strip()

    if clearance not in ACCESS_LEVELS:
        return 'Invalid clearance level.'

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO users (name, password, clearance_level) VALUES (?, ?, ?)",
                   (name, password, clearance))
    conn.commit()
    conn.close()

    return f'User {name} added/updated successfully.'

@app.route('/logout')
def logout():
    session.clear()
    return 'Logged out successfully.'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
