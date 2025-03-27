
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production

# Define access levels
ACCESS_LEVELS = {
    "Alpha Prime": 3,
    "Alpha": 2,
    "Beta": 1,
    "Gamma": 0
}

# Initialize users table
def init_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                     (name TEXT PRIMARY KEY, clearance_level TEXT)''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect("secure_files.db")
    conn.row_factory = sqlite3.Row
    return conn

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

# Initialize database and encryption
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
init_db()

# Initialize admin user
def init_admin():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (name, clearance_level) VALUES (?, ?)",
                  ("Admin", "Alpha Prime"))
    cursor.execute("INSERT OR IGNORE INTO users (name, clearance_level) VALUES (?, ?)",
                  ("Djaylano Asper", "Alpha Prime"))
    conn.commit()
    conn.close()

init_users()
init_admin()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name'].strip()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT clearance_level FROM users WHERE name = ?", (name,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            flash('Access denied! Unauthorized user.', 'danger')
        else:
            session['name'] = name
            session['clearance'] = user['clearance_level']
            flash(f'Welcome, {name}!', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'name' not in session or session['clearance'] != 'Alpha Prime':
        flash('Only Alpha Prime users can manage users.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name'].strip()
        clearance = request.form['clearance'].strip()
        
        if clearance not in ACCESS_LEVELS:
            flash('Invalid clearance level.', 'danger')
        else:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO users (name, clearance_level) VALUES (?, ?)",
                         (name, clearance))
            conn.commit()
            conn.close()
            flash(f'User {name} added/updated successfully.', 'success')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return render_template('manage_users.html', users=users, access_levels=ACCESS_LEVELS.keys())

@app.route('/dashboard')
def dashboard():
    if 'name' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT filename, clearance_level FROM files")
    all_files = cursor.fetchall()
    conn.close()
    
    files = [file for file in all_files 
             if ACCESS_LEVELS[session['clearance']] >= ACCESS_LEVELS[file['clearance_level']]]
    
    return render_template('dashboard.html', files=files)

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
    
    flash(f'File "{filename}" has been encrypted and stored.', 'success')
    return redirect(url_for('dashboard'))

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
                flash(f'File content: {decrypted_content}', 'info')
            except:
                flash('Error decrypting file.', 'danger')
        else:
            flash('Access denied! Your clearance level is too low.', 'danger')
    else:
        flash('File not found.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
