from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__, 
            template_folder='templates',  # Templates in 'templates' folder
            static_folder='static')      # Static files in 'static' folder
app.secret_key = os.urandom(24)  # Secure random key

# Define upload folder relative to the app's root directory
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        photo_path TEXT
    )''')
    conn.commit()
    conn.close()

# Initialize database
init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        photo = request.files['photo']

        # Validate inputs
        if not all([name, email, password, photo]):
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))

        # Validate file extension
        if not allowed_file(photo.filename):
            flash('Invalid file type! Allowed types: png, jpg, jpeg, gif', 'error')
            return redirect(url_for('signup'))

        # Check if email already exists
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT email FROM users WHERE email = ?', (email,))
        if c.fetchone():
            flash('Email already registered!', 'error')
            conn.close()
            return redirect(url_for('signup'))

        # Save photo
        filename = secure_filename(photo.filename)
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(photo_path)

        # Hash password and store user
        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (name, email, password, photo_path) VALUES (?, ?, ?, ?)',
                  (name, email, hashed_password, filename))
        conn.commit()
        conn.close()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_email'] = user[2]
            session['photo_path'] = os.path.join('uploads', user[4])
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT name, email, photo_path FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    conn.close()

    if user:
        photo_path = os.path.join('uploads', user[2])
        return render_template('dashboard.html',
                               name=user[0],
                               email=user[1],
                               photo_path=photo_path)
    else:
        flash('User not found!', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
