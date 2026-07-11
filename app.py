import os
import hashlib
import uuid
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'doc-verify-key-888'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///doc_verify.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='issuer')

class Certificate(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    student_name = db.Column(db.String(100), nullable=False)
    degree = db.Column(db.String(100), nullable=False)
    major = db.Column(db.String(100), nullable=False)
    gpa = db.Column(db.Float, nullable=False)
    issue_date = db.Column(db.String(20), nullable=False)
    crypto_hash = db.Column(db.String(64), nullable=False, unique=True)
    salt = db.Column(db.String(32), nullable=False) # Cryptographic salt for tampering checks

# Helper: Compute SHA-256 Hash of certificate details
def compute_cert_hash(student_name, degree, major, gpa, issue_date, salt):
    raw_str = f"{student_name.strip().lower()}|{degree.strip().lower()}|{major.strip().lower()}|{float(gpa):.2f}|{issue_date.strip()}|{salt}"
    return hashlib.sha256(raw_str.encode('utf-8')).hexdigest()

# Seed Demo Data
def seed_data():
    if User.query.first() is None:
        # Seed Issuer
        pw_hash = generate_password_hash("issuer123")
        issuer = User(username="university_registrar", password_hash=pw_hash, role="issuer")
        db.session.add(issuer)
        db.session.commit()

        # Seed Certificates
        # Cert 1
        salt1 = "super_secret_salt_111"
        h1 = compute_cert_hash("Alice Smith", "Bachelor of Science", "Computer Science", 3.85, "2026-06-15", salt1)
        c1 = Certificate(id="cert-8881-aaa", student_name="Alice Smith", degree="Bachelor of Science", major="Computer Science", gpa=3.85, issue_date="2026-06-15", crypto_hash=h1, salt=salt1)
        
        # Cert 2
        salt2 = "super_secret_salt_222"
        h2 = compute_cert_hash("Bob Jones", "Master of Business Administration", "Finance", 3.52, "2026-06-16", salt2)
        c2 = Certificate(id="cert-8882-bbb", student_name="Bob Jones", degree="Master of Business Administration", major="Finance", gpa=3.52, issue_date="2026-06-16", crypto_hash=h2, salt=salt2)

        db.session.add_all([c1, c2])
        db.session.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify_document():
    cert_id = request.form.get('cert_id', '').strip()
    student_name = request.form.get('student_name', '').strip()
    degree = request.form.get('degree', '').strip()
    major = request.form.get('major', '').strip()
    
    try:
        gpa = float(request.form.get('gpa', 0.0))
    except ValueError:
        return jsonify({'error': 'Invalid GPA rating input.'}), 400
        
    issue_date = request.form.get('issue_date', '').strip()

    if not cert_id:
        return jsonify({'error': 'Certificate ID is required for verification lookup.'}), 400

    # 1. Fetch certificate from DB
    cert = Certificate.query.get(cert_id)
    if not cert:
        return jsonify({
            'status': 'invalid',
            'title': 'Invalid / Fake ID',
            'status_class': 'danger',
            'explanation': 'The Certificate ID entered does not exist in our institutional ledger.'
        })

    # 2. Compute hash using the same salt
    computed = compute_cert_hash(student_name, degree, major, gpa, issue_date, cert.salt)

    # 3. Compare hashes
    if computed == cert.crypto_hash:
        return jsonify({
            'status': 'authentic',
            'title': 'Authentic / Verified',
            'status_class': 'success',
            'student_name': cert.student_name,
            'degree': cert.degree,
            'major': cert.major,
            'gpa': f"{cert.gpa:.2f}",
            'issue_date': cert.issue_date,
            'crypto_hash': cert.crypto_hash,
            'explanation': 'Cryptographic hashes match. The details match the institutional record exactly.'
        })
    else:
        # Details tampered!
        return jsonify({
            'status': 'tampered',
            'title': 'Tampered / Fraudulent',
            'status_class': 'danger',
            'explanation': 'WARNING: The Certificate ID exists, but the details entered (e.g. GPA, major, name) do not match the digital signature. The document content was altered after issuance.'
        })

# Issuer Login / Logout
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('issuer_dashboard'))
        return render_template('login.html', error="Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def issuer_dashboard():
    if 'user_id' not in session or session['role'] != 'issuer':
        return redirect(url_for('login'))

    certs = Certificate.query.order_by(Certificate.issue_date.desc()).all()
    return render_template('dashboard.html', certs=certs)

@app.route('/certificate/issue', methods=['POST'])
def issue_certificate():
    if 'user_id' not in session or session['role'] != 'issuer':
        return redirect(url_for('login'))

    student_name = request.form.get('student_name', '').strip()
    degree = request.form.get('degree', '').strip()
    major = request.form.get('major', '').strip()
    
    try:
        gpa = float(request.form.get('gpa', 0.0))
    except ValueError:
        return redirect(url_for('issuer_dashboard'))
        
    issue_date = request.form.get('issue_date', '').strip()

    # Generate salt and hash
    salt = uuid.uuid4().hex
    crypto_hash = compute_cert_hash(student_name, degree, major, gpa, issue_date, salt)

    new_cert = Certificate(
        student_name=student_name,
        degree=degree,
        major=major,
        gpa=gpa,
        issue_date=issue_date,
        crypto_hash=crypto_hash,
        salt=salt
    )
    db.session.add(new_cert)
    db.session.commit()

    return redirect(url_for('issuer_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_data()
    app.run(debug=True, port=5022)
