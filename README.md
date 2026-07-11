# Digital Document Verification

A cryptographically secure academic credential verification application designed to record student graduation details, generate unique SHA-256 digital document signatures, and audit certificates for tampering.

## Features

- **Tamper-Detection Auditor:** Recalculates graduation details (Name, Degree, GPA, Date) with a secret record salt. If any field (e.g. GPA) is altered by even one digit, the audit declares the document **"Tampered / Fraudulent"**.
- **Cryptographic Hash Signatures:** Creates 256-bit SHA-256 hex signatures committed to an institutional SQLite ledger database.
- **Registrar Management Console:** A password-protected panel where registrars can register new graduates, generate certificates, and copy unique document UUIDs for external checking.
- **Verification Autocomplete Demos:** Includes preloaded copy shortcuts to load valid credentials or trigger fake altered inputs for testing.

## Tech Stack

- **Backend:** Python 3, Flask, Flask-SQLAlchemy (SQLite), hashlib.
- **Frontend:** HTML5, CSS3 (Indigo/amber space theme, verified badges, secure forms), JavaScript (AJAX audit requests, Clipboard copying), Boxicons.

## Setup & Running

1. Open your terminal in this directory (`2-document-verification`).
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the application:
   ```bash
   python app.py
   ```
4. Access the portal at `http://127.0.0.1:5022`.

> **Demo Credentials:** See `demo_credentials.txt` in this folder.
