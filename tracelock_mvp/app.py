"""
TraceLock - Air-Gapped Zero-Trust Document Distribution System
==============================================================
Main Flask Web Application with Role-Based Authentication and Sessions.

Architecture:
- Authentication & Session control via `flask.session`
- Role-based access control (Admin & Client)
- AES-256-GCM broadcast document vault
- Dynamic invisible forensic watermarking (PyMuPDF)
- Post-Quantum Digital Signatures (NIST FIPS 204 ML-DSA / Dilithium)
- Offline immutable hash-chain ledger (SQLite3)
- Forensic traitor-tracing laboratory
"""

import os
import io
import time
import uuid
from functools import wraps
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file, jsonify, abort, session
)

import crypto_utils as cu
import ledger_utils as lu
import watermark_utils as wu

# ==============================================================================
# Flask Application Setup & Paths
# ==============================================================================

app = Flask(__name__)
# Cryptographically random persistent secret key for Flask sessions
app.secret_key = os.urandom(32)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "vault")
KEYSTORE_DIR = os.path.join(BASE_DIR, "keystore")
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "tracelock.db")

MASTER_AES_KEY_PATH = os.path.join(KEYSTORE_DIR, "master_broadcast.key")
ALICE_PQC_KEY_PATH = os.path.join(KEYSTORE_DIR, "alice_pqc.key")
ADMIN_PQC_KEY_PATH = os.path.join(KEYSTORE_DIR, "admin_pqc.key")

# Ensure all directories exist
for path in (VAULT_DIR, KEYSTORE_DIR, DATA_DIR, UPLOADS_DIR):
    os.makedirs(path, exist_ok=True)

# Initialize Post-Quantum Signature Engine
pqc_engine = cu.PQCSignatureEngine()

# ==============================================================================
# Mock Credentials & Role Access
# ==============================================================================

MOCK_USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin",
        "display_name": "Defense Administrator",
        "key_path": ADMIN_PQC_KEY_PATH
    },
    "alice": {
        "password": "alice123",
        "role": "client",
        "display_name": "Alice (Authorized Analyst)",
        "key_path": ALICE_PQC_KEY_PATH
    }
}


# ==============================================================================
# Authentication & Role Decorators
# ==============================================================================

def login_required(allowed_roles=None):
    """
    Decorator to enforce session authentication and role-based clearance.
    
    :param allowed_roles: Optional list of authorized roles (e.g. ['admin', 'client']).
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = session.get("user")
            role = session.get("role")
            
            if not user or not role:
                flash("Access Denied: Authentication required to access defense terminal.", "error")
                return redirect(url_for("login", next=request.path))
                
            if allowed_roles and role not in allowed_roles:
                flash(f"Authorization Failure: Clearance level '{role.upper()}' denied access to requested resource.", "error")
                if role == "client":
                    return redirect(url_for("client_dashboard"))
                else:
                    return redirect(url_for("admin_dashboard"))
                    
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ==============================================================================
# System Initialization & Seeding
# ==============================================================================

def init_system() -> None:
    """
    Bootstrap the air-gapped system:
    1. Initialize the SQLite hash-chain ledger.
    2. Provision the AES-256 master broadcast key.
    3. Generate and enroll Post-Quantum ML-DSA key pairs for Admin and Alice.
    4. Seed initial classified broadcast document if vault is empty.
    """
    print("[TraceLock] Initializing air-gapped system...")
    lu.init_ledger_db(DB_PATH)
    conn = lu.get_db_connection(DB_PATH)

    # 1. Master AES-256 Broadcast Key
    if not os.path.exists(MASTER_AES_KEY_PATH):
        master_key = cu.generate_aes_key()
        cu.save_key_to_file(master_key, MASTER_AES_KEY_PATH)
        print(f"[TraceLock] Provisioned Master AES-256 broadcast key in {MASTER_AES_KEY_PATH}")

    # 2. Admin & Alice Post-Quantum ML-DSA Keystores
    for username, meta in MOCK_USERS.items():
        key_path = meta["key_path"]
        role = meta["role"]
        capitalized_user = username.title()
        
        if not os.path.exists(key_path) or not lu.get_user(conn, capitalized_user):
            print(f"[TraceLock] Generating Post-Quantum ({pqc_engine.get_algorithm()}) keypair for {capitalized_user}...")
            pub_bytes, priv_bytes = pqc_engine.generate_keypair()
            cu.save_key_to_file(priv_bytes, key_path)
            pub_hex = cu.key_to_hex(pub_bytes)
            lu.register_user(conn, capitalized_user, role, pqc_engine.get_algorithm(), pub_hex)
            print(f"[TraceLock] Enrolled {capitalized_user} with PQC public key ({len(pub_hex)} hex chars)")

    # 3. Seed Sample Document in Broadcast Vault if empty
    existing_docs = lu.list_vault_documents(conn)
    if not existing_docs:
        print("[TraceLock] Seeding default classified broadcast document into vault...")
        sample_title = "PROJECT ZEPHYR - AIR-GAPPED INTEL"
        sample_body = (
            "CLASSIFICATION: TOP SECRET // TRACELOCK SPECIAL ACCESS PROGRAM\n\n"
            "Executive Briefing:\n"
            "This document is encrypted under the TraceLock broadcast protocol using AES-256-GCM. "
            "Any authorized workstation decrypting this intelligence will have its cryptographic identity "
            "permanently bound to the document via a Post-Quantum ML-DSA signature and an offline "
            "immutable hash-chain ledger.\n\n"
            "Zero-Trust Traitor Tracing Notice:\n"
            "An invisible forensic watermark (ISO 32000-1 render_mode=3) is dynamically embedded "
            "at the exact moment of decryption. If this document is leaked, unauthorized dissemination "
            "can be mathematically attributed to the decryptor without network connectivity."
        )
        sample_pdf = wu.create_sample_pdf(sample_title, sample_body)
        doc_id = uuid.uuid4().hex[:12]
        doc_hash = cu.compute_sha256(sample_pdf)
        
        master_key = cu.load_key_from_file(MASTER_AES_KEY_PATH)
        encrypted_bytes = cu.encrypt_document_aes(sample_pdf, master_key)
        
        enc_filename = f"{doc_id}.enc"
        enc_path = os.path.join(VAULT_DIR, enc_filename)
        with open(enc_path, "wb") as f:
            f.write(encrypted_bytes)
            
        lu.register_vault_document(
            conn,
            doc_id=doc_id,
            original_filename="Project_Zephyr_Intel.pdf",
            encrypted_filename=enc_filename,
            file_hash=doc_hash,
            file_size=len(sample_pdf),
            uploaded_by="Admin"
        )
        print("[TraceLock] Seed document created and encrypted successfully.")

    conn.close()
    print("[TraceLock] System ready on localhost.")


# Run bootstrap
init_system()


# ==============================================================================
# Template Context Processor
# ==============================================================================

@app.context_processor
def inject_global_status():
    """Inject cryptographic engine metadata into all templates."""
    return {
        "pqc_algorithm": pqc_engine.get_algorithm(),
        "is_pqc_native": pqc_engine.is_pqc_enabled()
    }


# ==============================================================================
# Routes: Authentication & Sessions
# ==============================================================================

@app.route("/")
def index():
    """
    Root entrypoint:
    Redirects authenticated users to their authorized workspace.
    Unauthenticated users are directed to the secure login terminal.
    """
    if "user" in session:
        role = session.get("role")
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif role == "client":
            return redirect(url_for("client_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Secure Defense Terminal Entry Point."""
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "").strip()

        if username in MOCK_USERS and MOCK_USERS[username]["password"] == password:
            user_data = MOCK_USERS[username]
            session.clear()
            session["user"] = username
            session["role"] = user_data["role"]
            session["display_name"] = user_data["display_name"]

            flash(f"Access Granted: Cryptographic session mounted for {username.title()}.", "success")
            
            # Check for redirect query parameter or default by role
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)

            if user_data["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("client_dashboard"))
        else:
            flash("Authentication Failed: Invalid operator identifier or passphrase.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Terminate the active cryptographic session."""
    user = session.get("user", "Operator")
    session.clear()
    flash(f"Session Terminated: Keystore unmounted for {user}.", "info")
    return redirect(url_for("login"))


# ==============================================================================
# Routes: Admin Dashboard & Broadcast (Admin Only)
# ==============================================================================

@app.route("/admin")
@login_required(allowed_roles=["admin"])
def admin_dashboard():
    """Render the Admin dashboard with broadcast vault and hash-chain views."""
    conn = lu.get_db_connection(DB_PATH)
    documents = lu.list_vault_documents(conn)
    ledger_entries = lu.get_ledger_entries(conn, limit=50)
    users = lu.list_users(conn)
    ledger_audit = lu.verify_ledger_integrity(conn)
    conn.close()

    return render_template(
        "admin_dashboard.html",
        documents=documents,
        ledger_entries=ledger_entries,
        users=users,
        ledger_audit=ledger_audit
    )


@app.route("/upload_broadcast", methods=["POST"])
@login_required(allowed_roles=["admin"])
def upload_broadcast():
    """Handle admin broadcast upload of a standard PDF document."""
    file = request.files.get("pdf_file")
    if not file or file.filename == "":
        flash("Please select a valid PDF file to upload.", "error")
        return redirect(url_for("admin_dashboard"))

    if not file.filename.lower().endswith(".pdf"):
        flash("Invalid file type! Only standard PDF documents are supported.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        pdf_bytes = file.read()
        
        if not pdf_bytes.startswith(b"%PDF"):
            flash("The uploaded file is not a valid PDF document.", "error")
            return redirect(url_for("admin_dashboard"))

        doc_hash = cu.compute_sha256(pdf_bytes)
        doc_id = uuid.uuid4().hex[:12]
        
        master_key = cu.load_key_from_file(MASTER_AES_KEY_PATH)
        encrypted_data = cu.encrypt_document_aes(pdf_bytes, master_key)
        
        enc_filename = f"{doc_id}.enc"
        enc_path = os.path.join(VAULT_DIR, enc_filename)
        with open(enc_path, "wb") as f:
            f.write(encrypted_data)

        conn = lu.get_db_connection(DB_PATH)
        lu.register_vault_document(
            conn,
            doc_id=doc_id,
            original_filename=file.filename,
            encrypted_filename=enc_filename,
            file_hash=doc_hash,
            file_size=len(pdf_bytes),
            uploaded_by="Admin"
        )
        conn.close()

        flash(f"Document '{file.filename}' encrypted with AES-256-GCM and broadcast to vault (Doc ID: {doc_id}).", "success")
    except Exception as e:
        flash(f"Failed to encrypt and broadcast document: {str(e)}", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/seed_sample_broadcast")
@login_required(allowed_roles=["admin"])
def seed_sample_broadcast():
    """Generate and broadcast an additional sample classified PDF."""
    try:
        sample_title = f"AIR-GAPPED TELEMETRY REPORT #{uuid.uuid4().hex[:4].upper()}"
        sample_body = (
            "DEFENSE COVERT RECONNAISSANCE SUMMARY\n\n"
            "This report is generated dynamically by the TraceLock test suite. "
            "It simulates sensitive military/diplomatic intelligence shared over a broadcast channel."
        )
        pdf_bytes = wu.create_sample_pdf(sample_title, sample_body)
        doc_hash = cu.compute_sha256(pdf_bytes)
        doc_id = uuid.uuid4().hex[:12]
        
        master_key = cu.load_key_from_file(MASTER_AES_KEY_PATH)
        encrypted_data = cu.encrypt_document_aes(pdf_bytes, master_key)
        
        enc_filename = f"{doc_id}.enc"
        enc_path = os.path.join(VAULT_DIR, enc_filename)
        with open(enc_path, "wb") as f:
            f.write(encrypted_data)

        conn = lu.get_db_connection(DB_PATH)
        lu.register_vault_document(
            conn,
            doc_id=doc_id,
            original_filename=f"Telemetry_{doc_id[:6].upper()}.pdf",
            encrypted_filename=enc_filename,
            file_hash=doc_hash,
            file_size=len(pdf_bytes),
            uploaded_by="Admin"
        )
        conn.close()
        flash("Quick test sample generated, encrypted, and registered in vault.", "success")
    except Exception as e:
        flash(f"Failed to generate sample: {str(e)}", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/download_vault/<doc_id>")
@login_required(allowed_roles=["admin"])
def download_vault_ciphertext(doc_id: str):
    """Download the raw AES-256 ciphertext file from the vault."""
    conn = lu.get_db_connection(DB_PATH)
    doc = lu.get_vault_document(conn, doc_id)
    conn.close()
    
    if not doc:
        abort(404, "Vault document not found.")
        
    enc_path = os.path.join(VAULT_DIR, doc["encrypted_filename"])
    if not os.path.exists(enc_path):
        abort(404, "Vault file missing on disk.")
        
    return send_file(
        enc_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"{doc['original_filename']}.enc"
    )


# ==============================================================================
# Routes: Client Dashboard & The Decryption Loop (Client & Admin)
# ==============================================================================

@app.route("/client")
@login_required(allowed_roles=["client", "admin"])
def client_dashboard():
    """
    Render Alice's client workstation interface.
    Displays client keystore and list of available broadcast documents.
    """
    active_user = session.get("user", "alice").title()
    conn = lu.get_db_connection(DB_PATH)
    documents = lu.list_vault_documents(conn)
    alice_user = lu.get_user(conn, active_user) or lu.get_user(conn, "Alice")
    conn.close()

    alice_public_key = alice_user["public_key"] if alice_user else "N/A"

    return render_template(
        "client_dashboard.html",
        documents=documents,
        alice_public_key=alice_public_key
    )


@app.route("/decrypt/<doc_id>")
@login_required(allowed_roles=["client", "admin"])
def decrypt_document(doc_id: str):
    """
    THE DECRYPTION LOOP (Crucial Traitor-Tracing Engine):
    When an authorized operator clicks 'Decrypt':
    1. Read and decrypt AES-256 payload from the local vault.
    2. Mint a unique Session_ID (UUID + Timestamp + UserID).
    3. Use PyMuPDF to inject the Session_ID as invisible 0% opacity text & metadata.
    4. Prompt the operator's local Post-Quantum private key to sign:
       SHA256(FileHash + Session_ID + Timestamp).
    5. Append the immutable record to the SQLite hash-chain ledger.
    6. Deliver the pristine watermarked PDF for download.
    """
    current_user = session.get("user", "alice")
    capitalized_user = current_user.title()
    user_key_path = MOCK_USERS.get(current_user, {}).get("key_path", ALICE_PQC_KEY_PATH)

    conn = lu.get_db_connection(DB_PATH)
    doc = lu.get_vault_document(conn, doc_id)
    
    if not doc:
        conn.close()
        flash("Requested document not found in vault.", "error")
        return redirect(url_for("client_dashboard"))

    enc_path = os.path.join(VAULT_DIR, doc["encrypted_filename"])
    if not os.path.exists(enc_path):
        conn.close()
        flash("Encrypted ciphertext missing from local vault storage.", "error")
        return redirect(url_for("client_dashboard"))

    try:
        # Step 1: Read and Decrypt AES-256-GCM payload
        with open(enc_path, "rb") as f:
            encrypted_bytes = f.read()
            
        master_key = cu.load_key_from_file(MASTER_AES_KEY_PATH)
        plaintext_pdf = cu.decrypt_document_aes(encrypted_bytes, master_key)
        
        # Step 2: Generate Unique Session_ID & Timestamp
        timestamp_str = datetime.now(timezone.utc).isoformat()
        session_uuid = uuid.uuid4().hex[:10].upper()
        session_id = f"TL-SESS-{session_uuid}-{capitalized_user.upper()}-{int(time.time())}"
        
        # Step 3: Inject Invisible Forensic Watermark via PyMuPDF
        watermarked_pdf = wu.embed_invisible_watermark(
            pdf_bytes=plaintext_pdf,
            session_id=session_id,
            user_id=capitalized_user,
            timestamp=timestamp_str
        )
        
        # Step 4: Prompt Local Post-Quantum Private Key to sign decryption binding
        # Binding: SHA256(FileHash + Session_ID + Timestamp)
        operator_priv_key = cu.load_key_from_file(user_key_path)
        binding_digest = cu.create_decryption_event_digest(
            file_hash=doc["file_hash"],
            session_id=session_id,
            timestamp_str=timestamp_str
        )
        
        pqc_signature_bytes = pqc_engine.sign(binding_digest, operator_priv_key)
        pqc_signature_hex = cu.key_to_hex(pqc_signature_bytes)
        
        # Step 5: Append to SQLite Hash-Chain Ledger
        ledger_entry = lu.append_ledger_entry(
            conn=conn,
            session_id=session_id,
            user_id=capitalized_user,
            document_name=doc["original_filename"],
            document_hash=doc["file_hash"],
            pqc_algorithm=pqc_engine.get_algorithm(),
            pqc_signature=pqc_signature_hex,
            timestamp=timestamp_str
        )
        conn.close()

        # Step 6: Serve pristine, watermarked PDF to operator for download
        filename_out = f"Watermarked_{doc['original_filename']}"
        return send_file(
            io.BytesIO(watermarked_pdf),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename_out
        )

    except Exception as e:
        conn.close()
        flash(f"Decryption protocol execution failed: {str(e)}", "error")
        return redirect(url_for("client_dashboard"))


# ==============================================================================
# Routes: Forensic Extraction & Traitor Tracing Laboratory (Admin Only)
# ==============================================================================

@app.route("/forensics", methods=["GET", "POST"])
@login_required(allowed_roles=["admin"])
def forensics_page():
    """
    Forensic Extractor & Traitor Tracing:
    1. Extracts invisible covert watermark from suspect leaked PDF.
    2. Queries SQLite ledger for associated Session_ID.
    3. Retrieves Post-Quantum signature and User Public Key.
    4. Mathematically verifies the signature over SHA256(FileHash + Session_ID + Timestamp).
    5. Returns mathematically irrefutable traitor attribution report.
    """
    report = None

    if request.method == "POST":
        file = request.files.get("leaked_pdf")
        if not file or file.filename == "":
            flash("Please choose a suspect PDF file for forensic analysis.", "error")
            return redirect(url_for("forensics_page"))

        try:
            pdf_bytes = file.read()
            
            # Step 1: Deep steganographic watermark extraction
            wm_info = wu.extract_watermark(pdf_bytes)
            
            if not wm_info or not wm_info.get("session_id"):
                report = {
                    "success": False,
                    "error": (
                        "No TraceLock forensic markers detected in this PDF. "
                        "The document does not originate from an authorized TraceLock decryption session."
                    )
                }
            else:
                session_id = wm_info["session_id"]
                
                # Step 2: Query SQLite hash-chain ledger for Session_ID
                conn = lu.get_db_connection(DB_PATH)
                entry = lu.get_ledger_entry_by_session(conn, session_id)
                
                if not entry:
                    report = {
                        "success": False,
                        "session_id": session_id,
                        "error": f"Session ID '{session_id}' found in document watermark, but no matching record exists in the local ledger."
                    }
                else:
                    # Step 3: Retrieve user and public key
                    user = lu.get_user(conn, entry["user_id"])
                    
                    if not user:
                        report = {
                            "success": False,
                            "session_id": session_id,
                            "error": f"Decryptor identity '{entry['user_id']}' recorded in ledger, but user public key is missing from keystore registry."
                        }
                    else:
                        # Step 4: Mathematically verify Post-Quantum signature
                        binding_digest = cu.create_decryption_event_digest(
                            file_hash=entry["document_hash"],
                            session_id=session_id,
                            timestamp_str=entry["timestamp"]
                        )
                        
                        sig_bytes = cu.hex_to_key(entry["pqc_signature"])
                        pub_bytes = cu.hex_to_key(user["public_key"])
                        
                        # Configure verification engine for the exact algorithm stored in the block
                        verification_engine = cu.PQCSignatureEngine(algorithm=entry["pqc_algorithm"])
                        sig_valid = verification_engine.verify(binding_digest, sig_bytes, pub_bytes)
                        
                        # Verify ledger block integrity
                        ledger_audit = lu.verify_ledger_integrity(conn)

                        report = {
                            "success": True,
                            "session_id": session_id,
                            "user_id": entry["user_id"],
                            "timestamp": entry["timestamp"],
                            "document_name": entry["document_name"],
                            "document_hash": entry["document_hash"],
                            "detection_layers": wm_info.get("detection_layers", ["Covert Watermark Layer"]),
                            "pages_found": wm_info.get("pages_found", [1]),
                            "pqc_algorithm": entry["pqc_algorithm"],
                            "pqc_signature": entry["pqc_signature"],
                            "public_key": user["public_key"],
                            "signature_valid": sig_valid,
                            "ledger_block_id": entry["id"],
                            "previous_hash": entry["previous_hash"],
                            "current_hash": entry["current_hash"],
                            "ledger_audit_valid": ledger_audit["valid"]
                        }

                conn.close()

        except Exception as e:
            report = {
                "success": False,
                "error": f"Forensic parsing error: {str(e)}"
            }

    return render_template("forensics.html", report=report)


# ==============================================================================
# Simulation & Demo Utilities
# ==============================================================================

@app.route("/tamper_ledger", methods=["POST"])
@login_required(allowed_roles=["admin"])
def tamper_ledger():
    """Simulation action: Deliberately tamper with a ledger block in SQLite."""
    block_id = request.form.get("block_id", type=int)
    forged_user = request.form.get("forged_user", default="Eve_The_Attacker")

    if not block_id:
        flash("Invalid block ID for tampering simulation.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = lu.get_db_connection(DB_PATH)
    success = lu.simulate_ledger_tampering(conn, block_id, forged_user)
    conn.close()

    if success:
        flash(f"TAMPERING INJECTED: Block #{block_id} decryptor modified to '{forged_user}'. Run audit to see detection!", "warning")
    else:
        flash("Failed to tamper with block (invalid block ID).", "error")

    return redirect(url_for("admin_dashboard"))


@app.route("/repair_tamper")
@login_required(allowed_roles=["admin"])
def repair_tamper():
    """Restore tampered user back to Alice for demo continuity."""
    conn = lu.get_db_connection(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE ledger SET user_id = 'Alice' WHERE user_id != 'Alice' AND user_id != 'Admin'")
    conn.commit()
    conn.close()
    flash("Tampering reverted. Ledger integrity restored.", "success")
    return redirect(url_for("admin_dashboard"))


# ==============================================================================
# JSON API Endpoints
# ==============================================================================

@app.route("/api/verify_ledger")
@login_required(allowed_roles=["admin"])
def api_verify_ledger():
    """Audit the SQLite hash-chain ledger and return JSON report."""
    conn = lu.get_db_connection(DB_PATH)
    audit = lu.verify_ledger_integrity(conn)
    conn.close()
    return jsonify(audit)


@app.route("/api/stats")
def api_stats():
    """Return high-level cryptographic telemetry."""
    conn = lu.get_db_connection(DB_PATH)
    docs = lu.list_vault_documents(conn)
    entries = lu.list_users(conn)
    ledger = lu.get_ledger_entries(conn)
    conn.close()

    return jsonify({
        "status": "ONLINE",
        "air_gapped": True,
        "pqc_algorithm": pqc_engine.get_algorithm(),
        "pqc_native": pqc_engine.is_pqc_enabled(),
        "documents_in_vault": len(docs),
        "ledger_blocks": len(ledger),
        "identities": len(entries)
    })


# ==============================================================================
# Entry Point
# ==============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 65)
    print(" 🛡️  TraceLock Air-Gapped Zero-Trust Traitor Tracing System")
    print("    Running on: http://127.0.0.1:5000")
    print(f"    Post-Quantum Signature Engine: {pqc_engine.get_algorithm()}")
    print("=" * 65 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
