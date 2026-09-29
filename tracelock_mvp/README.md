# TraceLock: Air-Gapped Zero-Trust Traitor Tracing System

**TraceLock** is a local, air-gapped, zero-trust document distribution system for high-security broadcast document sharing (specifically PDFs). It solves the classical **traitor tracing** problem without relying on external cloud Key Management Services (KMS) or persistent internet connectivity.

---

## Key Security Innovations

1. **Air-Gapped & Zero Cloud Dependency**: Runs entirely on `localhost` (`127.0.0.1:5000`) with zero external network calls. All front-end assets (Bootstrap 5, Icons, custom CSS) are served locally.
2. **Standard Broadcast Encryption**: AES-256-GCM authenticated cipher encrypts broadcast payloads stored in the local vault.
3. **NIST Post-Quantum Digital Signatures (ML-DSA / Dilithium)**: Modular PQC wrapper implementing NIST FIPS 204 (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`, or classical fallback). Decryption events are cryptographically signed by the client's local quantum-resistant private key.
4. **Covert Dynamic Watermarking (PyMuPDF)**: At the exact moment of decryption, an invisible forensic watermark is dynamically injected using ISO 32000-1 invisible text rendering (`render_mode=3`), microscopic glyphs, and PDF metadata dictionaries.
5. **Offline Immutable Hash-Chain Ledger**: SQLite3 database with blockchain-style hash linking (`previous_hash` and `current_hash` SHA-256 chain). Any unauthorized modification to audit records immediately breaks the chain.
6. **Automated Forensic Extraction & Attribution**: Leaked PDFs uploaded to the forensics laboratory are scanned, extracting the covert session ID, verifying the ML-DSA signature against the client's public key, and identifying the leaker with mathematical certainty.

---

## Project Structure

```
/tracelock_mvp
  ├── app.py                 # Main Flask application, routing, and controller
  ├── crypto_utils.py        # AES-256-GCM and modular Post-Quantum ML-DSA engine
  ├── watermark_utils.py     # PyMuPDF invisible forensic watermarking and extraction
  ├── ledger_utils.py        # SQLite3 hash-chain database operations & audit
  ├── data/                  # SQLite database storage (tracelock.db)
  ├── keystore/              # Local client/admin private keys (alice_pqc.key, master_broadcast.key)
  ├── vault/                 # AES-256 encrypted document storage (.enc)
  ├── static/
  │    ├── css/              # Local Bootstrap 5, Bootstrap Icons, style.css
  │    └── js/               # Local Bootstrap bundle JS
  └── templates/
       ├── base.html             # Common dark-mode cybersecurity layout
       ├── admin_dashboard.html  # Broadcast upload, vault list, and hash-chain ledger
       ├── client_dashboard.html # Alice's workstation and 6-step decryption loop
       └── forensics.html        # Leaked PDF analysis and traitor tracing laboratory
```

---

## Installation & Setup

### 1. Python Environment
TraceLock requires **Python 3.10+**.

```bash
# Clone and enter directory
cd /path/to/ShareAndForensic/tracelock_mvp

# Install core dependencies
pip install flask cryptography pymupdf
```

### 2. Post-Quantum Cryptography Setup (`liboqs` & `liboqs-python`)

TraceLock uses **Open Quantum Safe (OQS)** for NIST FIPS 204 Post-Quantum signatures.

#### Option A: Linux (Fedora / RHEL)
```bash
# Install system liboqs shared libraries
sudo dnf install -y liboqs liboqs-devel

# Install python bindings
pip install liboqs-python
```

#### Option B: Linux (Ubuntu / Debian)
```bash
sudo apt-get update
sudo apt-get install -y cmake gcc ninja-build libssl-dev

# Clone and build liboqs
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install
cd ../..

# Install python bindings
pip install liboqs-python
```

#### Option C: Automatic Modular Fallback
`crypto_utils.py` contains an intelligent, modular wrapper. If native `liboqs` is not installed on a development machine, TraceLock automatically detects this and falls back to standard cryptographic signatures (Ed25519) with explicit warnings, allowing the entire application to run seamlessly across any platform without crashes.

---

## Authentication & Access Control

TraceLock includes role-based access control (RBAC) managed via `flask.session`:

| Identity | Username | Password | Role | Access Clearance |
| :--- | :--- | :--- | :--- | :--- |
| **Defense Administrator** | `admin` | `admin123` | `admin` | Full Clearance: `/admin`, `/forensics`, Broadcast Vault, Ledger Audit, Tamper Simulator |
| **Alice (Client Analyst)** | `alice` | `alice123` | `client` | Client Terminal: `/client`, Decryption Loop `/decrypt/<doc_id>` |

*Unauthenticated users or users attempting to access endpoints outside their security clearance are immediately redirected to `/login` with an authorization error flash.*

---

## Running the Application

Start the local web server:

```bash
cd tracelock_mvp
python3 app.py
```

Open your browser to:
```
http://127.0.0.1:5000
```
*(Automatically routes unauthenticated requests to the secure `/login` terminal)*

---

## Complete Walkthrough Demo Guide

### Step 1: Secure Terminal Login (`/login`)
1. Open `http://127.0.0.1:5000`. You will be directed to the **Tactical Defense Terminal Entry**.
2. Click **Admin Authority** (or enter `admin` / `admin123`) to authenticate.
3. You will be redirected to the **Admin Dashboard** (`/admin`).

### Step 2: Admin Broadcast & Ledger Management (`/admin`)
1. Inspect the **Post-Quantum Layer** status card (indicates active algorithm, e.g., `ML-DSA-44`).
2. Click **Quick Test Sample** (or upload your own PDF).
3. The system encrypts the PDF using **AES-256-GCM** and stores it in the `vault/` directory.
4. Click **Logout** in the top navigation bar to terminate the session.

### Step 3: Client Decryption Loop (`/client`)
1. On the login screen, click **Alice (Client Agent)** (or enter `alice` / `alice123`).
2. You will be redirected to Alice's **Client Terminal** (`/client`).
3. View Alice's mounted keystore: her 2,560-byte Post-Quantum private key stored in `keystore/alice_pqc.key` and her registered public key fingerprint.
4. Click **Decrypt & Download** next to the broadcast document.
5. The backend executes the atomic 6-step loop:
   - Reads ciphertext from the vault and decrypts with AES-256.
   - Mints a unique `Session_ID`: `TL-SESS-<UUID>-ALICE-<TIMESTAMP>`.
   - Uses PyMuPDF to inject covert 0% opacity text (`render_mode=3`) and metadata tags.
   - Prompts Alice's PQC private key to sign `SHA256(FileHash + Session_ID + Timestamp)`.
   - Records the event into the SQLite hash-chain ledger.
   - Streams the pristine, watermarked PDF (`Watermarked_Project_Zephyr_Intel.pdf`) to your browser.
6. Click **Logout**.

### Step 4: Ledger Inspection & Tamper Simulation (`/admin`)
1. Log in again as **Admin**.
2. Notice the new block in the **Immutable Hash-Chain Ledger** table with `Previous_Hash` linked to the genesis hash and `Current_Hash` highlighted.
3. Click **Audit Integrity** to execute a cryptographic audit.
4. Test Tamper-Evidence:
   - Click **Tamper Simulation** and inject a forged decryptor (e.g., `Eve_The_Attacker`).
   - The status bar immediately flags an **INTEGRITY VIOLATION**, pointing to the exact altered block!
   - Click **Revert Tampering** to restore the chain.

### Step 5: Forensic Traitor Tracing (`/forensics`)
1. Navigate to **Forensic Extractor** in the navbar (`/forensics`).
2. Upload the `Watermarked_...pdf` file downloaded during Alice's session.
3. Click **Extract Watermark & Trace Culprit**.
4. The Forensic Lab displays a **dramatic, pulsing neon breach banner**:
   - **SECURITY BREACH DETECTED: LEAK TRACED TO OPERATOR [ ALICE ]**
   - **Post-Quantum Digital Signature: VERIFIED** (mathematically verified against Alice's ML-DSA public key).
   - **Steganographic Detection Layers**: Invisible Page Text (Layer 1) & Document Metadata (Layer 2).
   - **Immutable Hash-Chain Anchor**: Verified Block link in SQLite.
   - **Mathematical Non-Repudiation**: Definitively proves Alice decrypted and redistributed the file.
