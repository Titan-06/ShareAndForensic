"""
TraceLock - Immutable Hash-Chain Ledger Module
===============================================
This module implements an offline, tamper-evident hash-chain ledger using SQLite3.

Blockchain-like properties:
- Every record is cryptographically bound to its predecessor via `previous_hash`.
- The `current_hash` is computed over the row's payload concatenated with `previous_hash`.
- Any unauthorized modification, row deletion, or insertion retroactively invalidates
  the entire hash chain down to the genesis block.
"""

import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

GENESIS_HASH = "0" * 64


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Create a thread-safe connection to the SQLite ledger database."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_ledger_db(db_path: str) -> None:
    """
    Initialize SQLite tables for:
    1. `ledger`: The immutable hash-chain audit log for document decryptions.
    2. `users`: Public keys, roles, and identity mappings.
    3. `documents`: Metadata for broadcast-encrypted documents stored in the vault.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    # 1. Immutable Hash-Chain Ledger Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        session_id TEXT UNIQUE NOT NULL,
        user_id TEXT NOT NULL,
        document_name TEXT NOT NULL,
        document_hash TEXT NOT NULL,
        pqc_algorithm TEXT NOT NULL,
        pqc_signature TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL
    )
    """)
    
    # 2. User & Post-Quantum Public Key Keystore Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL,
        pqc_algorithm TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    
    # 3. Encrypted Vault Documents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_id TEXT UNIQUE NOT NULL,
        original_filename TEXT NOT NULL,
        encrypted_filename TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        uploaded_by TEXT NOT NULL,
        uploaded_at TEXT NOT NULL
    )
    """)
    
    conn.commit()
    conn.close()


def get_latest_hash(conn: sqlite3.Connection) -> str:
    """Retrieve the current_hash of the most recently committed ledger block."""
    cursor = conn.cursor()
    cursor.execute("SELECT current_hash FROM ledger ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if row and row["current_hash"]:
        return row["current_hash"]
    return GENESIS_HASH


def compute_block_hash(
    block_id: Optional[int],
    timestamp: str,
    session_id: str,
    user_id: str,
    document_name: str,
    document_hash: str,
    pqc_algorithm: str,
    pqc_signature: str,
    previous_hash: str
) -> str:
    """
    Deterministically compute the SHA-256 hash of a ledger block.
    Combines all immutable fields with the previous_hash link.
    """
    canonical_repr = (
        f"{timestamp}|"
        f"{session_id}|"
        f"{user_id}|"
        f"{document_name}|"
        f"{document_hash}|"
        f"{pqc_algorithm}|"
        f"{pqc_signature}|"
        f"{previous_hash}"
    )
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


def append_ledger_entry(
    conn: sqlite3.Connection,
    session_id: str,
    user_id: str,
    document_name: str,
    document_hash: str,
    pqc_algorithm: str,
    pqc_signature: str,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Append an immutable event to the hash-chain ledger.
    Calculates previous_hash, computes current_hash, and commits the row atomically.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
        
    cursor = conn.cursor()
    
    # In SQLite, wrap in immediate transaction to prevent race conditions in sequential blocks
    cursor.execute("BEGIN IMMEDIATE")
    try:
        # Get the previous block's hash
        cursor.execute("SELECT current_hash FROM ledger ORDER BY id DESC LIMIT 1")
        last_row = cursor.fetchone()
        previous_hash = last_row["current_hash"] if last_row else GENESIS_HASH
        
        # Calculate current hash
        current_hash = compute_block_hash(
            block_id=None,
            timestamp=timestamp,
            session_id=session_id,
            user_id=user_id,
            document_name=document_name,
            document_hash=document_hash,
            pqc_algorithm=pqc_algorithm,
            pqc_signature=pqc_signature,
            previous_hash=previous_hash
        )
        
        cursor.execute("""
            INSERT INTO ledger (
                timestamp, session_id, user_id, document_name, document_hash,
                pqc_algorithm, pqc_signature, previous_hash, current_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, session_id, user_id, document_name, document_hash,
            pqc_algorithm, pqc_signature, previous_hash, current_hash
        ))
        
        row_id = cursor.lastrowid
        conn.commit()
        
        return {
            "id": row_id,
            "timestamp": timestamp,
            "session_id": session_id,
            "user_id": user_id,
            "document_name": document_name,
            "document_hash": document_hash,
            "pqc_algorithm": pqc_algorithm,
            "pqc_signature": pqc_signature,
            "previous_hash": previous_hash,
            "current_hash": current_hash
        }
    except Exception as e:
        conn.rollback()
        raise e


def get_ledger_entries(conn: sqlite3.Connection, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve ledger entries sorted in chronological sequence."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ledger ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_ledger_entry_by_session(conn: sqlite3.Connection, session_id: str) -> Optional[Dict[str, Any]]:
    """Lookup a forensic record by its unique Session_ID."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ledger WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def verify_ledger_integrity(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    Cryptographically verify the integrity of the entire ledger hash-chain.
    
    Checks:
    1. Genesis block references the standard 64-zero genesis hash.
    2. Every block's previous_hash exactly equals the prior block's current_hash.
    3. Every block's current_hash matches the recalculated SHA-256 hash of its contents.
    
    :return: Audit report dictionary with validity status and diagnostic info.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ledger ORDER BY id ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    
    if not rows:
        return {
            "valid": True,
            "total_blocks": 0,
            "message": "Ledger is currently empty (Genesis state).",
            "broken_at_block": None
        }
        
    expected_prev = GENESIS_HASH
    
    for idx, block in enumerate(rows):
        block_id = block["id"]
        
        # 1. Check backward linkage
        if block["previous_hash"] != expected_prev:
            return {
                "valid": False,
                "total_blocks": len(rows),
                "broken_at_block": block_id,
                "message": f"Hash chain broken at Block #{block_id}! Expected previous_hash '{expected_prev[:12]}...', found '{block['previous_hash'][:12]}...'"
            }
            
        # 2. Check internal integrity (recompute hash)
        recalculated_hash = compute_block_hash(
            block_id=block["id"],
            timestamp=block["timestamp"],
            session_id=block["session_id"],
            user_id=block["user_id"],
            document_name=block["document_name"],
            document_hash=block["document_hash"],
            pqc_algorithm=block["pqc_algorithm"],
            pqc_signature=block["pqc_signature"],
            previous_hash=block["previous_hash"]
        )
        
        if recalculated_hash != block["current_hash"]:
            return {
                "valid": False,
                "total_blocks": len(rows),
                "broken_at_block": block_id,
                "message": f"Content tampering detected in Block #{block_id}! Recorded hash '{block['current_hash'][:12]}...' does not match recalculated hash '{recalculated_hash[:12]}...'."
            }
            
        expected_prev = block["current_hash"]
        
    return {
        "valid": True,
        "total_blocks": len(rows),
        "message": f"Ledger integrity verified successfully. All {len(rows)} blocks cryptographically validated.",
        "broken_at_block": None
    }


def simulate_ledger_tampering(conn: sqlite3.Connection, block_id: int, forged_user: str = "Eve_Mallory") -> bool:
    """
    Simulation tool: Intentionally tamper with a block's user_id or content in the database.
    This demonstrates the immediate failure of the hash-chain audit.
    """
    cursor = conn.cursor()
    cursor.execute("UPDATE ledger SET user_id = ? WHERE id = ?", (forged_user, block_id))
    conn.commit()
    return cursor.rowcount > 0


# ==============================================================================
# User & Document Management Helpers
# ==============================================================================

def register_user(
    conn: sqlite3.Connection,
    username: str,
    role: str,
    pqc_algorithm: str,
    public_key_hex: str
) -> None:
    """Upsert a user with their Post-Quantum public key."""
    cursor = conn.cursor()
    now_ts = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO users (username, role, pqc_algorithm, public_key, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            role = excluded.role,
            pqc_algorithm = excluded.pqc_algorithm,
            public_key = excluded.public_key
    """, (username, role, pqc_algorithm, public_key_hex, now_ts))
    conn.commit()


def get_user(conn: sqlite3.Connection, username: str) -> Optional[Dict[str, Any]]:
    """Retrieve user details and Post-Quantum public key."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    return dict(row) if row else None


def list_users(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """List all registered identities."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY id ASC")
    return [dict(r) for r in cursor.fetchall()]


def register_vault_document(
    conn: sqlite3.Connection,
    doc_id: str,
    original_filename: str,
    encrypted_filename: str,
    file_hash: str,
    file_size: int,
    uploaded_by: str
) -> None:
    """Register an AES-256 broadcast encrypted document in the database."""
    cursor = conn.cursor()
    now_ts = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
        INSERT INTO documents (
            doc_id, original_filename, encrypted_filename,
            file_hash, file_size, uploaded_by, uploaded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (doc_id, original_filename, encrypted_filename, file_hash, file_size, uploaded_by, now_ts))
    conn.commit()


def list_vault_documents(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """List all available documents in the broadcast vault."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents ORDER BY id DESC")
    return [dict(r) for r in cursor.fetchall()]


def get_vault_document(conn: sqlite3.Connection, doc_id: str) -> Optional[Dict[str, Any]]:
    """Lookup a vault document by its unique document ID."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,))
    row = cursor.fetchone()
    return dict(row) if row else None
