"""
TraceLock - Cryptographic Utilities Module
===========================================
This module provides cryptographic primitives for the TraceLock air-gapped system:
1. Standard Cryptography: AES-256-GCM for broadcast document encryption.
2. Post-Quantum Cryptography (PQC): Modular wrapper for NIST-standardized
   ML-DSA (Dilithium) digital signatures via `liboqs-python`.
3. Keystore management: Loading and persisting quantum-resistant key pairs.
"""

import os
import sys
import ctypes
import hashlib
from typing import Tuple, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ensure system libcrypto is preloaded with RTLD_GLOBAL if available.
# This guarantees that OpenSSL 3.x symbols (such as EVP_DigestSqueeze)
# are resolvable by liboqs.so when dynamically loaded.
try:
    if sys.platform.startswith("linux"):
        for libname in ("libcrypto.so.3", "libcrypto.so", "libcrypto.so.1.1"):
            try:
                ctypes.CDLL(libname, mode=ctypes.RTLD_GLOBAL)
                break
            except Exception:
                continue
except Exception:
    pass

# Try importing liboqs
HAS_LIBOQS = False
OQS_LIB_ERROR = None

try:
    import oqs
    HAS_LIBOQS = True
except Exception as e:
    OQS_LIB_ERROR = str(e)


# ==============================================================================
# 1. Standard Cryptography: AES-256-GCM Broadcast Encryption
# ==============================================================================

def generate_aes_key() -> bytes:
    """Generate a cryptographically secure 256-bit (32 bytes) AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_document_aes(data: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Encrypt a document payload using AES-256-GCM authenticated encryption.
    
    Structure of returned ciphertext:
    [12-byte Nonce / IV] + [AES-GCM Ciphertext with 16-byte Tag appended]
    
    :param data: Plaintext document bytes.
    :param key: 32-byte AES key.
    :param associated_data: Optional authenticated data (AAD).
    :return: Nonce concatenated with ciphertext and authentication tag.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key. Received: {len(key)} bytes.")
    
    # Standard 96-bit (12-byte) nonce for AES-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, associated_data)
    
    return nonce + ciphertext_with_tag


def decrypt_document_aes(encrypted_data: bytes, key: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted payload.
    
    :param encrypted_data: [12-byte Nonce] + [Ciphertext + 16-byte Tag]
    :param key: 32-byte AES key.
    :param associated_data: Optional authenticated data used during encryption.
    :return: Plaintext bytes.
    :raises cryptography.exceptions.InvalidTag: If data was tampered with or key is wrong.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key. Received: {len(key)} bytes.")
    if len(encrypted_data) < 28: # 12 bytes nonce + 16 bytes tag minimum
        raise ValueError("Encrypted data is too short to be a valid AES-GCM payload.")
    
    nonce = encrypted_data[:12]
    ciphertext_with_tag = encrypted_data[12:]
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)


def compute_sha256(data: bytes) -> str:
    """Compute the SHA-256 hexadecimal hash string for arbitrary binary data."""
    return hashlib.sha256(data).hexdigest()


# ==============================================================================
# 2. Modular Post-Quantum Cryptography (PQC) Signature Wrapper
# ==============================================================================

class PQCSignatureEngine:
    """
    Modular wrapper for Post-Quantum Digital Signature schemes.
    
    Defaults to NIST FIPS 204 ML-DSA-44 (Dilithium2), and allows seamless
    swapping to ML-DSA-65 (Dilithium3), ML-DSA-87 (Dilithium5), or classical
    fallbacks for heterogeneous air-gapped nodes.
    """
    
    # Priority list of quantum-resistant signature algorithms
    PREFERRED_ALGORITHMS = [
        "ML-DSA-44",     # NIST FIPS 204 Category 2 (Dilithium2)
        "ML-DSA-65",     # NIST FIPS 204 Category 3 (Dilithium3)
        "ML-DSA-87",     # NIST FIPS 204 Category 5 (Dilithium5)
        "Dilithium2",
        "Dilithium3",
        "Dilithium5"
    ]
    
    def __init__(self, algorithm: Optional[str] = None):
        """
        Initialize the PQC Signature Engine with a requested or auto-detected algorithm.
        """
        self.is_native_pqc = False
        self.available_mechanisms: List[str] = []
        
        if HAS_LIBOQS:
            try:
                enabled = oqs.get_enabled_sig_mechanisms()
                self.available_mechanisms = [str(m) for m in enabled]
                self.is_native_pqc = True
            except Exception as e:
                print(f"[PQCSignatureEngine] Warning: Failed to query liboqs mechanisms: {e}")
                self.is_native_pqc = False
                
        # Resolve target algorithm
        if algorithm:
            self.algorithm = algorithm
        elif self.is_native_pqc:
            # Pick first available algorithm from preferred list
            matched = [alg for alg in self.PREFERRED_ALGORITHMS if alg in self.available_mechanisms]
            if matched:
                self.algorithm = matched[0]
            elif self.available_mechanisms:
                self.algorithm = self.available_mechanisms[0]
            else:
                self.algorithm = "FALLBACK-ED25519"
        else:
            self.algorithm = "FALLBACK-ED25519"

    def get_algorithm(self) -> str:
        """Return the current signature algorithm name."""
        return self.algorithm

    def is_pqc_enabled(self) -> bool:
        """Return True if running on native Post-Quantum liboqs."""
        return self.is_native_pqc and (self.algorithm in self.available_mechanisms)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a Post-Quantum public and private key pair.
        
        :return: (public_key_bytes, secret_key_bytes)
        """
        if self.is_pqc_enabled():
            with oqs.Signature(self.algorithm) as signer:
                public_key = signer.generate_keypair()
                secret_key = signer.export_secret_key()
                return public_key, secret_key
        else:
            # Fallback using standard cryptography Ed25519 if liboqs native is unavailable
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            priv_bytes = priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return pub_bytes, priv_bytes

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a binary message with the Post-Quantum secret key.
        
        :param message: Binary message bytes (or digest).
        :param secret_key: Private/Secret key bytes.
        :return: Post-Quantum digital signature bytes.
        """
        if self.is_pqc_enabled():
            with oqs.Signature(self.algorithm, secret_key=secret_key) as signer:
                return signer.sign(message)
        else:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
            return priv.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a digital signature against the message and public key.
        
        :param message: Binary message bytes.
        :param signature: Digital signature bytes.
        :param public_key: Public key bytes.
        :return: True if signature is valid, False otherwise.
        """
        if not signature or not public_key or not message:
            return False
            
        if self.is_pqc_enabled():
            try:
                with oqs.Signature(self.algorithm) as verifier:
                    return verifier.verify(message, signature, public_key)
            except Exception as e:
                print(f"[PQCSignatureEngine] Verification exception: {e}")
                return False
        else:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.exceptions import InvalidSignature
            try:
                pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
                pub.verify(signature, message)
                return True
            except InvalidSignature:
                return False
            except Exception:
                return False


# ==============================================================================
# 3. Decryption Event Binding & Keystore Utilities
# ==============================================================================

def create_decryption_event_digest(file_hash: str, session_id: str, timestamp_str: str) -> bytes:
    """
    Construct the canonical cryptographic binding payload string:
    SHA256(FileHash + Session_ID + Timestamp)
    
    This binds the specific decrypted document state, the unique tracking session,
    and the physical moment of decryption into an irrefutable claim.
    
    :return: 32-byte SHA-256 binary digest.
    """
    canonical_str = f"{file_hash}:{session_id}:{timestamp_str}"
    return hashlib.sha256(canonical_str.encode("utf-8")).digest()


def save_key_to_file(key_bytes: bytes, file_path: str) -> None:
    """Save raw private or public key bytes to a local file."""
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(key_bytes)


def load_key_from_file(file_path: str) -> bytes:
    """Load raw private or public key bytes from a local file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Keystore file not found at: {file_path}")
    with open(file_path, "rb") as f:
        return f.read()


def key_to_hex(key_bytes: bytes) -> str:
    """Convert raw key bytes to hexadecimal string."""
    return key_bytes.hex()


def hex_to_key(hex_str: str) -> bytes:
    """Convert hexadecimal string to raw key bytes."""
    return bytes.fromhex(hex_str.strip())
