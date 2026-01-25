# -*- encoding: utf-8 -*-
"""
RijanAuth - Cryptographic Utilities
Password hashing, token generation, and JWT operations
"""

import os
import hashlib
import base64
import secrets
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

try:
    from cryptography.fernet import Fernet, InvalidToken
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False


# Encryption key from environment or generate a default one
_ENCRYPTION_KEY = os.getenv('RIJANAUTH_ENCRYPTION_KEY', '')

def _get_fernet():
    """Get Fernet instance for encryption/decryption"""
    if not FERNET_AVAILABLE:
        raise RuntimeError("cryptography library not installed")
    
    key = _ENCRYPTION_KEY
    if not key:
        # Use a default key derived from a fixed string (not secure for production!)
        # In production, RIJANAUTH_ENCRYPTION_KEY should be set
        key = base64.urlsafe_b64encode(hashlib.sha256(b'rijanauth-default-key').digest()).decode()
    
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_data(plaintext: str) -> str:
    """
    Encrypt sensitive data using Fernet symmetric encryption.
    
    Args:
        plaintext: The string to encrypt
        
    Returns:
        Base64-encoded encrypted string
    """
    if not plaintext:
        return plaintext
    
    try:
        f = _get_fernet()
        encrypted = f.encrypt(plaintext.encode('utf-8'))
        return encrypted.decode('utf-8')
    except Exception:
        # If encryption fails, return plaintext (for backward compatibility)
        return plaintext


def decrypt_data(ciphertext: str) -> str:
    """
    Decrypt data that was encrypted with encrypt_data.
    
    Args:
        ciphertext: The encrypted string
        
    Returns:
        Decrypted plaintext string
    """
    if not ciphertext:
        return ciphertext
    
    try:
        f = _get_fernet()
        decrypted = f.decrypt(ciphertext.encode('utf-8'))
        return decrypted.decode('utf-8')
    except Exception:
        # If decryption fails, assume it's not encrypted
        return ciphertext


def generate_secret(length: int = 32) -> str:
    """Generate a cryptographically secure random secret"""
    return secrets.token_urlsafe(length)


def generate_token(length: int = 32) -> str:
    """Generate a random token for authorization codes, refresh tokens, etc."""
    return secrets.token_hex(length)


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    Returns the hash as a string.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password, salt)
    return hashed.decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a bcrypt hash.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    
    try:
        return bcrypt.checkpw(password, hashed)
    except Exception:
        return False


def generate_pkce_code_verifier() -> str:
    """Generate a PKCE code verifier"""
    return secrets.token_urlsafe(32)


def generate_pkce_code_challenge(verifier: str, method: str = 'S256') -> str:
    """
    Generate a PKCE code challenge from a verifier.
    
    Args:
        verifier: The code verifier
        method: 'S256' (SHA-256) or 'plain'
    
    Returns:
        The code challenge
    """
    if method == 'plain':
        return verifier
    elif method == 'S256':
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    else:
        raise ValueError(f'Unknown code challenge method: {method}')


def verify_pkce_code_challenge(verifier: str, challenge: str, method: str = 'S256') -> bool:
    """
    Verify a PKCE code challenge against a verifier.
    """
    expected = generate_pkce_code_challenge(verifier, method)
    return secrets.compare_digest(expected, challenge)


# TOTP utilities for 2FA
def generate_totp_secret(length: int = 20) -> str:
    """Generate a TOTP secret key"""
    return base64.b32encode(secrets.token_bytes(length)).decode('utf-8').rstrip('=')


def get_totp_uri(secret: str, account_name: str, issuer: str = 'RijanAuth',
                 algorithm: str = 'SHA1', digits: int = 6, period: int = 30) -> str:
    """
    Generate a TOTP URI for QR code generation.
    
    Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm={algorithm}&digits={digits}&period={period}
    """
    from urllib.parse import quote
    
    label = f'{quote(issuer)}:{quote(account_name)}'
    params = [
        f'secret={secret}',
        f'issuer={quote(issuer)}',
        f'algorithm={algorithm}',
        f'digits={digits}',
        f'period={period}'
    ]
    return f'otpauth://totp/{label}?' + '&'.join(params)


def verify_totp(secret: str, code: str, digits: int = 6, period: int = 30,
                algorithm: str = 'SHA1', window: int = 1) -> bool:
    """
    Verify a TOTP code.
    
    Args:
        secret: The TOTP secret (base32 encoded)
        code: The code to verify
        digits: Number of digits in the code
        period: Time period in seconds
        algorithm: Hash algorithm (SHA1, SHA256, SHA512)
        window: Number of periods to check before/after current time
    
    Returns:
        True if the code is valid
    """
    import hmac
    import struct
    import time
    
    # Pad secret if needed
    secret = secret.upper()
    padding = 8 - (len(secret) % 8)
    if padding != 8:
        secret += '=' * padding
    
    try:
        key = base64.b32decode(secret)
    except Exception:
        return False
    
    # Get hash function
    hash_funcs = {
        'SHA1': hashlib.sha1,
        'SHA256': hashlib.sha256,
        'SHA512': hashlib.sha512,
    }
    hash_func = hash_funcs.get(algorithm.upper(), hashlib.sha1)
    
    current_time = int(time.time())
    
    # Check current time +/- window
    for offset in range(-window, window + 1):
        counter = (current_time // period) + offset
        counter_bytes = struct.pack('>Q', counter)
        
        # Calculate HMAC
        h = hmac.new(key, counter_bytes, hash_func)
        digest = h.digest()
        
        # Dynamic truncation
        offset_byte = digest[-1] & 0x0F
        truncated = struct.unpack('>I', digest[offset_byte:offset_byte + 4])[0]
        truncated &= 0x7FFFFFFF
        
        # Generate code
        generated = str(truncated % (10 ** digits)).zfill(digits)
        
        if secrets.compare_digest(generated, code.zfill(digits)):
            return True
    
    return False


# JWT utilities (basic implementation, will use proper library in production)
class JWTError(Exception):
    """JWT-related error"""
    pass


def base64url_encode(data: bytes) -> str:
    """Base64url encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def base64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration"""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def generate_jwt_id() -> str:
    """Generate a unique JWT ID (jti claim)"""
    return secrets.token_hex(16)


def create_jwt(payload: Dict[str, Any], secret: str, algorithm: str = 'HS256') -> str:
    """
    Create a JWT token.
    
    Args:
        payload: The JWT payload (claims)
        secret: The secret key for signing
        algorithm: The signing algorithm (HS256)
    
    Returns:
        The encoded JWT string
    """
    import json
    import hmac
    
    # Convert datetime objects to timestamps
    processed_payload = {}
    for key, value in payload.items():
        if isinstance(value, datetime):
            processed_payload[key] = int(value.timestamp())
        else:
            processed_payload[key] = value
    
    # Create header
    header = {
        'alg': algorithm,
        'typ': 'JWT'
    }
    
    # Encode header and payload
    header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_encoded = base64url_encode(json.dumps(processed_payload, separators=(',', ':')).encode('utf-8'))
    
    # Create signature
    message = f'{header_encoded}.{payload_encoded}'
    
    if algorithm == 'HS256':
        signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
    else:
        raise JWTError(f'Unsupported algorithm: {algorithm}')
    
    signature_encoded = base64url_encode(signature)
    
    return f'{header_encoded}.{payload_encoded}.{signature_encoded}'


def decode_jwt(token: str, secret: str, algorithms: list = None) -> Dict[str, Any]:
    """
    Decode and verify a JWT token.
    
    Args:
        token: The JWT token string
        secret: The secret key for verification
        algorithms: List of allowed algorithms (default: ['HS256'])
    
    Returns:
        The decoded payload
    
    Raises:
        JWTError: If token is invalid or expired
    """
    import json
    import hmac
    
    if algorithms is None:
        algorithms = ['HS256']
    
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise JWTError('Invalid token format')
        
        header_encoded, payload_encoded, signature_encoded = parts
        
        # Decode header
        header = json.loads(base64url_decode(header_encoded))
        algorithm = header.get('alg')
        
        if algorithm not in algorithms:
            raise JWTError(f'Algorithm {algorithm} not allowed')
        
        # Verify signature
        message = f'{header_encoded}.{payload_encoded}'
        
        if algorithm == 'HS256':
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                message.encode('utf-8'),
                hashlib.sha256
            ).digest()
        else:
            raise JWTError(f'Unsupported algorithm: {algorithm}')
        
        actual_signature = base64url_decode(signature_encoded)
        
        if not hmac.compare_digest(expected_signature, actual_signature):
            raise JWTError('Invalid signature')
        
        # Decode payload
        payload = json.loads(base64url_decode(payload_encoded))
        
        # Check expiration
        if 'exp' in payload:
            exp = payload['exp']
            if isinstance(exp, (int, float)) and datetime.utcnow().timestamp() > exp:
                raise JWTError('Token expired')
        
        return payload
        
    except JWTError:
        raise
    except Exception as e:
        raise JWTError(f'Failed to decode token: {str(e)}')
