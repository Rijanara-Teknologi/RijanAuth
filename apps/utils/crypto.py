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
