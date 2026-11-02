"""Tests unitarios de backend/services/auth.py (hashing y JWT), sin red ni DB."""

import time

import jwt
import pytest
from fastapi import HTTPException

from backend.services import auth


def test_hash_password_never_plaintext():
    hashed = auth.hash_password("miClaveSecreta123")
    assert hashed != "miClaveSecreta123"
    assert hashed.startswith("$2b$")  # prefijo estándar de bcrypt


def test_verify_password_correct_and_incorrect():
    hashed = auth.hash_password("correcta123")
    assert auth.verify_password("correcta123", hashed) is True
    assert auth.verify_password("incorrecta", hashed) is False


def test_verify_password_handles_garbage_hash_gracefully():
    # Un hash corrupto/no-bcrypt no debe tirar excepción, solo devolver False.
    assert auth.verify_password("cualquiera", "esto-no-es-un-hash-bcrypt") is False


def test_create_access_token_roundtrip():
    token_data = auth.create_access_token(username="admin", role="admin")
    assert token_data["token_type"] == "bearer"
    assert token_data["username"] == "admin"
    assert token_data["role"] == "admin"

    payload = jwt.decode(token_data["access_token"], auth.JWT_SECRET, algorithms=[auth.JWT_ALGORITHM])
    assert payload["sub"] == "admin"
    assert payload["role"] == "admin"


def test_decode_token_rejects_tampered_signature():
    token_data = auth.create_access_token(username="admin", role="admin")
    tampered = token_data["access_token"][:-3] + "xxx"
    with pytest.raises(HTTPException) as exc_info:
        auth._decode_token(tampered)
    assert exc_info.value.status_code == 401


def test_decode_token_rejects_expired_token():
    now = int(time.time())
    expired_payload = {"sub": "admin", "role": "admin", "iat": now - 1000, "exp": now - 500}
    expired_token = jwt.encode(expired_payload, auth.JWT_SECRET, algorithm=auth.JWT_ALGORITHM)
    with pytest.raises(HTTPException) as exc_info:
        auth._decode_token(expired_token)
    assert exc_info.value.status_code == 401
    assert "expirada" in exc_info.value.detail.lower()
