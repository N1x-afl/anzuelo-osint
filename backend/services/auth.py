"""
Autenticación real para Anzuelo (reemplaza el login de fachada frontend-only).

- Contraseñas hasheadas con bcrypt (nunca en texto plano, ni siquiera las demo).
- Sesión vía JWT firmado (HS256), enviado como `Authorization: Bearer <token>`.
- 3 roles: admin, analista, viewer. "admin" es el único que puede vaciar el
  historial (least privilege). El resto de los endpoints de análisis/export
  requieren solo estar autenticado, sin distinción de rol.

ANZUELO_JWT_SECRET (.env): si no está configurada, se genera una aleatoria al
arrancar el proceso — funciona, pero invalida todas las sesiones activas cada
vez que se reinicia el backend. Para un despliegue persistente, fijá un valor
propio en .env.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.services import db

JWT_SECRET = os.getenv("ANZUELO_JWT_SECRET", "").strip() or secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("ANZUELO_JWT_EXPIRE_MINUTES", "480").strip() or 480)  # 8hs por defecto

_bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(username: str, role: str) -> dict:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRE_MINUTES * 60,
        "username": username,
        "role": role,
    }


def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión expirada. Volvé a iniciar sesión.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido.")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> dict:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado. Iniciá sesión para usar esta función.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = _decode_token(credentials.credentials)
    username = payload.get("sub")
    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado.")
    return {"username": user["username"], "role": user["role"]}


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta acción requiere rol de Administrador.",
        )
    return current_user
