from datetime import datetime, timedelta
from typing import Optional
import os

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import User
from backend.config import get_settings


settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str, db: Optional[Session] = None):
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return user
    finally:
        if close_db:
            db.close()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed"
        )


def create_default_admin():
    # Admin creation is an explicit bootstrap operation, disabled by default.
    if os.getenv("CREATE_DEFAULT_ADMIN", "false").strip().lower() != "true":
        return

    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        if user:
            return

        admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD")
        if not admin_password:
            raise RuntimeError(
                "CREATE_DEFAULT_ADMIN=true requires DEFAULT_ADMIN_PASSWORD to be set"
            )

        db.add(User(username="admin", hashed_password=get_password_hash(admin_password)))
        db.commit()
    finally:
        db.close()
