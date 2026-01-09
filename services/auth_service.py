import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from supabase import Client
from core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    @staticmethod
    def create_access_token(data: dict):
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    @staticmethod
    def get_password_hash(password):
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password, hashed_password):
        try:
            safe_password = plain_password[:72] if plain_password else ""
            return pwd_context.verify(safe_password, hashed_password)
        except Exception as e:
            print(f"Ошибка при проверке пароля: {e}")
            return False

    @staticmethod
    def is_virtual_admin(username: str) -> bool:
        return username in settings.ADMINS_DICT

    @staticmethod
    def check_virtual_admin(username: str, password: str) -> bool:
        return settings.ADMINS_DICT.get(username) == password

    @staticmethod
    def get_virtual_admin_data(username: str) -> Dict[str, Any]:
        return {
            'username': username,
            'is_admin': True,
            'read_poems_json': [],
            'pinned_poem_title': None,
            'show_all_tab': False,
            'user_data': ''
  }
