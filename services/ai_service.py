import secrets
import datetime
from typing import Optional, List, Dict, Any
from supabase import Client
import google.generativeai as genai
from core.config import settings

# Конфигурируем Gemini API
try:
    # Исправлено на GOOGLE_API_KEY
    genai.configure(api_key=settings.GOOGLE_API_KEY)
except Exception as e:
    print(f"Ошибка при конфигурации Gemini API: {e}")

class AIService:
    @staticmethod
    def generate_api_key(db: Client, generated_by: str, expires_at: Optional[datetime.datetime] = None, daily_limit: Optional[int] = None) -> str:
        key = secrets.token_urlsafe(32)
        new_key_data = {
            "key": key,
            "generated_by": generated_by,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "daily_limit": daily_limit,
            "is_active": True,
            "usage_today": 0,
            "last_usage_date": None
        }
        try:
            db.table('ai_keys').insert(new_key_data).execute()
            return key
        except Exception as e:
            print(f"Ошибка при создании ключа в БД: {e}")
            return None

    @staticmethod
    def validate_key(db: Client, key: str) -> bool:
        try:
            response = db.table('ai_keys').select("*").eq('key', key).single().execute()
            key_data = response.data
        except Exception:
            key_data = None
            
        if not key_data or not key_data["is_active"]:
            return False

        if key_data["expires_at"] and datetime.datetime.fromisoformat(key_data["expires_at"]) < datetime.datetime.utcnow():
            return False

        today = datetime.date.today()
        last_usage = datetime.datetime.fromisoformat(key_data["last_usage_date"]).date() if key_data.get("last_usage_date") else None
        
        usage_today = key_data["usage_today"]
        if last_usage != today:
            usage_today = 0

        if key_data["daily_limit"] is not None and usage_today >= key_data["daily_limit"]:
            return False
        
        # Обновляем использование
        try:
            db.table('ai_keys').update({
                "usage_today": usage_today + 1,
                "last_usage_date": today.isoformat()
            }).eq('key', key).execute()
        except Exception as e:
            print(f"Ошибка при обновлении использования ключа: {e}")
            # Не блокируем доступ, если не удалось обновить, но логируем
        
        return True

    @staticmethod
    def get_keys_for_admin(db: Client, admin_username: str) -> List[Dict[str, Any]]:
        try:
            response = db.table('ai_keys').select("*").eq('generated_by', admin_username).execute()
            return response.data
        except Exception as e:
            print(f"Ошибка при получении ключей для админа: {e}")
            return []

    @staticmethod
    def disable_key(db: Client, key: str) -> bool:
        try:
            db.table('ai_keys').update({"is_active": False}).eq('key', key).execute()
            return True
        except Exception as e:
            print(f"Ошибка при деактивации ключа: {e}")
            return False

    @staticmethod
    def save_chat_message(db: Client, username: str, role: str, content: str):
        """Сохраняет сообщение в историю чата."""
        try:
            db.table('ai_chat_history').insert({
                "username": username,
                "role": role,
                "content": content
            }).execute()
        except Exception as e:
            print(f"Ошибка при сохранении сообщения в чат: {e}")

    @staticmethod
    def get_chat_history(db: Client, username: str) -> List[Dict[str, Any]]:
        """Получает и форматирует историю чата для Gemini."""
        try:
            response = db.table('ai_chat_history').select("role, content").eq('username', username).order('created_at', desc=False).limit(20).execute()
            
            history = []
            for item in response.data:
                history.append({
                    "role": item['role'],
                    "parts": [item['content']]
                })
            return history
        except Exception as e:
            print(f"Ошибка при получении истории чата: {e}")
            return []
        
    @staticmethod
    def get_gemini_response(prompt: str, history: list) -> str:
        try:
            model = genai.GenerativeModel('gemini-3-flash-preview')
            chat = model.start_chat(history=history)
            response = chat.send_message(prompt)
            return response.text
        except Exception as e:
            print(f"Ошибка при вызове Gemini API: {e}")
            return "Извините, произошла ошибка при обращении к AI."
