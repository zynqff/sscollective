import os
from fastapi import FastAPI, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv
from supabase import create_client, Client
import logging

# Отключаем логирование лишних предупреждений passlib
logging.getLogger("passlib").setLevel(logging.ERROR)

# --- 0. ЗАГРУЗКА КОНФИГУРАЦИИ ---
load_dotenv()

# Ключи для Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Настройки безопасности
# ВАЖНО: Добавь SECRET_KEY в свой .env файл!
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-default-key-change-it") 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 неделя

# Настройки Админов
ADMIN_USERNAMES = os.getenv("ADMIN_USERNAMES", "").split(",")
ADMIN_PASSWORDS = os.getenv("ADMIN_PASSWORDS", "").split(",")
ADMINS_DICT = dict(zip(ADMIN_USERNAMES, ADMIN_PASSWORDS))

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Ошибка: SUPABASE_URL или SUPABASE_KEY не найдены в .env")

# --- 1. ИНИЦИАЛИЗАЦИЯ ---
app = FastAPI()
templates = Jinja2Templates(directory="templates")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- 2. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def get_db():
    return supabase

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload if payload.get("exp") > datetime.utcnow().timestamp() else None
    except jwt.PyJWTError:
        return None

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    payload = decode_access_token(token)
    if not payload:
        return None
    
    db = get_db()
    user = db.table('user').select('*').eq('username', payload.get("sub")).execute()
    return user.data[0] if user.data else None

# --- 3. МАРШРУТЫ (ROUTES) ---

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, user=Depends(get_current_user)):
    db = get_db()
    # Получаем все стихи
    poems_resp = db.table('poem').select('*').execute()
    poems = poems_resp.data if poems_resp.data else []
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "all_poems_json": poems
    })

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login_post(username: str = Form(...), password: str = Form(...)):
    db = get_db()
    
    # 1. Проверка на админа из .env
    if username in ADMINS_DICT and password == ADMINS_DICT[username]:
        # Проверяем, есть ли админ в базе, если нет - создаем
        user_in_db = db.table('user').select('*').eq('username', username).execute()
        if not user_in_db.data:
            db.table('user').insert({
                "username": username,
                "password_hash": get_password_hash(password),
                "is_admin": True
            }).execute()
        
        token = create_access_token(data={"sub": username})
        resp = RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
        resp.set_cookie(key="access_token", value=token, httponly=True)
        return resp

    # 2. Обычный пользователь
    user_resp = db.table('user').select('*').eq('username', username).execute()
    if not user_resp.data or not verify_password(password, user_resp.data[0]['password_hash']):
        return templates.TemplateResponse("login.html", {"request": {}, "error": "Неверный логин или пароль"})

    token = create_access_token(data={"sub": username})
    resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    resp.set_cookie(key="access_token", value=token, httponly=True)
    return resp

@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
async def register_post(username: str = Form(...), password: str = Form(...)):
    db = get_db()
    # Проверка существования
    existing = db.table('user').select('username').eq('username', username).execute()
    if existing.data:
        return templates.TemplateResponse("register.html", {"request": {}, "error": "Пользователь уже существует"})
    
    new_user = {
        "username": username,
        "password_hash": get_password_hash(password),
        "is_admin": False,
        "user_data": ""
    }
    db.table('user').insert(new_user).execute()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/")
    resp.delete_cookie("access_token")
    return resp

@app.get("/profile", response_class=HTMLResponse)
async def profile_get(request: Request, user=Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})

# --- 4. АДМИН-ПАНЕЛЬ ---

@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(request: Request, user=Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    
    db = get_db()
    poems = db.table('poem').select('*').execute()
    return templates.TemplateResponse("admin_panel.html", {
        "request": request, 
        "poems": poems.data
    })

@app.post("/admin/add_poem")
async def add_poem(
    title: str = Form(...), 
    author: str = Form(...), 
    content: str = Form(...),
    user=Depends(get_current_user)
):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    
    db = get_db()
    db.table('poem').insert({
        "title": title,
        "author": author,
        "poem_text": content
    }).execute()
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

# --- ЗАПУСК ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
    
