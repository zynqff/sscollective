import os
from fastapi import FastAPI, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
from typing import Optional, List
import json
from dotenv import load_dotenv
from supabase import create_client, Client
import logging
# Отключаем логирование ошибок внутри passlib, чтобы они не засоряли консоль
logging.getLogger("passlib").setLevel(logging.ERROR)

# --- 0. ЗАГРУЗКА .env ---
load_dotenv()

# Загружаем списки админов из .env
ADMIN_USERNAMES = os.getenv("ADMIN_USERNAMES", "").split(",")
ADMIN_PASSWORDS = os.getenv("ADMIN_PASSWORDS", "").split(",")
ADMINS_DICT = dict(zip(ADMIN_USERNAMES, ADMIN_PASSWORDS))

# --- 1. КОНФИГУРАЦИЯ ПРИЛОЖЕНИЯ ---
app = FastAPI()
templates = Jinja2Templates(directory="templates")

# --- 2. НАСТРОЙКА КЛИЕНТА SUPABASE ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

# Проверка наличия переменных окружения
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Supabase URL and Key must be set in the .env file")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Зависимость для получения клиента Supabase
def get_db() -> Client:
    """Возвращает экземпляр клиента Supabase."""
    return supabase

# --- 3. МОДЕЛИ ДАННЫХ Pydantic (SQLAlchemy убраны) ---
# Модели SQLAlchemy заменены на словари, получаемые от Supabase.
# Pydantic модели остаются для валидации входящих данных.

class UserCreate(BaseModel):
    username: str
    password: str

class PoemCreate(BaseModel):
    title: str
    author: str
    text: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    
class ToggleModel(BaseModel):
    title: str
    
# --- Вспомогательные функции для работы с данными пользователя ---

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    try:
        # Обрезаем пароль до 72 символов, чтобы bcrypt не выдавал ошибку
        safe_password = plain_password[:72] if plain_password else ""
        return pwd_context.verify(safe_password, hashed_password)
    except Exception as e:
        print(f"Ошибка при проверке пароля: {e}")
        return False

def set_password(password):
    return get_password_hash(password)

def check_password(password, password_hash):
    return verify_password(password, password_hash)

def get_read_poems_titles(user: dict) -> List[str]:
    """Возвращает список заголовков прочитанных стихов из данных пользователя."""
    return user.get('read_poems_json', [])

def is_poem_read(user: dict, title: str) -> bool:
    """Проверяет, прочитан ли стих."""
    return title in get_read_poems_titles(user)

def toggle_poem_read_status(user: dict, title: str) -> str:
    """Переключает статус прочтения стиха. Возвращает 'marked' или 'unmarked'."""
    current_reads = get_read_poems_titles(user)
    
    if title in current_reads:
        current_reads.remove(title)
        action = 'unmarked'
    else:
        current_reads.append(title)
        action = 'marked'
        
    user['read_poems_json'] = current_reads
    return action

def toggle_pinned_poem(user: dict, title: str) -> str:
    """Переключает статус изучаемого стиха (закреплен/откреплен)."""
    if user.get('pinned_poem_title') == title:
        user['pinned_poem_title'] = None
        return 'unpinned'
    else:
        user['pinned_poem_title'] = title
        return 'pinned'

# --- 4. НАСТРОЙКА АУТЕНТИФИКАЦИИ (JWT) ---
SECRET_KEY = "sUper_sEcrEt_kEy_fOr_pRojeCt_2024_fAstApi"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 1 day

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db: Client, username: str) -> Optional[dict]:
    """Получает пользователя из Supabase по имени."""
    try:
        response = db.table('user').select("*").eq('username', username).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

def get_current_user(request: Request, db: Client = Depends(get_db)) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            detail="Not authenticated",
            headers={"Location": "/login"},
        )
    try:
        token = token.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        user = get_user(db, username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
        
    except (jwt.PyJWTError, IndexError):
        # Если токен невалиден, перенаправляем на логин
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie("access_token")
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/login"},
            detail="Could not validate credentials"
        ) from None


def get_current_user_optional(request: Request, db: Client = Depends(get_db)) -> Optional[dict]:
    try:
        return get_current_user(request, db)
    except HTTPException:
        return None

# --- 5. МАРШРУТЫ (ЭНДПОИНТЫ) ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, db: Client = Depends(get_db), current_user: Optional[dict] = Depends(get_current_user_optional)):
    poems_response = db.table('poem').select("*").execute()
    poems = poems_response.data or []

    for poem in poems:
        poem['text'] = poem.get('text', '').replace('\\n', '\n')
        poem['line_count'] = len(poem.get('text', '').split('\n'))

    read_poems = []
    if current_user:
        read_poems_json = current_user.get('read_poems_json')
        if isinstance(read_poems_json, str):
            try:
                read_poems = json.loads(read_poems_json)
            except json.JSONDecodeError:
                read_poems = []
        elif isinstance(read_poems_json, list):
            read_poems = read_poems_json

    context = {
        "request": request,
        "poems": poems,
        "read_poems": read_poems,
        "pinned_title": current_user.get('pinned_poem_title') if current_user else None,
        "is_admin": current_user.get('is_admin', False) if current_user else False,
        "show_all_tab": current_user.get('show_all_tab', False) if current_user else False,
        "current_user": current_user,
    }
    return templates.TemplateResponse("index.html", context)


@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request, current_user: Optional[dict] = Depends(get_current_user_optional)):
    if current_user:
        return RedirectResponse(url="/profile", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    db: Client = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...)
):
    if len(password) < 4:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пароль должен быть не менее 4 символов."
        })

    if get_user(db, username):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Пользователь с таким именем уже существует!"
        })

    hashed_password = get_password_hash(password)
    
    try:
        db.table('user').insert({
            "username": username,
            "password_hash": hashed_password
        }).execute()
    except Exception as e:
        return templates.TemplateResponse("register.html", {
            "request": request, "error": f"Ошибка регистрации: {e}"
        })

    return RedirectResponse(url="/login?msg=reg_success", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, current_user: Optional[dict] = Depends(get_current_user_optional)):
    if current_user:
        return RedirectResponse(url="/profile", status_code=status.HTTP_302_FOUND)
    
    context = {"request": request}
    if request.query_params.get("msg") == "reg_success":
        context["success"] = "Регистрация прошла успешно! Вы можете войти."
        
    return templates.TemplateResponse("login.html", context)


@app.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Client = Depends(get_db)
):
    # 1. Проверка "виртуальных" админов из .env
    if username in ADMINS_DICT:
        if password == ADMINS_DICT[username]:
            access_token = create_access_token(data={"sub": username, "is_admin": True})
            # Перенаправляем на главную или в админку
            resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
            resp.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
            return resp
        else:
            return templates.TemplateResponse("login.html", {"request": {}, "error": "Неверный пароль администратора"})

    # 2. Проверка обычных пользователей в таблице 'user'
    try:
        user_res = db.table('user').select("*").eq("username", username).execute()
        if user_res.data:
            user = user_res.data[0]
            if verify_password(password, user['password_hash']):
                access_token = create_access_token(data={"sub": username, "is_admin": user.get('is_admin', False)})
                resp = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
                resp.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
                return resp
    except Exception as e:
        print(f"Ошибка входа: {e}")

    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверное имя пользователя или пароль"})

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    return response


@app.get("/profile", response_class=HTMLResponse)
async def profile_get(request: Request, current_user: dict = Depends(get_current_user)):
    return templates.TemplateResponse("profile.html", {"request": request, "current_user": current_user, "user_data": current_user.get('user_data', ''), "show_all_tab": current_user.get('show_all_tab', False)})

@app.post("/profile", response_class=HTMLResponse)
async def profile_post(
    request: Request,
    db: Client = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    new_password: Optional[str] = Form(None),
    user_data: Optional[str] = Form(None),
    show_all_tab: Optional[str] = Form(None)
):
    update_data = {}
    
    if new_password:
        if len(new_password) < 4:
            return templates.TemplateResponse("profile.html", {
                "request": request, "current_user": current_user, "user_data": current_user.get('user_data'),
                "show_all_tab": current_user.get('show_all_tab'), "error": "Новый пароль должен быть не менее 4 символов."
            })
        update_data['password_hash'] = set_password(new_password)

    if user_data is not None:
        update_data['user_data'] = user_data
    
    update_data['show_all_tab'] = show_all_tab == 'on'

    if update_data:
        try:
            response = db.table('user').update(update_data).eq('username', current_user['username']).execute()
            # Обновляем данные пользователя для отображения
            current_user.update(update_data)

        except Exception as e:
            return templates.TemplateResponse("profile.html", {
                "request": request, "current_user": current_user, "error": f"Ошибка обновления: {e}"
            })

    return templates.TemplateResponse("profile.html", {
        "request": request, "current_user": current_user, "user_data": current_user.get('user_data'),
        "show_all_tab": current_user.get('show_all_tab'), "success": "Настройки профиля обновлены!"
    })


@app.post("/toggle_read")
async def toggle_read(
    toggle_data: ToggleModel,
    db: Client = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    poem_resp = db.table('poem').select('title').eq('title', toggle_data.title).execute()
    if not poem_resp.data:
        raise HTTPException(status_code=404, detail="Стих не найден")

    try:
        # Get current read list
        read_json = current_user.get('read_poems_json')
        if isinstance(read_json, str):
            read_list = json.loads(read_json)
        elif isinstance(read_json, list):
            read_list = read_json
        else:
            read_list = []

        # Toggle status
        if toggle_data.title in read_list:
            read_list.remove(toggle_data.title)
            action = "unmarked"
        else:
            read_list.append(toggle_data.title)
            action = "marked"

        # Save back to Supabase
        db.table('user').update({"read_poems_json": read_list}).eq("username", current_user['username']).execute()

        return {"success": True, "action": action}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при обновлении БД: {str(e)}")


@app.post("/toggle_pin")
async def toggle_pin(
    toggle_data: ToggleModel,
    db: Client = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    poem_resp = db.table('poem').select('title').eq('title', toggle_data.title).execute()
    if not poem_resp.data:
        raise HTTPException(status_code=404, detail="Стих не найден")

    try:
        action = toggle_pinned_poem(current_user, toggle_data.title)
        
        db.table('user').update({
            'pinned_poem_title': current_user['pinned_poem_title']
        }).eq('username', current_user['username']).execute()
        
        return {"success": True, "action": action, "pinned_title": current_user['pinned_poem_title']}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при обновлении БД: {str(e)}")


# --- АДМИН-МАРШРУТЫ ---

def get_admin_user(current_user: dict = Depends(get_current_user)):
    if not current_user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Доступ запрещен. Требуются права администратора.")
    return current_user

@app.get("/admin_panel", response_class=HTMLResponse)
async def admin_panel(request: Request, admin: dict = Depends(get_admin_user)):
    return templates.TemplateResponse("admin_panel.html", {"request": request, "current_user": admin})

@app.get("/api/poems")
async def get_all_poems_api(db: Client = Depends(get_db), admin: dict = Depends(get_admin_user)):
    poems_resp = db.table('poem').select("*").execute()
    poems_data = poems_resp.data or []
    
    for p in poems_data:
        p['text'] = p.get('text', '').replace('\\n', '\n')
        p['line_count'] = len(p.get('text', '').split('\n'))
        
    return {"success": True, "poems": poems_data}

@app.post("/add_poem")
async def add_poem_post(
    poem_in: PoemCreate,
    db: Client = Depends(get_db),
    admin: dict = Depends(get_admin_user)
):
    if not all([poem_in.title, poem_in.author, poem_in.text]):
        raise HTTPException(status_code=400, detail="Все поля должны быть заполнены.")

    if db.table('poem').select('title').eq('title', poem_in.title).execute().data:
        raise HTTPException(status_code=409, detail=f'Стих с названием "{poem_in.title}" уже существует.')

    try:
        new_poem_data = poem_in.dict()
        response = db.table('poem').insert(new_poem_data).execute()
        
        if not response.data:
             raise HTTPException(status_code=500, detail="Не удалось добавить стих.")

        new_poem = response.data[0]
        new_poem['text'] = new_poem.get('text', '').replace('\\n', '\n')
        new_poem['line_count'] = len(new_poem.get('text', '').split('\n'))

        return {"success": True, "message": f'Стих "{new_poem["title"]}" успешно добавлен!', "poem": new_poem}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка БД: {str(e)}")

@app.post("/edit_poem/{original_title}")
async def edit_poem_post(
    original_title: str,
    poem_in: PoemCreate,
    db: Client = Depends(get_db),
    admin: dict = Depends(get_admin_user)
):
    poem_to_edit = db.table('poem').select('title').eq('title', original_title).execute()
    if not poem_to_edit.data:
        raise HTTPException(status_code=404, detail="Стих для редактирования не найден.")
        
    update_data = poem_in.dict()

    if not all(update_data.values()):
        raise HTTPException(status_code=400, detail="Все поля должны быть заполнены.")
            
    try:
        if update_data['title'] != original_title:
            # Проверяем, не занято ли новое имя
            if db.table('poem').select('title').eq('title', update_data['title']).execute().data:
                raise HTTPException(status_code=409, detail=f'Стих с новым названием "{update_data["title"]}" уже существует.')
        
        response = db.table('poem').update(update_data).eq('title', original_title).execute()
        
        if not response.data:
             raise HTTPException(status_code=500, detail="Не удалось обновить стих.")
        
        updated_poem = response.data[0]
        updated_poem['text'] = updated_poem.get('text', '').replace('\\n', '\n')
        updated_poem['line_count'] = len(updated_poem.get('text', '').split('\n'))
        
        return {"success": True, "message": f'Стих "{updated_poem["title"]}" успешно обновлен!', "poem": updated_poem}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка БД: {str(e)}")

@app.post("/delete_poem/{title}")
async def delete_poem(title: str, db: Client = Depends(get_db), admin: dict = Depends(get_admin_user)):
    poem_to_delete = db.table('poem').select('title').eq('title', title).execute()
    if not poem_to_delete.data:
        raise HTTPException(status_code=404, detail="Стих не найден.")
        
    try:
        db.table('poem').delete().eq('title', title).execute()
        return {"success": True, "message": f"Стих '{title}' успешно удален."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при удалении: {str(e)}")


# --- 6. ИНИЦИАЛИЗАЦИЯ ДАННЫХ (для Supabase) ---
def initialize_db_data():
    """
    Проверяет наличие админа и создает его, если он отсутствует.
    Не трогает таблицу со стихами.
    """
    db = get_db()
    
    try:
        if not get_user(db, 'admin'):
            ADMIN_PASSWORD = 'zynqochka'
            admin_user_data = {
                'username': 'admin', 
                'password_hash': get_password_hash(ADMIN_PASSWORD),
                'is_admin': True
            }
            db.table('user').insert(admin_user_data).execute()
            print("Администратор 'admin' создан в Supabase.")
    except Exception as e:
        print(f"Ошибка при создании админа: {e}")


if __name__ == "__main__":
    print("Инициализация данных в Supabase...")
    initialize_db_data()
    print("Запуск FastAPI приложения...")
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
else:
    # Этот блок выполняется, когда gunicorn/uvicorn запускают приложение
    initialize_db_data()
