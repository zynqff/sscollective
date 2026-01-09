import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

# Загружаем .env
load_dotenv()

# Импортируем роутеры
from routers import auth, users, poems, admin
from core.database import get_db, supabase

app = FastAPI(title="Сборник Стихов")

# Настройка статических файлов и шаблонов
# app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Подключаем роутеры
app.include_router(auth.router, tags=["auth"])
app.include_router(users.router, tags=["users"])
app.include_router(poems.router, tags=["poems"])
app.include_router(admin.router, tags=["admin"])

@app.get("/")
async def root():
    return {"message": "Сборник Стихов API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
