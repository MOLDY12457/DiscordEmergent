from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict
import os
import logging
import uuid
import hashlib
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from pathlib import Path
import jwt
import json

# Charger .env
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configuration CORS à partir de variable d’environnement
origins_env = os.environ.get("CORS_ORIGINS", "")
if origins_env:
    origins = [o.strip() for o in origins_env.split(",")]
else:
    origins = ["*"]  # fallback (utile en dev, mais attention en prod)

app = FastAPI(title="ConvoTalk API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connexion MongoDB
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT config
JWT_SECRET = os.environ.get('JWT_SECRET', 'votre_secret_key_tres_securise')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7  # 7 jours

api_router = APIRouter(prefix="/api")

# Gestion WebSocket
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, str] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        connection_id = str(uuid.uuid4())
        self.active_connections[connection_id] = websocket
        self.user_connections[user_id] = connection_id
        return connection_id

    def disconnect(self, connection_id: str, user_id: str):
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        if user_id in self.user_connections:
            del self.user_connections[user_id]

    async def send_personal_message(self, message: str, user_id: str):
        if user_id in self.user_connections:
            conn_id = self.user_connections[user_id]
            if conn_id in self.active_connections:
                await self.active_connections[conn_id].send_text(message)

    async def broadcast(self, message: str):
        for websocket in self.active_connections.values():
            await websocket.send_text(message)

manager = ConnectionManager()

# Modèles Pydantic
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    avatar_url: Optional[str] = None
    is_online: bool = False
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Message(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    content: str
    sender_id: str
    sender_username: str
    sender_avatar: Optional[str] = None
    channel_id: str = "general"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message_type: str = "text"

class Channel(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    is_private: bool = False
    members: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SessionData(BaseModel):
    user_id: str
    email: str
    username: str
    session_token: str
    expires_at: datetime

# Fonctions auxiliaires
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed_password: str) -> bool:
    return hash_password(password) == hashed_password

def create_jwt_token(user_id: str, email: str, username: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if 'exp' in payload:
            payload['exp'] = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("session_token")
    if not token:
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ")[1]
    if not token:
        return None
    payload = verify_jwt_token(token)
    if not payload:
        return None
    session = await db.sessions.find_one({"session_token": token})
    if not session:
        return None
    expires_at = session["expires_at"]
    if hasattr(expires_at, 'replace') and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return None
    return payload

# Routes API (auth, chat, etc.) – tu peux copier celles que tu avais avant
@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    existing_user = await db.users.find_one({
        "$or": [{"email": user_data.email}, {"username": user_data.username}]
    })
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Email ou nom d'utilisateur déjà utilisé")
    user = User(username=user_data.username, email=user_data.email)
    user_dict = user.model_dump()
    user_dict["password"] = hash_password(user_data.password)
    await db.users.insert_one(user_dict)
    token = create_jwt_token(user.id, user.email, user.username)
    session_data = SessionData(
        user_id=user.id,
        email=user.email,
        username=user.username,
        session_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    )
    await db.sessions.insert_one(session_data.model_dump())
    return {
        "message": "Utilisateur créé avec succès",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "avatar_url": user.avatar_url
        },
        "token": token
    }

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Email ou mot de passe incorrect")
    token = create_jwt_token(user["id"], user["email"], user["username"])
    session_data = SessionData(
        user_id=user["id"],
        email=user["email"],
        username=user["username"],
        session_token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    )
    await db.sessions.insert_one(session_data.model_dump())
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"is_online": True, "last_seen": datetime.now(timezone.utc)}}
    )
    return {
        "message": "Connexion réussie",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar_url": user.get("avatar_url")
        },
        "token": token
    }

# ... tu remets le reste de tes routes, websocket, startup, etc.

# Finaliser
app.include_router(api_router)
