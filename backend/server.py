from fastapi import FastAPI, APIRouter, HTTPException, Query, BackgroundTasks, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import hmac
import hashlib
import httpx
import asyncio
import secrets
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from fastapi.responses import StreamingResponse
import io
import csv
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from jose import JWTError, jwt
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'hp-printos-dashboard-jwt-secret-2025')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Encryption setup - generate key from a secret passphrase
ENCRYPTION_SECRET = os.environ.get('ENCRYPTION_SECRET', 'hp-printos-dashboard-secret-key-2025')
def get_encryption_key():
    """Derive encryption key from secret passphrase"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'hp_printos_salt_v1',
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_SECRET.encode()))
    return Fernet(key)

cipher = get_encryption_key()

def encrypt_value(value: str) -> str:
    """Encrypt a string value"""
    if not value:
        return ""
    return cipher.encrypt(value.encode()).decode()

def decrypt_value(encrypted_value: str) -> str:
    """Decrypt an encrypted string value"""
    if not encrypted_value:
        return ""
    try:
        return cipher.decrypt(encrypted_value.encode()).decode()
    except Exception:
        return ""

# HP PrintOS API config (defaults, can be overridden by stored credentials)
HP_BASE_URL = os.environ.get('HP_PRINTOS_BASE_URL', 'https://printos.api.hp.com/printbeat')

# Cached credentials (loaded from DB on startup)
_cached_credentials = None

async def get_api_credentials():
    """Get API credentials from database or defaults"""
    global _cached_credentials
    
    if _cached_credentials is not None:
        return _cached_credentials
    
    # Try to load from database
    stored = await db.api_credentials.find_one({"_id": "hp_printos"})
    
    if stored:
        _cached_credentials = {
            "jobs_key": decrypt_value(stored.get("jobs_key_encrypted", "")),
            "jobs_secret": decrypt_value(stored.get("jobs_secret_encrypted", "")),
            "historic_key": decrypt_value(stored.get("historic_key_encrypted", "")),
            "historic_secret": decrypt_value(stored.get("historic_secret_encrypted", "")),
        }
    else:
        # Fallback to environment variables or empty
        _cached_credentials = {
            "jobs_key": os.environ.get('HP_JOBS_API_KEY', ''),
            "jobs_secret": os.environ.get('HP_JOBS_API_SECRET', ''),
            "historic_key": os.environ.get('HP_HISTORIC_API_KEY', ''),
            "historic_secret": os.environ.get('HP_HISTORIC_API_SECRET', ''),
        }
    
    return _cached_credentials

def clear_credentials_cache():
    """Clear cached credentials to force reload from DB"""
    global _cached_credentials
    _cached_credentials = None

# Device configuration (will be loaded from DB if available)
DEFAULT_DEVICES = {
    "47200413": {"name": "7K", "model": "HP Indigo 7K"},
    "47100144": {"name": "7900", "model": "HP Indigo 7900"},
    "47100122": {"name": "9129", "model": "HP Indigo 9129"}
}

DEVICES = DEFAULT_DEVICES.copy()

async def load_devices_from_db():
    """Load device configuration from database"""
    global DEVICES
    stored = await db.device_config.find_one({"_id": "devices"})
    if stored and stored.get("devices"):
        DEVICES = stored["devices"]
    else:
        DEVICES = DEFAULT_DEVICES.copy()

# Background sync state
sync_task = None
sync_running = False

# Cache settings for PrintVolume API
CACHE_TTL_HOURS = 24  # Cache data for 24 hours

# Create the main app
app = FastAPI(title="HP PrintOS Dashboard API")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ============ HP PrintOS API Helpers ============

def create_hmac_headers(method: str, path: str, key: str, secret: str) -> dict:
    """Create HMAC-SHA256 authentication headers for HP PrintOS API"""
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    string_to_sign = f"{method} {path}{timestamp}"
    signature = hmac.new(
        secret.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return {
        'content-type': 'application/json',
        'x-hp-hmac-authentication': f'{key}:{signature}',
        'x-hp-hmac-date': timestamp,
        'x-hp-hmac-algorithm': 'SHA256'
    }


async def fetch_hp_api(path: str, params: dict, use_historic_key: bool = False) -> dict:
    """Fetch data from HP PrintOS API using stored credentials"""
    creds = await get_api_credentials()
    
    if use_historic_key:
        key = creds.get("historic_key", "")
        secret = creds.get("historic_secret", "")
    else:
        key = creds.get("jobs_key", "")
        secret = creds.get("jobs_secret", "")
    
    if not key or not secret:
        raise HTTPException(status_code=400, detail="API credentials not configured. Please set up credentials in Settings.")
    
    headers = create_hmac_headers("GET", path, key, secret)
    url = f"{HP_BASE_URL}{path}"
    
    async with httpx.AsyncClient(timeout=30.0) as http_client:
        response = await http_client.get(url, params=params, headers=headers)
        
        if response.status_code == 429:
            raise HTTPException(status_code=429, detail="HP API rate limit exceeded. Please wait 30 seconds.")
        
        if response.status_code != 200:
            logger.error(f"HP API error: {response.status_code} - {response.text}")
            raise HTTPException(status_code=response.status_code, detail=f"HP API error: {response.text}")
        
        return response.json()


def categorize_click(job: dict) -> dict:
    """Categorize a job based on EPM/OneShot logic"""
    one_shot = job.get('oneShotImpressions', 0) > 0
    impressions_1 = job.get('impressions1Color', 0)
    impressions_2 = job.get('impressions2Colors', 0)
    impressions_n = job.get('impressionsNColors', 0)
    inks = job.get('inks', [])
    
    # Count unique colors
    color_count = len(inks)
    
    # Check for black ink
    has_black = any(ink.get('color', '').lower() == 'black' for ink in inks)
    
    # Determine category
    # First try the specific impression fields from API
    if impressions_1 > 0:
        category = '1 Color'
    elif impressions_2 > 0:
        category = '2 Colors'
    elif impressions_n > 0:
        if has_black:
            category = 'Multicolor'
        else:
            category = 'EPM'
    # If no specific impression data, categorize by ink count
    elif color_count > 0:
        if color_count == 1:
            category = '1 Color'
        elif color_count == 2:
            category = '2 Colors'
        elif has_black:
            category = 'Multicolor'
        else:
            category = 'EPM'
    else:
        category = 'Unknown'
    
    return {
        'is_oneshot': one_shot,
        'is_epm': category == 'EPM',
        'click_category': category
    }


# ============ Pydantic Models ============

class DeviceInfo(BaseModel):
    id: str
    name: str
    model: str
    status: str = "Unknown"
    speed: Optional[float] = None
    last_updated: Optional[str] = None

class JobSummary(BaseModel):
    marker: int
    press_id: str
    job_name: Optional[str] = None
    status: str
    submit_time: Optional[str] = None
    total_impressions: int = 0
    one_shot_impressions: int = 0
    is_oneshot: bool = False
    is_epm: bool = False
    click_category: str = "Unknown"
    inks: List[dict] = []
    substrates: List[dict] = []

class ClicksReport(BaseModel):
    total_impressions: int
    one_color: int
    two_colors: int
    epm: int
    multicolor: int
    oneshot_total: int
    multishot_total: int

class SyncStatus(BaseModel):
    status: str
    jobs_synced: int
    last_marker: int
    message: str


class YoYComparison(BaseModel):
    current_period: dict
    previous_period: dict
    change_percent: float
    change_absolute: int


class APICredentials(BaseModel):
    jobs_key: str = Field(..., description="API Key for Jobs endpoint")
    jobs_secret: str = Field(..., description="API Secret for Jobs endpoint")
    historic_key: str = Field(..., description="API Key for Historic endpoints")
    historic_secret: str = Field(..., description="API Secret for Historic endpoints")


class DeviceConfig(BaseModel):
    device_id: str = Field(..., description="HP PrintOS Device ID")
    name: str = Field(..., description="Display name for the device")
    model: str = Field(..., description="Device model name")


# ============ Auth Models ============

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str
    password: str


class PasswordResetRequest(BaseModel):
    email: EmailStr
    origin_url: Optional[str] = Field(default=None, description="Frontend origin URL for reset link")


class PasswordReset(BaseModel):
    token: str
    new_password: str = Field(..., min_length=6)


class SMTPConfig(BaseModel):
    host: str = Field(..., description="SMTP server hostname")
    port: int = Field(default=587, description="SMTP server port")
    username: str = Field(..., description="SMTP username/email")
    password: str = Field(..., description="SMTP password")
    from_email: str = Field(..., description="Sender email address")
    use_tls: bool = Field(default=True, description="Use TLS encryption")


# ============ Auth Helper Functions ============

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(hours=JWT_EXPIRATION_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return current user"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"username": username}, {"_id": 0, "password": 0})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user


async def get_optional_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user if authenticated, otherwise return None"""
    if not credentials:
        return None
    
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        
        user = await db.users.find_one({"username": username}, {"_id": 0, "password": 0})
        return user
    except JWTError:
        return None


async def get_smtp_config() -> Optional[dict]:
    """Get SMTP configuration from database"""
    stored = await db.smtp_config.find_one({"_id": "smtp"})
    if stored:
        return {
            "host": decrypt_value(stored.get("host_encrypted", "")),
            "port": stored.get("port", 587),
            "username": decrypt_value(stored.get("username_encrypted", "")),
            "password": decrypt_value(stored.get("password_encrypted", "")),
            "from_email": decrypt_value(stored.get("from_email_encrypted", "")),
            "use_tls": stored.get("use_tls", True)
        }
    return None


async def send_password_reset_email(email: str, reset_token: str, reset_url: Optional[str]):
    """Send password reset email via SMTP"""
    smtp_config = await get_smtp_config()
    
    if not smtp_config or not smtp_config.get("host"):
        logger.error("SMTP not configured, cannot send password reset email")
        raise HTTPException(status_code=500, detail="E-Mail-Server nicht konfiguriert")
    
    # Create email message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "HP PrintOS Dashboard - Passwort zurücksetzen"
    msg["From"] = smtp_config["from_email"]
    msg["To"] = email
    
    # Build URL section based on whether reset_url is available
    url_section_html = ""
    url_section_text = ""
    if reset_url:
        url_section_html = f"""
                <p>Oder klicken Sie auf den folgenden Link:</p>
                <p style="text-align: center;">
                    <a href="{reset_url}" class="button">Passwort zurücksetzen</a>
                </p>
        """
        url_section_text = f"\n\nOder besuchen Sie: {reset_url}"
    
    # HTML email content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #0f172a; color: #e2e8f0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; padding: 30px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .header h1 {{ color: #06b6d4; margin: 0; }}
            .content {{ line-height: 1.6; }}
            .button {{ display: inline-block; background-color: #06b6d4; color: #0f172a; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold; margin: 20px 0; }}
            .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #334155; color: #64748b; font-size: 12px; }}
            .code {{ background-color: #334155; padding: 10px 15px; border-radius: 4px; font-family: monospace; font-size: 18px; letter-spacing: 2px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>HP PrintOS Dashboard</h1>
            </div>
            <div class="content">
                <p>Hallo,</p>
                <p>Sie haben eine Anfrage zum Zurücksetzen Ihres Passworts gestellt.</p>
                <p>Ihr Reset-Code lautet:</p>
                <p style="text-align: center;">
                    <span class="code">{reset_token}</span>
                </p>
                {url_section_html}
                <p>Dieser Code ist <strong>1 Stunde</strong> gültig.</p>
                <p>Falls Sie diese Anfrage nicht gestellt haben, können Sie diese E-Mail ignorieren.</p>
            </div>
            <div class="footer">
                <p>Diese E-Mail wurde automatisch generiert. Bitte antworten Sie nicht auf diese Nachricht.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = f"""
    HP PrintOS Dashboard - Passwort zurücksetzen
    
    Hallo,
    
    Sie haben eine Anfrage zum Zurücksetzen Ihres Passworts gestellt.
    
    Ihr Reset-Code lautet: {reset_token}{url_section_text}
    
    Dieser Code ist 1 Stunde gültig.
    
    Falls Sie diese Anfrage nicht gestellt haben, können Sie diese E-Mail ignorieren.
    """
    
    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))
    
    try:
        if smtp_config["use_tls"]:
            await aiosmtplib.send(
                msg,
                hostname=smtp_config["host"],
                port=smtp_config["port"],
                username=smtp_config["username"],
                password=smtp_config["password"],
                start_tls=True
            )
        else:
            await aiosmtplib.send(
                msg,
                hostname=smtp_config["host"],
                port=smtp_config["port"],
                username=smtp_config["username"],
                password=smtp_config["password"]
            )
        logger.info(f"Password reset email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail=f"E-Mail konnte nicht gesendet werden: {str(e)}")


# ============ API Routes ============

# ============ Authentication Endpoints ============

@api_router.post("/auth/register")
async def register_user(user: UserCreate):
    """Register a new user"""
    # Check if this is the first user (will be admin)
    user_count = await db.users.count_documents({})
    
    # Check if username exists
    existing_user = await db.users.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Benutzername bereits vergeben")
    
    # Check if email exists
    existing_email = await db.users.find_one({"email": user.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="E-Mail bereits registriert")
    
    # Create user
    hashed_password = get_password_hash(user.password)
    new_user = {
        "username": user.username,
        "email": user.email,
        "password": hashed_password,
        "is_admin": user_count == 0,  # First user is admin
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(new_user)
    
    logger.info(f"New user registered: {user.username}")
    
    return {
        "status": "success",
        "message": "Benutzer erfolgreich registriert",
        "is_admin": new_user["is_admin"]
    }


@api_router.post("/auth/login")
async def login(user: UserLogin):
    """Login and get JWT token"""
    db_user = await db.users.find_one({"username": user.username})
    
    if not db_user:
        raise HTTPException(status_code=401, detail="Ungültige Anmeldedaten")
    
    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Ungültige Anmeldedaten")
    
    # Create access token
    access_token = create_access_token(data={"sub": user.username})
    
    logger.info(f"User logged in: {user.username}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": db_user["username"],
            "email": db_user["email"],
            "is_admin": db_user.get("is_admin", False)
        }
    }


@api_router.get("/auth/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return current_user


@api_router.get("/auth/check")
async def check_auth_status():
    """Check if any users exist (for initial setup)"""
    user_count = await db.users.count_documents({})
    return {
        "users_exist": user_count > 0,
        "requires_setup": user_count == 0
    }


@api_router.post("/auth/password-reset/request")
async def request_password_reset(request: PasswordResetRequest):
    """Request a password reset email"""
    user = await db.users.find_one({"email": request.email})
    
    # Always return success to prevent email enumeration
    if not user:
        return {"status": "success", "message": "Falls ein Konto mit dieser E-Mail existiert, wurde eine Reset-E-Mail gesendet"}
    
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    reset_code = ''.join(secrets.choice('0123456789') for _ in range(6))  # 6-digit code
    
    # Store reset token with expiration (1 hour)
    await db.password_resets.delete_many({"email": request.email})  # Remove old tokens
    await db.password_resets.insert_one({
        "email": request.email,
        "token": reset_token,
        "code": reset_code,
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    # Use origin_url from frontend request (dynamic), fallback to env vars
    frontend_url = request.origin_url
    if not frontend_url:
        frontend_url = os.environ.get('FRONTEND_URL', os.environ.get('REACT_APP_BACKEND_URL', ''))
    
    # Build reset URL - if no URL available, only send the code
    reset_url = f"{frontend_url}/reset-password?token={reset_token}" if frontend_url else None
    
    try:
        await send_password_reset_email(request.email, reset_code, reset_url)
    except HTTPException:
        # If email fails, still return success but log the error
        logger.error(f"Failed to send password reset email to {request.email}")
    
    return {"status": "success", "message": "Falls ein Konto mit dieser E-Mail existiert, wurde eine Reset-E-Mail gesendet"}


@api_router.post("/auth/password-reset/verify")
async def verify_reset_code(email: str = Query(...), code: str = Query(...)):
    """Verify password reset code"""
    reset_request = await db.password_resets.find_one({
        "email": email,
        "code": code
    })
    
    if not reset_request:
        raise HTTPException(status_code=400, detail="Ungültiger Reset-Code")
    
    # Check expiration
    expires_at = datetime.fromisoformat(reset_request["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        await db.password_resets.delete_one({"_id": reset_request["_id"]})
        raise HTTPException(status_code=400, detail="Reset-Code abgelaufen")
    
    return {"status": "valid", "token": reset_request["token"]}


@api_router.post("/auth/password-reset/complete")
async def complete_password_reset(reset: PasswordReset):
    """Complete password reset with new password"""
    reset_request = await db.password_resets.find_one({"token": reset.token})
    
    if not reset_request:
        raise HTTPException(status_code=400, detail="Ungültiger oder abgelaufener Reset-Token")
    
    # Check expiration
    expires_at = datetime.fromisoformat(reset_request["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        await db.password_resets.delete_one({"_id": reset_request["_id"]})
        raise HTTPException(status_code=400, detail="Reset-Token abgelaufen")
    
    # Update password
    hashed_password = get_password_hash(reset.new_password)
    await db.users.update_one(
        {"email": reset_request["email"]},
        {"$set": {"password": hashed_password}}
    )
    
    # Delete reset token
    await db.password_resets.delete_one({"_id": reset_request["_id"]})
    
    logger.info(f"Password reset completed for {reset_request['email']}")
    
    return {"status": "success", "message": "Passwort erfolgreich geändert"}


# ============ PrintVolume Cache Helpers ============

async def get_cached_printvolume(device_id: str, from_date: str, to_date: str, resolution: str) -> Optional[dict]:
    """Check cache for PrintVolume data"""
    cache_key = f"{device_id}_{from_date}_{to_date}_{resolution}"
    cached = await db.printvolume_cache.find_one(
        {"cache_key": cache_key},
        {"_id": 0}
    )
    
    if cached:
        # Check if cache is still valid
        cached_at = datetime.fromisoformat(cached["cached_at"].replace("Z", "+00:00"))
        age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
        
        if age_hours < CACHE_TTL_HOURS:
            logger.info(f"Cache HIT for PrintVolume: {cache_key}")
            return cached["data"]
        else:
            logger.info(f"Cache EXPIRED for PrintVolume: {cache_key}")
    
    return None


async def set_cached_printvolume(device_id: str, from_date: str, to_date: str, resolution: str, data: dict):
    """Store PrintVolume data in cache"""
    cache_key = f"{device_id}_{from_date}_{to_date}_{resolution}"
    
    await db.printvolume_cache.update_one(
        {"cache_key": cache_key},
        {
            "$set": {
                "cache_key": cache_key,
                "device_id": device_id,
                "from_date": from_date,
                "to_date": to_date,
                "resolution": resolution,
                "data": data,
                "cached_at": datetime.now(timezone.utc).isoformat()
            }
        },
        upsert=True
    )
    logger.info(f"Cache SET for PrintVolume: {cache_key}")


async def fetch_printvolume_with_cache(device_id: str, from_date: str, to_date: str, resolution: str) -> dict:
    """Fetch PrintVolume data with caching"""
    # Check cache first
    cached_data = await get_cached_printvolume(device_id, from_date, to_date, resolution)
    if cached_data is not None:
        return cached_data
    
    # Fetch from API
    path = '/externalApi/v1/Historic/PrintVolume'
    params = {
        'devices': device_id,
        'from': f'{from_date} 00:00:00' if from_date else '',
        'to': f'{to_date} 23:59:59' if to_date else '',
        'resolution': resolution,
        'unitSystem': 'Metric'
    }
    
    data = await fetch_hp_api(path, params, use_historic_key=True)
    
    # Store in cache
    await set_cached_printvolume(device_id, from_date, to_date, resolution, data)
    
    return data


@api_router.get("/")
async def root():
    return {"message": "HP PrintOS Dashboard API", "version": "1.0.0"}


# ============ Settings / Credentials Management ============

@api_router.get("/settings/credentials/status")
async def get_credentials_status():
    """Check if API credentials are configured (without exposing them)"""
    creds = await get_api_credentials()
    
    return {
        "configured": bool(creds.get("jobs_key") and creds.get("historic_key")),
        "jobs_api": {
            "configured": bool(creds.get("jobs_key") and creds.get("jobs_secret")),
            "key_preview": creds.get("jobs_key", "")[:8] + "..." if creds.get("jobs_key") else None
        },
        "historic_api": {
            "configured": bool(creds.get("historic_key") and creds.get("historic_secret")),
            "key_preview": creds.get("historic_key", "")[:8] + "..." if creds.get("historic_key") else None
        }
    }


@api_router.post("/settings/credentials")
async def save_credentials(credentials: APICredentials):
    """Save API credentials (encrypted)"""
    try:
        # Encrypt all values
        encrypted_data = {
            "_id": "hp_printos",
            "jobs_key_encrypted": encrypt_value(credentials.jobs_key),
            "jobs_secret_encrypted": encrypt_value(credentials.jobs_secret),
            "historic_key_encrypted": encrypt_value(credentials.historic_key),
            "historic_secret_encrypted": encrypt_value(credentials.historic_secret),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Upsert into database
        await db.api_credentials.replace_one(
            {"_id": "hp_printos"},
            encrypted_data,
            upsert=True
        )
        
        # Clear cache to force reload
        clear_credentials_cache()
        
        logger.info("API credentials saved successfully")
        
        return {"status": "success", "message": "Credentials saved successfully"}
    except Exception as e:
        logger.error(f"Error saving credentials: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save credentials: {str(e)}")


@api_router.post("/settings/credentials/test")
async def test_credentials(credentials: APICredentials):
    """Test API credentials by making a simple API call"""
    try:
        # Test Jobs API
        jobs_headers = create_hmac_headers("GET", "/externalApi/jobs", credentials.jobs_key, credentials.jobs_secret)
        
        async with httpx.AsyncClient(timeout=10.0) as http_client:
            # Test with minimal params
            jobs_response = await http_client.get(
                f"{HP_BASE_URL}/externalApi/jobs",
                params={"devices": list(DEVICES.keys())[0], "limit": 1},
                headers=jobs_headers
            )
            jobs_ok = jobs_response.status_code == 200
        
        # Test Historic API
        historic_headers = create_hmac_headers("GET", "/externalApi/v1/Historic/PrintVolume", credentials.historic_key, credentials.historic_secret)
        
        async with httpx.AsyncClient(timeout=10.0) as http_client:
            today = datetime.now().strftime("%Y-%m-%d")
            historic_response = await http_client.get(
                f"{HP_BASE_URL}/externalApi/v1/Historic/PrintVolume",
                params={
                    "devices": list(DEVICES.keys())[0],
                    "from": f"{today} 00:00:00",
                    "to": f"{today} 23:59:59",
                    "resolution": "Day",
                    "unitSystem": "Metric"
                },
                headers=historic_headers
            )
            historic_ok = historic_response.status_code == 200
        
        return {
            "jobs_api": {
                "success": jobs_ok,
                "status_code": jobs_response.status_code,
                "message": "OK" if jobs_ok else jobs_response.text[:200]
            },
            "historic_api": {
                "success": historic_ok,
                "status_code": historic_response.status_code,
                "message": "OK" if historic_ok else historic_response.text[:200]
            },
            "overall_success": jobs_ok and historic_ok
        }
    except Exception as e:
        logger.error(f"Error testing credentials: {e}")
        return {
            "jobs_api": {"success": False, "message": str(e)},
            "historic_api": {"success": False, "message": str(e)},
            "overall_success": False,
            "error": str(e)
        }


@api_router.delete("/settings/credentials")
async def delete_credentials():
    """Delete stored API credentials"""
    try:
        result = await db.api_credentials.delete_one({"_id": "hp_printos"})
        clear_credentials_cache()
        
        return {
            "status": "success",
            "deleted": result.deleted_count > 0
        }
    except Exception as e:
        logger.error(f"Error deleting credentials: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete credentials: {str(e)}")


# ============ Device Configuration ============

@api_router.get("/settings/devices")
async def get_device_config():
    """Get current device configuration"""
    return {
        "devices": DEVICES,
        "device_list": [
            {"id": k, "name": v["name"], "model": v["model"]}
            for k, v in DEVICES.items()
        ]
    }


@api_router.post("/settings/devices")
async def save_device_config(devices: List[DeviceConfig]):
    """Save device configuration"""
    try:
        device_dict = {}
        for device in devices:
            device_dict[device.device_id] = {
                "name": device.name,
                "model": device.model
            }
        
        await db.device_config.replace_one(
            {"_id": "devices"},
            {"_id": "devices", "devices": device_dict, "updated_at": datetime.now(timezone.utc).isoformat()},
            upsert=True
        )
        
        # Reload devices
        await load_devices_from_db()
        
        return {"status": "success", "devices": DEVICES}
    except Exception as e:
        logger.error(f"Error saving device config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save device config: {str(e)}")


@api_router.post("/settings/devices/add")
async def add_device(device: DeviceConfig):
    """Add a new device to configuration"""
    try:
        DEVICES[device.device_id] = {
            "name": device.name,
            "model": device.model
        }
        
        await db.device_config.replace_one(
            {"_id": "devices"},
            {"_id": "devices", "devices": DEVICES, "updated_at": datetime.now(timezone.utc).isoformat()},
            upsert=True
        )
        
        return {"status": "success", "devices": DEVICES}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add device: {str(e)}")


@api_router.delete("/settings/devices/{device_id}")
async def delete_device(device_id: str):
    """Remove a device from configuration"""
    try:
        if device_id in DEVICES:
            del DEVICES[device_id]
            
            await db.device_config.replace_one(
                {"_id": "devices"},
                {"_id": "devices", "devices": DEVICES, "updated_at": datetime.now(timezone.utc).isoformat()},
                upsert=True
            )
            
        return {"status": "success", "devices": DEVICES}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete device: {str(e)}")


# ============ SMTP Configuration ============

@api_router.get("/settings/smtp/status")
async def get_smtp_status():
    """Check if SMTP is configured (without exposing credentials)"""
    smtp = await get_smtp_config()
    
    if smtp and smtp.get("host"):
        return {
            "configured": True,
            "host": smtp["host"],
            "port": smtp["port"],
            "from_email": smtp["from_email"],
            "use_tls": smtp["use_tls"]
        }
    return {"configured": False}


@api_router.post("/settings/smtp")
async def save_smtp_config(config: SMTPConfig):
    """Save SMTP configuration (encrypted)"""
    try:
        encrypted_data = {
            "_id": "smtp",
            "host_encrypted": encrypt_value(config.host),
            "port": config.port,
            "username_encrypted": encrypt_value(config.username),
            "password_encrypted": encrypt_value(config.password),
            "from_email_encrypted": encrypt_value(config.from_email),
            "use_tls": config.use_tls,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        await db.smtp_config.replace_one(
            {"_id": "smtp"},
            encrypted_data,
            upsert=True
        )
        
        logger.info("SMTP configuration saved successfully")
        
        return {"status": "success", "message": "SMTP-Konfiguration gespeichert"}
    except Exception as e:
        logger.error(f"Error saving SMTP config: {e}")
        raise HTTPException(status_code=500, detail=f"Fehler beim Speichern: {str(e)}")


@api_router.post("/settings/smtp/test")
async def test_smtp_config(config: SMTPConfig):
    """Test SMTP configuration by sending a test email"""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "HP PrintOS Dashboard - SMTP Test"
        msg["From"] = config.from_email
        msg["To"] = config.from_email
        
        html_content = """
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #e2e8f0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; padding: 30px;">
                <h1 style="color: #06b6d4;">SMTP Test erfolgreich!</h1>
                <p>Die E-Mail-Konfiguration funktioniert korrekt.</p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText("SMTP Test erfolgreich!", "plain"))
        msg.attach(MIMEText(html_content, "html"))
        
        if config.use_tls:
            await aiosmtplib.send(
                msg,
                hostname=config.host,
                port=config.port,
                username=config.username,
                password=config.password,
                start_tls=True
            )
        else:
            await aiosmtplib.send(
                msg,
                hostname=config.host,
                port=config.port,
                username=config.username,
                password=config.password
            )
        
        return {"status": "success", "message": "Test-E-Mail erfolgreich gesendet"}
    except Exception as e:
        logger.error(f"SMTP test failed: {e}")
        return {"status": "error", "message": f"SMTP-Test fehlgeschlagen: {str(e)}"}


@api_router.delete("/settings/smtp")
async def delete_smtp_config():
    """Delete SMTP configuration"""
    try:
        result = await db.smtp_config.delete_one({"_id": "smtp"})
        return {"status": "success", "deleted": result.deleted_count > 0}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fehler beim Löschen: {str(e)}")


@api_router.get("/devices", response_model=List[DeviceInfo])
async def get_devices():
    """Get list of all devices with their basic info"""
    devices = []
    for device_id, info in DEVICES.items():
        devices.append(DeviceInfo(
            id=device_id,
            name=info["name"],
            model=info["model"],
            status="Ready"
        ))
    return devices


@api_router.get("/devices/{device_id}/realtime")
async def get_device_realtime(device_id: str):
    """Get real-time data for a specific device from HP PrintOS API"""
    if device_id != "all" and device_id not in DEVICES:
        raise HTTPException(status_code=404, detail="Device not found")
    
    try:
        # Fetch real-time data from HP API
        path = '/externalApi/v1/RealTimeData'
        devices_param = device_id if device_id != "all" else ",".join(DEVICES.keys())
        params = {
            'devices': devices_param,
            'resolution': 'Day',
            'unitSystem': 'Metric'
        }
        
        data = await fetch_hp_api(path, params, use_historic_key=True)
        
        # Parse the response to extract useful info
        result = {
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "devices": []
        }
        
        if data and "data" in data:
            for unit_data in data.get("data", {}).get("unitEvents", []):
                device_info = {
                    "unit_name": unit_data.get("unitName"),
                    "unit_id": unit_data.get("unitId"),
                    "status": "Unknown",
                    "speed": 0,
                    "impressions_today": 0,
                    "events": []
                }
                
                events = unit_data.get("events", [])
                if events:
                    latest = events[-1] if events else {}
                    device_info["impressions_today"] = latest.get("score", {}).get("value", 0)
                    device_info["events"] = events[-5:]  # Last 5 events
                
                result["devices"].append(device_info)
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching real-time data: {e}")
        return {
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
            "devices": []
        }


@api_router.get("/devices/{device_id}/status")
async def get_device_status(device_id: str):
    """Get real-time status for a specific device"""
    if device_id not in DEVICES:
        raise HTTPException(status_code=404, detail="Device not found")
    
    try:
        # Fetch real-time data from HP API
        path = '/externalApi/v1/RealTimeData'
        params = {
            'devices': device_id,
            'resolution': 'Day',
            'unitSystem': 'Metric'
        }
        data = await fetch_hp_api(path, params, use_historic_key=True)
        
        # Get today's impressions and sheets from database (from Jobs API)
        today = datetime.now().strftime("%Y-%m-%d")
        today_stats = await db.print_jobs.aggregate([
            {"$match": {
                "press_id": device_id,
                "submit_time": {"$gte": today, "$lte": today + "T23:59:59"}
            }},
            {"$group": {
                "_id": None,
                "total_impressions": {"$sum": "$total_impressions"},
                "total_sheets": {"$sum": {"$ifNull": ["$sheets", "$total_impressions"]}},
                "job_count": {"$sum": 1}
            }}
        ]).to_list(length=1)
        
        db_impressions = today_stats[0]["total_impressions"] if today_stats else 0
        db_sheets = today_stats[0]["total_sheets"] if today_stats else 0
        db_jobs = today_stats[0]["job_count"] if today_stats else 0
        
        return {
            "device_id": device_id,
            "device_name": DEVICES[device_id]["name"],
            "model": DEVICES[device_id]["model"],
            "data": data,
            "today_from_jobs": {
                "impressions": db_impressions,
                "sheets": db_sheets,
                "jobs": db_jobs
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching device status: {e}")
        # Return mock data on error
        return {
            "device_id": device_id,
            "device_name": DEVICES[device_id]["name"],
            "model": DEVICES[device_id]["model"],
            "status": "Ready",
            "speed": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }


@api_router.get("/devices/{device_id}/performance")
async def get_device_performance(
    device_id: str,
    from_date: str = Query(default=None),
    to_date: str = Query(default=None),
    resolution: str = Query(default="Day")
):
    """Get historic performance data for a device"""
    if device_id != "all" and device_id not in DEVICES:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Default dates: last 30 days
    if not to_date:
        to_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    if not from_date:
        from_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime('%Y-%m-%d')
    
    try:
        path = '/externalApi/v1/Historic/PrintVolume'
        devices_param = device_id if device_id != "all" else ",".join(DEVICES.keys())
        params = {
            'devices': devices_param,
            'from': f'{from_date} 00:00:00',
            'to': f'{to_date} 00:00:00',
            'resolution': resolution,
            'unitSystem': 'Metric'
        }
        
        data = await fetch_hp_api(path, params, use_historic_key=True)
        return {
            "device_id": device_id,
            "from_date": from_date,
            "to_date": to_date,
            "resolution": resolution,
            "data": data
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching performance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/jobs")
async def get_jobs(
    device_id: str = Query(default="all"),
    status: str = Query(default=None),
    is_oneshot: bool = Query(default=None),
    click_category: str = Query(default=None),
    search: str = Query(default=None),
    problem_jobs: bool = Query(default=False),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=100)
):
    """Get paginated list of jobs from MongoDB cache"""
    query = {}
    
    if device_id != "all":
        query["press_id"] = device_id
    
    if status:
        query["status"] = status
    
    if is_oneshot is not None:
        query["is_oneshot"] = is_oneshot
    
    if click_category:
        query["click_category"] = click_category
    
    if search:
        query["job_name"] = {"$regex": search, "$options": "i"}
    
    if problem_jobs:
        query["$or"] = [
            {"error_count": {"$gt": 3}},
            {"print_attempts": {"$gt": 5}}
        ]
    
    if from_date or to_date:
        query["submit_time"] = {}
        if from_date:
            query["submit_time"]["$gte"] = from_date
        if to_date:
            query["submit_time"]["$lte"] = to_date + "T23:59:59"
    
    skip = (page - 1) * limit
    
    cursor = db.print_jobs.find(query, {"_id": 0}).sort("submit_time", -1).skip(skip).limit(limit)
    jobs = await cursor.to_list(length=limit)
    
    total = await db.print_jobs.count_documents(query)
    
    return {
        "jobs": jobs,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit
    }


# ============ Import Endpoint ============

class JobImportRequest(BaseModel):
    jobs: List[Dict[str, Any]]


@api_router.post("/jobs/import")
async def import_jobs(request: JobImportRequest):
    """Import jobs from JSON file (Python script export)"""
    imported = 0
    updated = 0
    skipped = 0
    errors = 0
    
    for job in request.jobs:
        try:
            # Map fields from Python script format to our DB format
            marker = job.get('marker')
            if not marker:
                skipped += 1
                continue
            
            # Categorize the job
            categorization = categorize_click({
                'oneShotImpressions': job.get('oneShotImpressions', 0),
                'impressions1Color': job.get('impressions1Color', 0),
                'impressions2Colors': job.get('impressions2Colors', 0),
                'impressionsNColors': job.get('impressionsNColors', 0),
                'inks': job.get('inks', [])
            })
            
            job_doc = {
                "marker": marker,
                "press_id": job.get('pressSerialNumber'),
                "job_name": job.get('jobName'),
                "status": job.get('jobProgress', 'UNKNOWN'),
                "submit_time": job.get('jobSubmitTime'),
                "complete_time": job.get('jobCompleteTime'),
                "total_impressions": job.get('impressions', 0),
                "one_shot_impressions": job.get('oneShotImpressions', 0),
                "impressions_1_color": job.get('impressions1Color', 0),
                "impressions_2_colors": job.get('impressions2Colors', 0),
                "impressions_n_colors": job.get('impressionsNColors', 0),
                "epm_impressions": job.get('epmImpressions', 0),
                "inks": job.get('inks', []),
                "substrates": job.get('substrates', []),
                "width": job.get('width'),
                "height": job.get('height'),
                "duplex": job.get('duplex', False),
                "impressions_type": job.get('impressionsType'),
                "job_elapse_time": job.get('jobElapseTime'),
                **categorization
            }
            
            # Check if job exists
            existing = await db.print_jobs.find_one({"marker": marker})
            
            if existing:
                await db.print_jobs.update_one(
                    {"marker": marker},
                    {"$set": job_doc}
                )
                updated += 1
            else:
                await db.print_jobs.insert_one(job_doc)
                imported += 1
                
        except Exception as e:
            logger.error(f"Error importing job: {e}")
            errors += 1
    
    # Log import
    await db.import_log.insert_one({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_jobs": len(request.jobs),
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": errors
    })
    
    return {
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "total": len(request.jobs)
    }


@api_router.post("/jobs/recategorize")
async def recategorize_jobs():
    """Recategorize all existing jobs based on updated logic"""
    cursor = db.print_jobs.find({})
    jobs = await cursor.to_list(length=10000)
    
    updated = 0
    for job in jobs:
        # Build job dict for categorization using the inks field
        categorization = categorize_click({
            'oneShotImpressions': job.get('one_shot_impressions', 0),
            'impressions1Color': job.get('impressions_1_color', 0),
            'impressions2Colors': job.get('impressions_2_colors', 0),
            'impressionsNColors': job.get('impressions_n_colors', 0),
            'inks': job.get('inks', [])
        })
        
        await db.print_jobs.update_one(
            {"marker": job["marker"]},
            {"$set": categorization}
        )
        updated += 1
    
    return {"status": "success", "jobs_updated": updated}


@api_router.post("/jobs/sync")
async def sync_jobs(
    device_id: str = Query(default="47100122"),
    background_tasks: BackgroundTasks = None
):
    """Trigger job sync from HP PrintOS API"""
    if device_id not in DEVICES:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get last marker from DB
    last_job = await db.print_jobs.find_one(
        {"press_id": device_id},
        sort=[("marker", -1)],
        projection={"marker": 1, "_id": 0}
    )
    start_marker = last_job["marker"] if last_job else 0
    
    try:
        path = '/externalApi/jobs'
        params = {
            'devices': device_id,
            'startMarker': start_marker,
            'limit': 100,
            'sortOrder': 'ASC'
        }
        
        data = await fetch_hp_api(path, params, use_historic_key=False)
        attempts = data.get('attempts', [])
        
        if not attempts:
            return SyncStatus(
                status="complete",
                jobs_synced=0,
                last_marker=start_marker,
                message="No new jobs to sync"
            )
        
        # Process and insert jobs
        jobs_to_insert = []
        for job in attempts:
            categorization = categorize_click(job)
            job_doc = {
                "marker": job.get('marker'),
                "press_id": device_id,
                "job_name": job.get('jobName'),
                "status": job.get('jobProgress', 'UNKNOWN'),
                "submit_time": job.get('jobSubmitTime'),
                "total_impressions": job.get('impressions', 0),
                "one_shot_impressions": job.get('oneShotImpressions', 0),
                "impressions_1_color": job.get('impressions1Color', 0),
                "impressions_2_colors": job.get('impressions2Colors', 0),
                "impressions_n_colors": job.get('impressionsNColors', 0),
                "inks": job.get('inks', []),
                "substrates": job.get('substrates', []),
                "error_count": job.get('errorCount', 0),
                "print_attempts": job.get('printAttempts', 1),
                **categorization
            }
            jobs_to_insert.append(job_doc)
        
        # Upsert jobs
        from pymongo import UpdateOne
        operations = [
            UpdateOne(
                {"marker": job["marker"]},
                {"$set": job},
                upsert=True
            )
            for job in jobs_to_insert
        ]
        
        if operations:
            await db.print_jobs.bulk_write(operations)
        
        new_marker = attempts[-1]['marker'] if attempts else start_marker
        
        return SyncStatus(
            status="success",
            jobs_synced=len(attempts),
            last_marker=new_marker,
            message=f"Synced {len(attempts)} jobs. Wait 30s before next sync (API rate limit)."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Sync error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/clicks/report")
async def get_clicks_report(
    device_id: str = Query(default="all"),
    is_oneshot: bool = Query(default=None),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None)
):
    """Get clicks report with category breakdown
    
    Uses Jobs API data for < 14 days range, PrintVolume API for > 14 days
    """
    # Calculate date range
    use_jobs_api = True
    if from_date and to_date:
        from_dt = datetime.strptime(from_date, "%Y-%m-%d")
        to_dt = datetime.strptime(to_date, "%Y-%m-%d")
        days_diff = (to_dt - from_dt).days
        use_jobs_api = days_diff < 14
    elif from_date:
        from_dt = datetime.strptime(from_date, "%Y-%m-%d")
        days_diff = (datetime.now() - from_dt).days
        use_jobs_api = days_diff < 14
    
    report = {
        "total_impressions": 0,
        "total_sheets": 0,
        "total_jobs": 0,
        "one_color": 0,
        "two_colors": 0,
        "epm": 0,
        "multicolor": 0,
        "unknown": 0,
        "categories": [],
        "oneshot_total": 0,
        "multishot_total": 0,
        "data_source": "jobs" if use_jobs_api else "printvolume"
    }
    
    if use_jobs_api:
        # Use Jobs API data from MongoDB (< 14 days)
        match_stage = {}
        
        if device_id != "all":
            match_stage["press_id"] = device_id
        
        if is_oneshot is not None:
            match_stage["is_oneshot"] = is_oneshot
        
        if from_date or to_date:
            match_stage["submit_time"] = {}
            if from_date:
                match_stage["submit_time"]["$gte"] = from_date
            if to_date:
                match_stage["submit_time"]["$lte"] = to_date + "T23:59:59"
        
        pipeline = [
            {"$match": match_stage} if match_stage else {"$match": {}},
            {
                "$group": {
                    "_id": "$click_category",
                    "count": {"$sum": 1},
                    "impressions": {"$sum": "$total_impressions"},
                    "sheets": {"$sum": {"$ifNull": ["$sheets", "$total_impressions"]}}
                }
            }
        ]
        
        cursor = db.print_jobs.aggregate(pipeline)
        results = await cursor.to_list(length=100)
        
        for r in results:
            category = r["_id"] or "Unknown"
            impressions = r["impressions"]
            report["total_impressions"] += impressions
            report["total_sheets"] += r.get("sheets", impressions)
            report["total_jobs"] += r["count"]
            report["categories"].append({
                "name": category,
                "count": r["count"],
                "impressions": impressions
            })
            
            if category == "1 Color":
                report["one_color"] = impressions
            elif category == "2 Colors":
                report["two_colors"] = impressions
            elif category == "EPM":
                report["epm"] = impressions
            elif category == "Multicolor":
                report["multicolor"] = impressions
            else:
                report["unknown"] = impressions
        
        # Get oneshot/multishot breakdown
        oneshot_pipeline = [
            {"$match": match_stage} if match_stage else {"$match": {}},
            {
                "$group": {
                    "_id": "$is_oneshot",
                    "impressions": {"$sum": "$total_impressions"}
                }
            }
        ]
        
        cursor = db.print_jobs.aggregate(oneshot_pipeline)
        oneshot_results = await cursor.to_list(length=10)
        
        for r in oneshot_results:
            if r["_id"] is True:
                report["oneshot_total"] = r["impressions"]
            else:
                report["multishot_total"] = r["impressions"]
    
    else:
        # Use PrintVolume API for > 14 days (with caching)
        try:
            # Query each device separately to avoid permission issues
            devices_list = [device_id] if device_id != "all" else list(DEVICES.keys())
            
            for dev_id in devices_list:
                try:
                    # Use cached fetch
                    data = await fetch_printvolume_with_cache(dev_id, from_date, to_date, "Month")
                    
                    if data and "data" in data:
                        for unit in data.get("data", {}).get("unitEvents", []):
                            for event in unit.get("events", []):
                                # Use value.value for actual impressions
                                impressions = event.get("value", {}).get("value", 0)
                                report["total_impressions"] += impressions
                                report["multicolor"] += impressions
                except Exception as dev_e:
                    logger.error(f"PrintVolume API error for {dev_id}: {dev_e}")
            
            if report["total_impressions"] > 0:
                report["categories"].append({
                    "name": "Multicolor",
                    "count": 0,
                    "impressions": report["total_impressions"]
                })
        except Exception as e:
            logger.error(f"PrintVolume API error: {e}")
    
    return report


@api_router.get("/clicks/trend")
async def get_clicks_trend(
    device_id: str = Query(default="all"),
    is_oneshot: bool = Query(default=None),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None),
    resolution: str = Query(default="day")
):
    """Get clicks trend over time
    
    Uses Jobs API data for < 14 days range, PrintVolume API for > 14 days
    """
    # Calculate date range
    use_jobs_api = True
    if from_date and to_date:
        from_dt = datetime.strptime(from_date, "%Y-%m-%d")
        to_dt = datetime.strptime(to_date, "%Y-%m-%d")
        days_diff = (to_dt - from_dt).days
        use_jobs_api = days_diff < 14
    elif from_date:
        from_dt = datetime.strptime(from_date, "%Y-%m-%d")
        days_diff = (datetime.now() - from_dt).days
        use_jobs_api = days_diff < 14
    
    trend_data = {}
    
    if use_jobs_api:
        # Use Jobs API data from MongoDB (< 14 days)
        match_stage = {}
        
        if device_id != "all":
            match_stage["press_id"] = device_id
        
        if is_oneshot is not None:
            match_stage["is_oneshot"] = is_oneshot
        
        if from_date or to_date:
            match_stage["submit_time"] = {}
            if from_date:
                match_stage["submit_time"]["$gte"] = from_date
            if to_date:
                match_stage["submit_time"]["$lte"] = to_date + "T23:59:59"
        
        # Group by date based on resolution
        if resolution == "year":
            date_length = 4  # YYYY
        elif resolution == "month":
            date_length = 7  # YYYY-MM
        else:
            date_length = 10  # YYYY-MM-DD
        
        pipeline = [
            {"$match": match_stage} if match_stage else {"$match": {}},
            {
                "$addFields": {
                    "date": {"$substr": ["$submit_time", 0, date_length]}
                }
            },
            {
                "$group": {
                    "_id": {
                        "date": "$date",
                        "category": "$click_category"
                    },
                    "impressions": {"$sum": "$total_impressions"}
                }
            },
            {"$sort": {"_id.date": 1}}
        ]
        
        cursor = db.print_jobs.aggregate(pipeline)
        results = await cursor.to_list(length=1000)
        
        for r in results:
            date = r["_id"]["date"]
            category = r["_id"]["category"] or "Unknown"
            if date not in trend_data:
                trend_data[date] = {"date": date, "1 Color": 0, "2 Colors": 0, "EPM": 0, "Multicolor": 0}
            trend_data[date][category] = r["impressions"]
    
    else:
        # Use PrintVolume API for > 14 days (with caching)
        try:
            # Query each device separately
            devices_list = [device_id] if device_id != "all" else list(DEVICES.keys())
            hp_resolution = "Day" if resolution == "day" else "Month"
            
            for dev_id in devices_list:
                try:
                    # Use cached fetch
                    data = await fetch_printvolume_with_cache(dev_id, from_date, to_date, hp_resolution)
                    
                    if data and "data" in data:
                        for unit in data.get("data", {}).get("unitEvents", []):
                            for event in unit.get("events", []):
                                date = event.get("date", "")
                                if resolution == "year" and len(date) >= 4:
                                    date = date[:4]
                                elif resolution == "month" and len(date) >= 7:
                                    date = date[:7]
                                
                                impressions = event.get("value", {}).get("value", 0)
                                
                                if date not in trend_data:
                                    trend_data[date] = {"date": date, "1 Color": 0, "2 Colors": 0, "EPM": 0, "Multicolor": 0}
                                trend_data[date]["Multicolor"] += impressions
                except Exception as dev_e:
                    logger.error(f"PrintVolume trend error for {dev_id}: {dev_e}")
        except Exception as e:
            logger.error(f"PrintVolume API trend error: {e}")
    
    return list(trend_data.values())


@api_router.get("/clicks/yoy")
async def get_clicks_yoy(
    device_id: str = Query(default="all"),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None)
):
    """Get Year-over-Year comparison for clicks
    
    Compares current period with the same period from the previous year
    """
    # Default to year-to-date if no dates provided
    today = datetime.now()
    
    if not from_date:
        from_date = f"{today.year}-01-01"
    if not to_date:
        to_date = today.strftime("%Y-%m-%d")
    
    # Parse dates
    from_dt = datetime.strptime(from_date, "%Y-%m-%d")
    to_dt = datetime.strptime(to_date, "%Y-%m-%d")
    
    # Calculate previous year period
    prev_from_dt = from_dt.replace(year=from_dt.year - 1)
    prev_to_dt = to_dt.replace(year=to_dt.year - 1)
    
    prev_from_date = prev_from_dt.strftime("%Y-%m-%d")
    prev_to_date = prev_to_dt.strftime("%Y-%m-%d")
    
    async def get_impressions_for_period(start_date: str, end_date: str) -> dict:
        """Helper to get total impressions for a date range"""
        # Check date range to determine data source
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        days_diff = (end_dt - start_dt).days
        use_jobs_api = days_diff < 14
        
        result = {"total": 0, "source": "jobs" if use_jobs_api else "printvolume"}
        
        if use_jobs_api:
            # Use Jobs API data from MongoDB
            match_stage = {"submit_time": {"$gte": start_date, "$lte": end_date + "T23:59:59"}}
            
            if device_id != "all":
                match_stage["press_id"] = device_id
            
            pipeline = [
                {"$match": match_stage},
                {"$group": {"_id": None, "total": {"$sum": "$total_impressions"}}}
            ]
            
            cursor = db.print_jobs.aggregate(pipeline)
            results = await cursor.to_list(length=1)
            
            if results:
                result["total"] = results[0].get("total", 0)
        else:
            # Use PrintVolume API with caching
            devices_list = [device_id] if device_id != "all" else list(DEVICES.keys())
            
            for dev_id in devices_list:
                try:
                    data = await fetch_printvolume_with_cache(dev_id, start_date, end_date, "Month")
                    
                    if data and "data" in data:
                        for unit in data.get("data", {}).get("unitEvents", []):
                            for event in unit.get("events", []):
                                impressions = event.get("value", {}).get("value", 0)
                                result["total"] += impressions
                except Exception as e:
                    logger.error(f"YoY PrintVolume error for {dev_id}: {e}")
        
        return result
    
    # Get data for both periods
    current_data = await get_impressions_for_period(from_date, to_date)
    previous_data = await get_impressions_for_period(prev_from_date, prev_to_date)
    
    # Calculate change
    current_total = current_data["total"]
    previous_total = previous_data["total"]
    
    change_absolute = current_total - previous_total
    change_percent = 0
    if previous_total > 0:
        change_percent = round(((current_total - previous_total) / previous_total) * 100, 1)
    
    return {
        "current_period": {
            "from": from_date,
            "to": to_date,
            "total_impressions": current_total,
            "source": current_data["source"]
        },
        "previous_period": {
            "from": prev_from_date,
            "to": prev_to_date,
            "total_impressions": previous_total,
            "source": previous_data["source"]
        },
        "change_absolute": change_absolute,
        "change_percent": change_percent,
        "trend": "up" if change_absolute > 0 else ("down" if change_absolute < 0 else "stable")
    }


@api_router.get("/clicks/yoy/trend")
async def get_clicks_yoy_trend(
    device_id: str = Query(default="all"),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None)
):
    """Get Year-over-Year trend data for chart comparison
    
    Returns monthly data for current and previous year
    """
    today = datetime.now()
    
    if not from_date:
        from_date = f"{today.year}-01-01"
    if not to_date:
        to_date = today.strftime("%Y-%m-%d")
    
    from_dt = datetime.strptime(from_date, "%Y-%m-%d")
    to_dt = datetime.strptime(to_date, "%Y-%m-%d")
    
    # Previous year dates
    prev_from_dt = from_dt.replace(year=from_dt.year - 1)
    prev_to_dt = to_dt.replace(year=to_dt.year - 1)
    
    prev_from_date = prev_from_dt.strftime("%Y-%m-%d")
    prev_to_date = prev_to_dt.strftime("%Y-%m-%d")
    
    async def get_monthly_data(start_date: str, end_date: str, year_label: str) -> list:
        """Get monthly impressions data"""
        monthly = {}
        
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        days_diff = (end_dt - start_dt).days
        use_jobs_api = days_diff < 14
        
        if use_jobs_api:
            match_stage = {"submit_time": {"$gte": start_date, "$lte": end_date + "T23:59:59"}}
            
            if device_id != "all":
                match_stage["press_id"] = device_id
            
            pipeline = [
                {"$match": match_stage},
                {"$addFields": {"month": {"$substr": ["$submit_time", 0, 7]}}},
                {"$group": {"_id": "$month", "impressions": {"$sum": "$total_impressions"}}},
                {"$sort": {"_id": 1}}
            ]
            
            cursor = db.print_jobs.aggregate(pipeline)
            results = await cursor.to_list(length=100)
            
            for r in results:
                month_key = r["_id"][-2:]  # Get MM part
                monthly[month_key] = r["impressions"]
        else:
            devices_list = [device_id] if device_id != "all" else list(DEVICES.keys())
            
            for dev_id in devices_list:
                try:
                    data = await fetch_printvolume_with_cache(dev_id, start_date, end_date, "Month")
                    
                    if data and "data" in data:
                        for unit in data.get("data", {}).get("unitEvents", []):
                            for event in unit.get("events", []):
                                date = event.get("date", "")
                                if len(date) >= 7:
                                    month_key = date[5:7]  # Get MM part
                                    impressions = event.get("value", {}).get("value", 0)
                                    monthly[month_key] = monthly.get(month_key, 0) + impressions
                except Exception as e:
                    logger.error(f"YoY trend error for {dev_id}: {e}")
        
        return monthly
    
    # Get data for both years
    current_monthly = await get_monthly_data(from_date, to_date, "current")
    previous_monthly = await get_monthly_data(prev_from_date, prev_to_date, "previous")
    
    # Combine into chart-friendly format
    months = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"]
    month_names = ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"]
    
    trend = []
    for i, month in enumerate(months):
        trend.append({
            "month": month_names[i],
            "current_year": current_monthly.get(month, 0),
            "previous_year": previous_monthly.get(month, 0)
        })
    
    return {
        "current_year": from_dt.year,
        "previous_year": prev_from_dt.year,
        "trend": trend
    }


@api_router.get("/cache/status")
async def get_cache_status():
    """Get cache statistics"""
    total_cached = await db.printvolume_cache.count_documents({})
    
    # Get most recent cache entries
    cursor = db.printvolume_cache.find({}, {"_id": 0, "cache_key": 1, "cached_at": 1}).sort("cached_at", -1).limit(10)
    recent = await cursor.to_list(length=10)
    
    return {
        "total_cached_entries": total_cached,
        "cache_ttl_hours": CACHE_TTL_HOURS,
        "recent_entries": recent
    }


@api_router.delete("/cache/clear")
async def clear_cache():
    """Clear the PrintVolume cache"""
    result = await db.printvolume_cache.delete_many({})
    return {
        "status": "cleared",
        "deleted_entries": result.deleted_count
    }


@api_router.get("/analysis/availability")
async def get_availability_analysis(
    device_id: str = Query(default="all"),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None)
):
    """Get availability and technical analysis data per device
    
    Uses HP PrintOS APIs:
    - /Historic/Failures for failure data
    - /Historic/Jams for paper jam data
    - /Historic/Restarts for restart data
    """
    # Default to last 30 days
    today = datetime.now()
    if not from_date:
        from_date = (today - timedelta(days=30)).strftime("%Y-%m-%d")
    if not to_date:
        to_date = today.strftime("%Y-%m-%d")
    
    from_dt = datetime.strptime(from_date, "%Y-%m-%d")
    to_dt = datetime.strptime(to_date, "%Y-%m-%d")
    days_count = (to_dt - from_dt).days + 1
    
    # Get devices to query
    devices_list = [device_id] if device_id != "all" else list(DEVICES.keys())
    
    # Initialize result containers
    failures_data = {}  # date -> failures count
    jams_data = {}      # date -> jams count
    restarts_data = {}  # date -> restarts count
    impressions_data = {} # date -> impressions (for rate calculation)
    
    # Fetch data for each device
    for dev_id in devices_list:
        try:
            # Fetch Failures from HP API
            failures_path = '/externalApi/v1/Historic/Failures'
            failures_params = {
                'devices': dev_id,
                'from': f'{from_date} 00:00:00',
                'to': f'{to_date} 23:59:59',
                'resolution': 'Day',
                'unitSystem': 'Metric'
            }
            failures_response = await fetch_hp_api(failures_path, failures_params, use_historic_key=True)
            
            if failures_response and "data" in failures_response:
                for unit in failures_response.get("data", {}).get("unitEvents", []):
                    for event in unit.get("events", []):
                        date = event.get("date", "")[:10]
                        count = event.get("value", {}).get("value", 0)
                        failures_data[date] = failures_data.get(date, 0) + count
            
            # Fetch Jams from HP API
            jams_path = '/externalApi/v1/Historic/Jams'
            jams_params = {
                'devices': dev_id,
                'from': f'{from_date} 00:00:00',
                'to': f'{to_date} 23:59:59',
                'resolution': 'Day',
                'unitSystem': 'Metric'
            }
            jams_response = await fetch_hp_api(jams_path, jams_params, use_historic_key=True)
            
            if jams_response and "data" in jams_response:
                for unit in jams_response.get("data", {}).get("unitEvents", []):
                    for event in unit.get("events", []):
                        date = event.get("date", "")[:10]
                        count = event.get("value", {}).get("value", 0)
                        jams_data[date] = jams_data.get(date, 0) + count
            
            # Fetch Restarts from HP API
            restarts_path = '/externalApi/v1/Historic/Restarts'
            restarts_params = {
                'devices': dev_id,
                'from': f'{from_date} 00:00:00',
                'to': f'{to_date} 23:59:59',
                'resolution': 'Day',
                'unitSystem': 'Metric'
            }
            restarts_response = await fetch_hp_api(restarts_path, restarts_params, use_historic_key=True)
            
            if restarts_response and "data" in restarts_response:
                for unit in restarts_response.get("data", {}).get("unitEvents", []):
                    for event in unit.get("events", []):
                        date = event.get("date", "")[:10]
                        count = event.get("value", {}).get("value", 0)
                        restarts_data[date] = restarts_data.get(date, 0) + count
            
            # Fetch PrintVolume for impressions (for rate calculation)
            volume_data = await fetch_printvolume_with_cache(dev_id, from_date, to_date, "Day")
            if volume_data and "data" in volume_data:
                for unit in volume_data.get("data", {}).get("unitEvents", []):
                    for event in unit.get("events", []):
                        date = event.get("date", "")[:10]
                        impressions = event.get("value", {}).get("value", 0)
                        impressions_data[date] = impressions_data.get(date, 0) + impressions
                        
        except Exception as e:
            logger.error(f"Error fetching analysis data for {dev_id}: {e}")
    
    # Also get availability from jobs database
    match_stage = {"submit_time": {"$gte": from_date, "$lte": to_date + "T23:59:59"}}
    if device_id != "all":
        match_stage["press_id"] = device_id
    
    pipeline = [
        {"$match": match_stage},
        {
            "$addFields": {
                "date": {"$substr": ["$submit_time", 0, 10]}
            }
        },
        {
            "$group": {
                "_id": "$date",
                "total_jobs": {"$sum": 1},
                "printed": {"$sum": {"$cond": [{"$eq": ["$status", "PRINTED"]}, 1, 0]}}
            }
        },
        {"$sort": {"_id": 1}}
    ]
    
    cursor = db.print_jobs.aggregate(pipeline)
    availability_jobs = await cursor.to_list(length=100)
    
    # Build availability trend
    availability_trend = []
    for day in availability_jobs:
        date = day["_id"]
        total = day["total_jobs"]
        printed = day.get("printed", 0)
        availability = round((printed / max(total, 1)) * 100, 1)
        availability_trend.append({"date": date, "value": availability})
    
    # Calculate failure and jam rates per 1M impressions
    technical_daily = []
    failure_rates = []
    jam_rates = []
    
    all_dates = sorted(set(list(failures_data.keys()) + list(jams_data.keys()) + list(impressions_data.keys())))
    
    for date in all_dates:
        failures = failures_data.get(date, 0)
        jams = jams_data.get(date, 0)
        impressions = impressions_data.get(date, 1)  # Avoid division by zero
        
        # Rate per 1M impressions
        failure_rate = round((failures / impressions) * 1000000, 2) if impressions > 0 else 0
        jam_rate = round((jams / impressions) * 1000000, 2) if impressions > 0 else 0
        
        failure_rates.append(failure_rate)
        jam_rates.append(jam_rate)
        
        technical_daily.append({
            "date": date,
            "failures": failure_rate,
            "jams": jam_rate,
            "failures_count": failures,
            "jams_count": jams
        })
    
    # Build restarts data
    restarts_daily = []
    restart_values = []
    for date in sorted(restarts_data.keys()):
        count = restarts_data[date]
        restarts_daily.append({"date": date, "restarts": count})
        restart_values.append(count)
    
    # Calculate averages and maximums
    avg_availability = round(sum(d["value"] for d in availability_trend) / max(len(availability_trend), 1), 1) if availability_trend else 0
    avg_failure = round(sum(failure_rates) / max(len(failure_rates), 1), 2) if failure_rates else 0
    max_failure = max(failure_rates) if failure_rates else 0
    avg_jam = round(sum(jam_rates) / max(len(jam_rates), 1), 2) if jam_rates else 0
    max_jam = max(jam_rates) if jam_rates else 0
    avg_restarts = round(sum(restart_values) / max(len(restart_values), 1), 1) if restart_values else 0
    max_restarts = max(restart_values) if restart_values else 0
    
    return {
        "availability": {
            "average": avg_availability,
            "trend": availability_trend
        },
        "technicalIssues": {
            "failureRate": {
                "average": avg_failure,
                "max": max_failure
            },
            "paperJamRate": {
                "average": avg_jam,
                "max": max_jam
            },
            "dailyData": technical_daily
        },
        "restarts": {
            "averageRate": avg_restarts,
            "maxRate": max_restarts,
            "dailyData": restarts_daily
        },
        "period": {
            "from": from_date,
            "to": to_date,
            "days": days_count
        },
        "device": device_id
    }


@api_router.get("/clicks/export")
async def export_clicks_csv(
    device_id: str = Query(default="all"),
    is_oneshot: bool = Query(default=None),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None)
):
    """Export clicks data as CSV"""
    query = {}
    
    if device_id != "all":
        query["press_id"] = device_id
    
    if is_oneshot is not None:
        query["is_oneshot"] = is_oneshot
    
    if from_date or to_date:
        query["submit_time"] = {}
        if from_date:
            query["submit_time"]["$gte"] = from_date
        if to_date:
            query["submit_time"]["$lte"] = to_date + "T23:59:59"
    
    cursor = db.print_jobs.find(query, {"_id": 0}).sort("submit_time", -1)
    jobs = await cursor.to_list(length=10000)
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([
        "Job Name", "Press", "Submit Time", "Status", "Click Category",
        "Total Impressions", "OneShot Impressions", "Is OneShot", "Is EPM"
    ])
    
    # Data rows
    for job in jobs:
        press_name = DEVICES.get(job.get("press_id", ""), {}).get("name", job.get("press_id", ""))
        writer.writerow([
            job.get("job_name", ""),
            press_name,
            job.get("submit_time", ""),
            job.get("status", ""),
            job.get("click_category", ""),
            job.get("total_impressions", 0),
            job.get("one_shot_impressions", 0),
            job.get("is_oneshot", False),
            job.get("is_epm", False)
        ])
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=clicks_report.csv"}
    )


@api_router.get("/stats/overview")
async def get_stats_overview(
    device_id: str = Query(default="all"),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None)
):
    """Get overview statistics"""
    match_stage = {}
    if device_id != "all":
        match_stage["press_id"] = device_id
    
    if from_date or to_date:
        match_stage["submit_time"] = {}
        if from_date:
            match_stage["submit_time"]["$gte"] = from_date
        if to_date:
            match_stage["submit_time"]["$lte"] = to_date + "T23:59:59"
    
    # Total jobs and impressions
    pipeline = [
        {"$match": match_stage} if match_stage else {"$match": {}},
        {
            "$group": {
                "_id": None,
                "total_jobs": {"$sum": 1},
                "total_impressions": {"$sum": "$total_impressions"},
                "total_sheets": {"$sum": {"$ifNull": ["$sheets", "$total_impressions"]}},
                "printed_jobs": {"$sum": {"$cond": [{"$eq": ["$status", "PRINTED"]}, 1, 0]}},
                "aborted_jobs": {"$sum": {"$cond": [{"$eq": ["$status", "ABORTED"]}, 1, 0]}}
            }
        }
    ]
    
    cursor = db.print_jobs.aggregate(pipeline)
    results = await cursor.to_list(length=1)
    
    if results:
        stats = results[0]
        return {
            "total_jobs": stats.get("total_jobs", 0),
            "total_impressions": stats.get("total_impressions", 0),
            "total_sheets": stats.get("total_sheets", 0),
            "printed_jobs": stats.get("printed_jobs", 0),
            "aborted_jobs": stats.get("aborted_jobs", 0),
            "success_rate": round(stats.get("printed_jobs", 0) / max(stats.get("total_jobs", 1), 1) * 100, 1)
        }
    
    return {
        "total_jobs": 0,
        "total_impressions": 0,
        "total_sheets": 0,
        "printed_jobs": 0,
        "aborted_jobs": 0,
        "success_rate": 0
    }


# ============ Background Sync ============

async def sync_device_jobs(device_id: str):
    """Sync jobs for a single device"""
    try:
        last_job = await db.print_jobs.find_one(
            {"press_id": device_id},
            sort=[("marker", -1)],
            projection={"marker": 1, "_id": 0}
        )
        start_marker = last_job["marker"] if last_job else 0
        
        path = '/externalApi/jobs'
        params = {
            'devices': device_id,
            'startMarker': start_marker,
            'limit': 100,
            'sortOrder': 'ASC'
        }
        
        data = await fetch_hp_api(path, params, use_historic_key=False)
        attempts = data.get('attempts', [])
        
        if not attempts:
            return 0
        
        from pymongo import UpdateOne
        operations = []
        
        for job in attempts:
            categorization = categorize_click(job)
            job_doc = {
                "marker": job.get('marker'),
                "press_id": device_id,
                "job_name": job.get('jobName'),
                "status": job.get('jobProgress', 'UNKNOWN'),
                "submit_time": job.get('jobSubmitTime'),
                "total_impressions": job.get('impressions', 0),
                "one_shot_impressions": job.get('oneShotImpressions', 0),
                "impressions_1_color": job.get('impressions1Color', 0),
                "impressions_2_colors": job.get('impressions2Colors', 0),
                "impressions_n_colors": job.get('impressionsNColors', 0),
                "inks": job.get('inks', []),
                "substrates": job.get('substrates', []),
                "error_count": job.get('errorCount', 0),
                "print_attempts": job.get('printAttempts', 1),
                **categorization
            }
            operations.append(
                UpdateOne({"marker": job["marker"]}, {"$set": job_doc}, upsert=True)
            )
        
        if operations:
            await db.print_jobs.bulk_write(operations)
        
        # Log sync event
        await db.sync_log.insert_one({
            "device_id": device_id,
            "device_name": DEVICES.get(device_id, {}).get("name", device_id),
            "jobs_synced": len(attempts),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "auto_sync"
        })
        
        return len(attempts)
    except Exception as e:
        logger.error(f"Error syncing device {device_id}: {e}")
        # Log error
        await db.sync_log.insert_one({
            "device_id": device_id,
            "device_name": DEVICES.get(device_id, {}).get("name", device_id),
            "jobs_synced": 0,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "auto_sync"
        })
        return 0


async def background_sync_loop():
    """Background task that syncs all devices in rotation"""
    global sync_running
    sync_running = True
    
    device_ids = list(DEVICES.keys())
    current_device_idx = 0
    
    while sync_running:
        try:
            device_id = device_ids[current_device_idx]
            jobs_synced = await sync_device_jobs(device_id)
            logger.info(f"Background sync: {DEVICES[device_id]['name']} - {jobs_synced} jobs")
            
            # Move to next device
            current_device_idx = (current_device_idx + 1) % len(device_ids)
            
            # Wait 35 seconds between syncs (API rate limit is 2 req/min)
            await asyncio.sleep(35)
            
        except Exception as e:
            logger.error(f"Background sync error: {e}")
            await asyncio.sleep(60)  # Wait longer on error


@api_router.get("/sync/status")
async def get_sync_status():
    """Get background sync status with recent log"""
    global sync_running
    
    # Get recent sync logs
    cursor = db.sync_log.find({}, {"_id": 0}).sort("timestamp", -1).limit(10)
    recent_logs = await cursor.to_list(length=10)
    
    return {
        "running": sync_running,
        "devices": list(DEVICES.keys()),
        "recent_logs": recent_logs
    }


@api_router.get("/sync/log")
async def get_sync_log(limit: int = Query(default=50, ge=1, le=200)):
    """Get sync log history"""
    cursor = db.sync_log.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    logs = await cursor.to_list(length=limit)
    return {"logs": logs, "total": len(logs)}


@api_router.get("/import/log")
async def get_import_log(limit: int = Query(default=50, ge=1, le=200)):
    """Get import log history"""
    cursor = db.import_log.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
    logs = await cursor.to_list(length=limit)
    return {"logs": logs, "total": len(logs)}


@api_router.post("/data/refresh")
async def refresh_data(
    device_id: str = Query(default="all"),
    from_date: str = Query(default=None),
    to_date: str = Query(default=None),
    force: bool = Query(default=False)
):
    """Smart refresh - fetch from API if no data for date range or force=True"""
    devices_to_sync = [device_id] if device_id != "all" else list(DEVICES.keys())
    
    total_synced = 0
    results = []
    
    for dev_id in devices_to_sync:
        # Check if we have data for this SPECIFIC date range
        query = {"press_id": dev_id}
        if from_date:
            if "submit_time" not in query:
                query["submit_time"] = {}
            query["submit_time"]["$gte"] = from_date
        if to_date:
            if "submit_time" not in query:
                query["submit_time"] = {}
            query["submit_time"]["$lte"] = to_date + "T23:59:59"
        
        existing_count = await db.print_jobs.count_documents(query)
        
        # Sync from API if:
        # 1. No data exists for the date range, OR
        # 2. Force refresh is requested
        should_sync = existing_count == 0 or force
        
        if should_sync:
            try:
                jobs_synced = await sync_device_jobs(dev_id)
                total_synced += jobs_synced
                results.append({
                    "device": dev_id,
                    "device_name": DEVICES.get(dev_id, {}).get("name", dev_id),
                    "status": "synced",
                    "jobs_synced": jobs_synced,
                    "had_existing": existing_count > 0,
                    "forced": force
                })
                
                # Log refresh
                await db.sync_log.insert_one({
                    "device_id": dev_id,
                    "device_name": DEVICES.get(dev_id, {}).get("name", dev_id),
                    "jobs_synced": jobs_synced,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "manual_refresh",
                    "date_range": {"from": from_date, "to": to_date}
                })
                
                # Wait for rate limit if more devices to sync
                if len(devices_to_sync) > 1:
                    await asyncio.sleep(35)
                    
            except HTTPException as e:
                results.append({
                    "device": dev_id,
                    "device_name": DEVICES.get(dev_id, {}).get("name", dev_id),
                    "status": "error",
                    "error": str(e.detail)
                })
        else:
            results.append({
                "device": dev_id,
                "device_name": DEVICES.get(dev_id, {}).get("name", dev_id),
                "status": "cached",
                "existing_jobs": existing_count,
                "had_existing": True
            })
    
    return {
        "total_synced": total_synced,
        "results": results,
        "message": f"Refresh complete. {total_synced} new jobs synced." if total_synced > 0 else "Keine neuen Jobs gefunden."
    }


@api_router.post("/sync/start")
async def start_background_sync(background_tasks: BackgroundTasks):
    """Start background sync"""
    global sync_task, sync_running
    
    if sync_running:
        return {"status": "already_running", "message": "Background sync is already running"}
    
    background_tasks.add_task(background_sync_loop)
    return {"status": "started", "message": "Background sync started. Syncing all devices every 35 seconds."}


@api_router.post("/sync/stop")
async def stop_background_sync():
    """Stop background sync"""
    global sync_running
    sync_running = False
    return {"status": "stopped", "message": "Background sync will stop after current operation"}


# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize app on startup"""
    # Load device configuration from database
    await load_devices_from_db()
    # Pre-load credentials into cache
    await get_api_credentials()
    logger.info(f"App started with {len(DEVICES)} devices configured")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test MongoDB connection
        await db.command("ping")
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail="Database unavailable")