"""
Backend Application Configuration
Loads settings from environment variables or .env file with validated defaults.
"""

import os
import json
import tempfile
from typing import List, Union, Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, model_validator

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TMP_DIR = "/tmp" if os.path.exists("/tmp") else tempfile.gettempdir()
TMP_DB_PATH = os.path.join(TMP_DIR, "threat_detection.db").replace("\\", "/")

class Settings(BaseSettings):
    @model_validator(mode="before")
    @classmethod
    def clean_empty_strings(cls, values: Any) -> Any:
        """Strips out empty environment variables so strong defaults are used on Vercel."""
        if isinstance(values, dict):
            cleaned = {}
            for k, v in values.items():
                if isinstance(v, str) and not v.strip():
                    continue
                cleaned[k] = v
            return cleaned
        return values

    APP_NAME: str = "Privacy-Preserving Threat Detection"
    APP_ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # Database: Async SQLite fallback by default for zero-friction local run
    DATABASE_URL: str = f"sqlite+aiosqlite:///{TMP_DB_PATH}" if os.environ.get("VERCEL") else "sqlite+aiosqlite:///./threat_detection.db"

    # Security & JWT
    SECRET_KEY: str = "threat-detection-dev-secret-key-super-secure-32chars"
    JWT_SECRET: str = "threat-detection-jwt-secret-dev-key-32chars"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # Privacy Engine Salt & Encryption Keys (Part 30 - AES-256-GCM & HMAC-SHA-256)
    PRIVACY_SALT: str = "privacy-salt-isolated-dev-token-hmac-salt"
    PRIVACY_ENCRYPTION_KEY: str = "threat-detection-aes256gcm-dev-key-32chars!"
    PRIVACY_KEY_ID: str = "privacy-key-v1"

    # CORS & WebSockets
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://privacy-preserving-threat-detection.vercel.app"
    ]
    WEBSOCKET_URL: str = "ws://127.0.0.1:8000/ws"

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v_trimmed = v.strip()
            if not v_trimmed:
                return [
                    "http://localhost:3000",
                    "http://127.0.0.1:3000",
                    "https://privacy-preserving-threat-detection.vercel.app"
                ]
            if v_trimmed.startswith("[") and v_trimmed.endswith("]"):
                try:
                    parsed = json.loads(v_trimmed)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            return [origin.strip() for origin in v_trimmed.split(",") if origin.strip()]
        elif isinstance(v, (list, tuple)):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "https://privacy-preserving-threat-detection.vercel.app"
        ]

    # ML & Federated Learning
    MODEL_DIR: str = os.path.join(ROOT_DIR, "ml", "models")
    DATASET_DIR: str = os.path.join(ROOT_DIR, "ml", "datasets")
    FL_SERVER_HOST: str = "0.0.0.0"
    FL_SERVER_PORT: int = 8080
    FL_MIN_CLIENTS: int = 3
    FL_ROUNDS: int = 5

    # Operational Mode: LIVE, TEST, OFFLINE
    OPERATIONAL_MODE: str = "TEST"

    # Retention (days)
    EVENT_RETENTION_DAYS: int = 90
    ALERT_RETENTION_DAYS: int = 180
    AUDIT_RETENTION_DAYS: int = 365

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
