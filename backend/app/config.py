"""
Backend Application Configuration
Loads settings from environment variables or .env file with validated defaults.
"""

import os
import json
from typing import List, Union
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator

class Settings(BaseSettings):
    APP_NAME: str = "Privacy-Preserving Threat Detection"
    APP_ENV: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # Database: Async SQLite fallback by default for zero-friction local run
    DATABASE_URL: str = "sqlite+aiosqlite:///./threat_detection.db"

    # Security & JWT
    SECRET_KEY: str = "threat-detection-dev-secret-key-super-secure-32chars"
    JWT_SECRET: str = "threat-detection-jwt-secret-dev-key-32chars"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # Privacy Engine Salt (Used for HMAC-SHA256 salted pseudonymization)
    PRIVACY_SALT: str = "privacy-salt-isolated-dev-token-hmac-salt"

    # CORS & WebSockets
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    WEBSOCKET_URL: str = "ws://127.0.0.1:8000/ws"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v_trimmed = v.strip()
            if v_trimmed.startswith("[") and v_trimmed.endswith("]"):
                try:
                    parsed = json.loads(v_trimmed)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, (list, tuple)):
            return [str(origin).strip() for origin in v if str(origin).strip()]
        return v

    # ML & Federated Learning
    MODEL_DIR: str = "./ml/models"
    DATASET_DIR: str = "./ml/datasets"
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
