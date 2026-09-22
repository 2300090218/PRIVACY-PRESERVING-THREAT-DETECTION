"""
Backend Application Configuration
Loads settings from environment variables or .env file with validated defaults.
"""

import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

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
