"""
Local Organization Agent Configuration
"""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class AgentConfig(BaseSettings):
    ORGANIZATION_ID: str = "org_enterprise_a"
    AGENT_ID: str = "agent-dmz-01"
    AGENT_NAME: str = "DMZ Gateway Edge Agent"
    AGENT_API_KEY: str = "agent_key_enterprise_a_dmz_prod_secret"
    CENTRAL_API_URL: str = os.getenv("CENTRAL_API_URL", "http://127.0.0.1:8000").rstrip("/")
    RETRY_MAX_ATTEMPTS: int = 3
    RETRY_BACKOFF_FACTOR: float = 1.5
    REQUEST_TIMEOUT_SECONDS: float = 5.0
    LOCAL_LOG_PATH: str = "agent_local.log"

    model_config = SettingsConfigDict(env_prefix="AGENT_", env_file=".env", extra="ignore")

agent_config = AgentConfig()
