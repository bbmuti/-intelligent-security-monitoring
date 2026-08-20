from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelScope"
    database_url: str = "sqlite:///./security_monitor.db"
    jwt_secret: str = "local-development-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60
    admin_username: str = "admin"
    admin_password: str = "change-me-before-production"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
