from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelScope"
    environment: str = "development"
    database_url: str = "sqlite:///./security_monitor.db"
    jwt_secret: str = "local-development-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 20
    refresh_token_days: int = 7
    admin_username: str = "admin"
    admin_password: str = "change-me-before-production"
    ingestion_api_key: str = "local-ingestion-key-change-me"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    def validate_security(self) -> None:
        if self.environment.lower() == "production":
            insecure = {
                "local-development-secret-change-me",
                "change-me-before-production",
                "local-ingestion-key-change-me",
            }
            values = {self.jwt_secret, self.admin_password, self.ingestion_api_key}
            if insecure & values:
                raise RuntimeError("Production security secrets must be replaced")
            if len(self.jwt_secret) < 32 or len(self.admin_password) < 12 or len(self.ingestion_api_key) < 24:
                raise RuntimeError("Production secrets do not meet the minimum length requirements")
            if len(values) != 3:
                raise RuntimeError("Production secrets must be independent values")
            if "*" in self.allowed_origins:
                raise RuntimeError("Wildcard CORS origins are not allowed in production")


@lru_cache
def get_settings() -> Settings:
    return Settings()
