"""Application configuration — loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Database
    database_url: str = "postgresql+asyncpg://hipaa:hipaa@localhost:5432/hipaa_scanner"

    # JWT
    jwt_secret_key: str = "CHANGE-ME-IN-PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Scanner API
    scanner_api_secret: str = "CHANGE-ME-IN-PRODUCTION"

    # Email (optional notifications)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_email: str = "noreply@hipaa-scanner.com"

    # App
    app_name: str = "HIPAA Scanner Platform"
    app_version: str = "1.0.0"
    debug: bool = False
    allowed_origins: list[str] = ["http://localhost:5173", "https://hipaa.texmg.com"]


settings = Settings()
