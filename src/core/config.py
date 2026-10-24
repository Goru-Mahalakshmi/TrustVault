import base64
from typing import Optional
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

def normalize_db_url(url: str) -> str:
    """Hosts such as Render hand out postgres:// or postgresql:// URLs; the app needs the asyncpg driver form."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://"):]
    return url.replace("sslmode=", "ssl=")          # asyncpg spells it ssl=


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    ENVIRONMENT: str = "development"
    DATABASE_URL: str = "sqlite+aiosqlite:///./trustvault.db"
    AUDIT_HMAC_KEY: str = "dev-only-change-me"          # keep outside the DB in production
    SESSION_COOKIE_NAME: str = "tv_session"
    SESSION_IDLE_TIMEOUT_MINUTES: int = 30
    SESSION_ABSOLUTE_TIMEOUT_HOURS: int = 12
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 15
    EMAIL_CHANGE_TOKEN_EXPIRE_MINUTES: int = 15
    TRUSTED_PROXIES: list[str] = ["127.0.0.1", "::1"]   # exact IPs or CIDR ranges, e.g. "172.16.0.0/12" for a Docker network
    ENABLE_DOCS: Optional[bool] = None   # interactive /docs; default: on in development, OFF in production
    RATE_LIMIT_LOGIN_PER_MIN: int = 5
    RATE_LIMIT_REGISTER_PER_MIN: int = 5
    RATE_LIMIT_FORGOT_PER_HOUR: int = 3
    RATE_LIMIT_REFUSALS_PER_MIN: int = 20
    RATE_LIMIT_GRANTS_PER_MIN: int = 10
    MASTER_KEY_B64: str = ""            # base64 of 32 random bytes; REQUIRED outside development
    STORAGE_DIR: str = "./storage"      # outside any web root; never mounted as static files
    STORAGE_BACKEND: str = "disk"       # disk: encrypted files in STORAGE_DIR | db: encrypted blobs in PostgreSQL (hosts without a persistent disk)
    RATE_LIMIT_UPLOADS_PER_MIN: int = 30
    MAX_UPLOAD_BYTES: int = 25 * 1024 * 1024
    MAX_CONCURRENT_DECRYPTS: int = 10
    COOKIE_SECURE: bool = True          # browsers accept Secure cookies on http://localhost; set False only for odd setups
    APP_BASE_URL: str = "http://127.0.0.1:8000"
    EMAIL_BACKEND: str = "console"      # console (dev: prints) | smtp | memory (tests)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "TrustVault <no-reply@trustvault.local>"
    # Advisory grantee suggestions are optional. Two provider styles:
    #   anthropic          -> ANTHROPIC_API_KEY (+ optional AI_MODEL)
    #   openai_compatible  -> AI_API_KEY + AI_BASE_URL + AI_MODEL (Groq, OpenRouter, Mistral, Gemini's compatibility endpoint, ...)
    AI_PROVIDER: str = "anthropic"
    ANTHROPIC_API_KEY: str = ""
    AI_API_KEY: str = ""
    AI_BASE_URL: str = ""               # must be https, e.g. https://api.groq.com/openai/v1
    AI_MODEL: str = ""                  # required for openai_compatible; anthropic defaults to claude-sonnet-4-6

    @model_validator(mode="after")
    def _ai_settings(self):
        if self.AI_PROVIDER not in ("anthropic", "openai_compatible"):
            raise ValueError("AI_PROVIDER must be 'anthropic' or 'openai_compatible'")
        if self.AI_BASE_URL and not self.AI_BASE_URL.startswith("https://"):
            raise ValueError("AI_BASE_URL must start with https://")
        return self

    @property
    def ai_model(self) -> str:
        return self.AI_MODEL or ("claude-sonnet-4-6" if self.AI_PROVIDER == "anthropic" else "")

    @property
    def ai_configured(self) -> bool:
        if self.AI_PROVIDER == "anthropic":
            return bool(self.ANTHROPIC_API_KEY)
        return bool(self.AI_API_KEY and self.AI_BASE_URL and self.AI_MODEL)

    @model_validator(mode="after")
    def _normalise(self):
        self.DATABASE_URL = normalize_db_url(self.DATABASE_URL)
        if self.STORAGE_BACKEND not in ("disk", "db"):
            raise ValueError("STORAGE_BACKEND must be 'disk' or 'db'")
        return self

    @model_validator(mode="after")
    def _production_guard_rails(self):
        """Refuse to start in production with development defaults: a weak audit key or a missing master key would
        silently void the audit guarantee / encryption at rest."""
        if self.ENVIRONMENT != "production":
            return self
        problems = []
        if self.AUDIT_HMAC_KEY in ("dev-only-change-me", "change-me-long-random-string") or len(self.AUDIT_HMAC_KEY) < 32:
            problems.append("AUDIT_HMAC_KEY must be a random string of at least 32 characters")
        try:
            if len(base64.b64decode(self.MASTER_KEY_B64)) != 32:
                raise ValueError
        except Exception:
            problems.append("MASTER_KEY_B64 must be base64 of exactly 32 random bytes")
        if not self.COOKIE_SECURE:
            problems.append("COOKIE_SECURE must be true in production (serve over HTTPS)")
        if self.DATABASE_URL.startswith("sqlite"):
            problems.append("DATABASE_URL must be PostgreSQL in production")
        if problems:
            raise ValueError("Unsafe production configuration: " + "; ".join(problems))
        return self

    @property
    def docs_enabled(self) -> bool:
        return self.ENABLE_DOCS if self.ENABLE_DOCS is not None else self.ENVIRONMENT != "production"

settings = Settings()
