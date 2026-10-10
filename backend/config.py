import os
from functools import lru_cache
from dotenv import load_dotenv

load_dotenv()


class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    FRONTEND_ORIGIN: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./siem.db")
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
    RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    SIMULATION_MODE: bool = os.getenv("APEXSIEM_SIMULATION_MODE", "false").strip().lower() in {"1", "true", "yes", "on"}

    def validate_required(self):
        errors = []
        if not self.SECRET_KEY:
            errors.append("SECRET_KEY environment variable is required")
        if not self.GROQ_API_KEY:
            errors.append("GROQ_API_KEY environment variable is required for AI analysis")
        if errors:
            raise RuntimeError("Configuration validation failed:\n" + "\n".join(errors))


@lru_cache
def get_settings() -> Settings:
    return Settings()
