import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    LLM_MODEL: str = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4-5-20250929")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))

    TOOLS_CONTAINER: str = os.getenv("TOOLS_CONTAINER", "shadowpulse-tools")

    # Default to local Postgres (outside docker). Docker compose overrides DATABASE_URL to use host "postgres".
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://shadowpulse:shadowpulse@localhost:5432/shadowpulse",
    )

    SCAN_OUTPUT_DIR: str = os.getenv("SCAN_OUTPUT_DIR", "/data/scans")

    # Concurrency limits
    MAX_CONCURRENT_JOBS_GLOBAL: int = int(os.getenv("MAX_CONCURRENT_JOBS_GLOBAL", "5"))
    MAX_CONCURRENT_JOBS_PER_TARGET: int = int(os.getenv("MAX_CONCURRENT_JOBS_PER_TARGET", "2"))

    # Retention policy
    RETENTION_RAW_OUTPUT_DAYS: int = int(os.getenv("RETENTION_RAW_OUTPUT_DAYS", "30"))
    RETENTION_COMPLETED_RUNS_DAYS: int = int(os.getenv("RETENTION_COMPLETED_RUNS_DAYS", "90"))

    # CORS origins for frontend
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


settings = Settings()

# Ensure API keys are available as env vars for LiteLLM
# (LiteLLM reads directly from os.environ, not from our Settings object)
if settings.ANTHROPIC_API_KEY:
    os.environ["ANTHROPIC_API_KEY"] = settings.ANTHROPIC_API_KEY
if settings.OPENAI_API_KEY:
    os.environ["OPENAI_API_KEY"] = settings.OPENAI_API_KEY
