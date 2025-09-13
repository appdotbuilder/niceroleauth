"""Configuration management for the NiceGUI authentication application."""

import os
from datetime import timedelta


class Config:
    """Application configuration."""

    # Database configuration
    DATABASE_URL: str = os.environ.get("APP_DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/postgres")

    # Security configuration
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production")
    SESSION_DURATION_HOURS: int = int(os.environ.get("SESSION_DURATION_HOURS", "24"))
    PASSWORD_MIN_LENGTH: int = int(os.environ.get("PASSWORD_MIN_LENGTH", "6"))

    # Application configuration
    APP_NAME: str = os.environ.get("APP_NAME", "NiceGUI Auth App")
    DEBUG: bool = os.environ.get("DEBUG", "false").lower() == "true"

    @classmethod
    def get_session_duration(cls) -> timedelta:
        """Get session duration as timedelta."""
        return timedelta(hours=cls.SESSION_DURATION_HOURS)
