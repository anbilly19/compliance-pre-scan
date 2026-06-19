"""Centralised settings loaded from environment / .env file."""
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Audit DB
    db_path: Path = Path("data/compliance.db")

    # Scanner thresholds
    pii_warn_threshold: int = 1   # warn after N PII hits
    secret_warn_threshold: int = 1
    keyword_warn_threshold: int = 1

    # Anomaly heuristics
    entropy_high_threshold: float = 7.2   # bits/byte (max is 8)
    size_ratio_threshold: float = 50.0    # bytes-per-text-char; above = suspicious
    max_archive_depth: int = 2

    # Export
    export_pseudonymise_users: bool = False  # set True in production

    # Custom keyword lists (comma-separated paths to YAML files)
    keyword_config_paths: list[Path] = [Path("config/keywords.yml")]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
