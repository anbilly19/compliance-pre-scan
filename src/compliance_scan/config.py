"""Centralised settings loaded from environment / .env file."""
from pathlib import Path
from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Audit DB
    db_path: Path = Path("data/compliance.db")

    # Scanner thresholds
    pii_warn_threshold: int = 1
    secret_warn_threshold: int = 1
    keyword_warn_threshold: int = 1

    # Anomaly heuristics
    entropy_high_threshold: float = 7.2
    size_ratio_threshold: float = 50.0
    max_archive_depth: int = 2

    # Export
    export_pseudonymise_users: bool = False

    # Custom keyword lists (comma-separated paths to YAML files)
    keyword_config_paths: list[Path] = [Path("config/keywords.yml")]


settings = Settings()
