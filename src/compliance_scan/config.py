"""Centralised settings loaded from environment / .env file."""
from pathlib import Path
from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Audit DB
    db_path: Path = Path("data/compliance.db")

    # ── Warn thresholds ───────────────────────────────────────────────────────
    # Decision becomes ALLOW_WITH_WARNING when hit count >= threshold.
    pii_warn_threshold: int = 1
    secret_warn_threshold: int = 1
    keyword_warn_threshold: int = 1

    # ── BLOCK thresholds ──────────────────────────────────────────────────────
    # Set to a positive integer to hard-block uploads above that hit count.
    # Set to 0 (default) to disable blocking for that category.
    #
    # block_on_secret=1  → any secret hit → HTTP 451 + BLOCK decision
    # block_on_pii=10    → 10+ PII hits   → HTTP 451 + BLOCK decision
    # block_on_structural_anomaly=True → any HIGH anomaly (ext mismatch etc.) → BLOCK
    block_on_secret: int = 1
    block_on_pii: int = 0                  # 0 = warn only, never hard-block
    block_on_structural_anomaly: bool = True

    # Anomaly heuristics
    entropy_high_threshold: float = 7.2
    size_ratio_threshold: float = 50.0
    max_archive_depth: int = 2

    # Export
    export_pseudonymise_users: bool = False

    # Custom keyword lists (comma-separated paths to YAML files)
    keyword_config_paths: list[Path] = [Path("config/keywords.yml")]


settings = Settings()
