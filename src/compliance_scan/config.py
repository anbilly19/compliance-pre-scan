"""Centralised settings loaded from environment / .env file."""
from pathlib import Path
from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Audit DB
    db_path: Path = Path("data/compliance.db")

    # ── Warn thresholds ───────────────────────────────────────────────────────
    pii_warn_threshold: int = 1
    secret_warn_threshold: int = 1
    keyword_warn_threshold: int = 1

    # ── BLOCK thresholds ──────────────────────────────────────────────────────
    block_on_secret: int = 1
    block_on_pii: int = 0
    block_on_structural_anomaly: bool = True

    # ── Hit masking (Phase 11) ────────────────────────────────────────────────
    # False (default) — full snippets stored and returned; useful for dev/test
    # True            — snippets masked before DB write + API response; use in production
    #
    # PII:    keep first 2 + last 2 chars  e.g. 'max.mustermann@firma.de' → 'ma***de'
    # SECRET: keep first 4 chars only      e.g. 'AKIAIOSFODNN7EXAMPLE'   → 'AKIA****'
    # KEYWORD / ANOMALY: pass through unchanged
    mask_snippets: bool = False

    # Anomaly heuristics
    entropy_high_threshold: float = 7.2
    size_ratio_threshold: float = 50.0
    max_archive_depth: int = 2

    # Export
    export_pseudonymise_users: bool = False

    # Custom keyword lists
    keyword_config_paths: list[Path] = [Path("config/keywords.yml")]


settings = Settings()
