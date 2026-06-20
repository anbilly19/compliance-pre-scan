"""Centralised settings loaded from environment / .env file."""
from pathlib import Path
from typing import Optional
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
    mask_snippets: bool = False

    # ── OPA / Rego policy engine (Phase 12) ───────────────────────────────────
    # Leave empty (default) to use the inline Python fallback.
    # Set to the OPA server base URL to use OPA for policy decisions.
    # Example: OPA_URL=http://localhost:8181
    opa_url: Optional[str] = None
    opa_timeout_s: float = 2.0

    # Anomaly heuristics
    entropy_high_threshold: float = 7.2
    size_ratio_threshold: float = 50.0
    max_archive_depth: int = 2

    # Export
    export_pseudonymise_users: bool = False

    # Custom keyword lists
    keyword_config_paths: list[Path] = [Path("config/keywords.yml")]


settings = Settings()
