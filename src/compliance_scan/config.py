from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    db_path: Path = Path("./compliance_audit.db")
    pii_warn_threshold: int = 1
    secret_warn_threshold: int = 1
    anomaly_entropy_threshold: float = 7.2
    anomaly_size_ratio: float = 10.0
    export_pseudonymise_users: bool = True
    keyword_rules_dir: Path = Path("./rules/keywords")
    secret_rules_file: Path = Path("./rules/secrets/patterns.yaml")


settings = Settings()
