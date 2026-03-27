"""
TorrentVault — Configuration
All settings are read from environment variables with secure defaults.
"""

import os
import secrets
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Security ──────────────────────────────────────────────────────────────
    secret_key: str = secrets.token_hex(32)
    admin_password_hash: str = "$2b$12$Z05bnBMUOMIOiYr/2QIojO6ZAcRYveNNOGih6h59PuC.7U5KujZIq"  # "changeme"
    domain: str = "localhost"

    # ── Login security ────────────────────────────────────────────────────────
    max_failed_logins: int = 5
    lockout_duration_minutes: int = 15

    # ── Network ───────────────────────────────────────────────────────────────
    allowed_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]
    allowed_hosts: list[str] = ["localhost", "127.0.0.1"]

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./data/torrentvault.db"

    # ── Storage ───────────────────────────────────────────────────────────────
    download_dir: str = str(Path.home() / "Downloads")

    # ── libtorrent ────────────────────────────────────────────────────────────
    listen_port_min: int = 6881
    listen_port_max: int = 6891

    # ── Tier defaults ─────────────────────────────────────────────────────────
    free_tier_max_torrents: int = 3
    free_tier_speed_cap_kbps: int = 500

    # ── Invite system ─────────────────────────────────────────────────────────
    require_invite_code: bool = False

    # ── API key ───────────────────────────────────────────────────────────────
    api_key_header: str = "X-API-Key"

    @property
    def listen_ports(self) -> tuple[int, int]:
        return (self.listen_port_min, self.listen_port_max)

    @property
    def users(self) -> dict[str, str]:
        return {"admin": self.admin_password_hash}

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }


settings = Settings()
