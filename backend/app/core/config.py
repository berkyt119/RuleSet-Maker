from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Dogma VPN Ruleset"
    secret_key: str = "change-me-in-production"
    access_token_expire_minutes: int = 720
    database_url: str = "sqlite:///./dogma_vpn.db"
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "admin12345A!"
    prefix_finder_timeout_seconds: int = 45
    enable_browser_discovery: bool = True
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    domain_json_export_token: str = ""
    domain_json_export_path: str = "/home/opencode/dogma_vpn/exports/domains-export.json"
    ruleset_output_path: str = "/var/www/files/data.json"
    ruleset_archive_dir: str = "/var/www/files"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
