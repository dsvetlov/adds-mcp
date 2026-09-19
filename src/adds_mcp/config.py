"""Configuration loaded from environment variables."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ADDS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    servers: Annotated[list[str], NoDecode] = Field(default_factory=list)
    port: int = 636
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    domain: str = ""

    tls_validate: bool = True
    ca_cert_file: str = ""

    http_host: str = "127.0.0.1"
    http_port: int = 8080

    max_page_size: int = 500
    default_page_size: int = 50
    query_timeout_seconds: int = 30

    @field_validator("servers", mode="before")
    @classmethod
    def _split_servers(cls, v: object) -> object:
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v

    def require_ready(self) -> None:
        missing = [
            name
            for name, value in {
                "ADDS_SERVERS": self.servers,
                "ADDS_BIND_DN": self.bind_dn,
                "ADDS_BIND_PASSWORD": self.bind_password,
                "ADDS_BASE_DN": self.base_dn,
            }.items()
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Active Directory MCP server is missing required configuration: "
                + ", ".join(missing)
                + ". Populate them in the environment or .env file."
            )


settings = Settings()
