"""An in-memory Active Directory for the tests.

ldap3's MOCK_SYNC strategy with the bundled AD 2012 R2 schema formats values
the way ldap3 does against a DC reached with get_info=ALL (FILETIME attributes
as datetime, tick intervals as timedelta), with the raw bytes in
raw_attributes. Constructed attributes such as msDS-User-Account-Control-Computed
are simply stored here, as a DC would compute them. The "no-schema" variant is
what ldap3 returns without schema information.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server
from mcp.server.fastmcp import FastMCP

from adds_mcp import config as adds_config
from adds_mcp.client import ReadOnlyADClient
from adds_mcp.config import Settings
from adds_mcp.tools import register_all

BASE = "DC=example,DC=test"
BIND_DN = f"CN=svc,{BASE}"


def _settings_values() -> dict[str, Any]:
    return {
        "servers": ["dc01.example.test"],
        "bind_dn": BIND_DN,
        "bind_password": "secret",
        "base_dn": BASE,
    }


class FakeAD:
    """Holds the entries; builds a FastMCP server whose client reads them."""

    def __init__(self, with_schema: bool) -> None:
        self.with_schema = with_schema
        self.entries: list[tuple[str, dict[str, Any]]] = [
            (BASE, {"objectClass": ["top", "domain", "domainDNS"], "dc": "example"}),
        ]

    def add(self, dn: str, attributes: dict[str, Any]) -> None:
        self.entries.append((dn, attributes))

    def set_domain(self, **attributes: Any) -> None:
        self.entries[0][1].update(attributes)

    def mcp(self) -> FastMCP:
        fake = self

        class _Client(ReadOnlyADClient):
            def _connect(self) -> Connection:
                server = Server(
                    "dc01.example.test",
                    get_info=OFFLINE_AD_2012_R2 if fake.with_schema else None,
                )
                conn = Connection(
                    server, user=BIND_DN, password="secret", client_strategy=MOCK_SYNC
                )
                conn.strategy.add_entry(
                    BIND_DN,
                    {"objectClass": ["top", "person", "user"], "userPassword": "secret"},
                    validate=False,
                )
                for dn, attributes in fake.entries:
                    # validate=False: store the values exactly as a DC holds them.
                    conn.strategy.add_entry(dn, attributes, validate=False)
                conn.bind()
                return conn

        settings = Settings(**_settings_values(), _env_file=None)
        server = FastMCP(name="adds-mcp-test")
        register_all(server, _Client(settings))
        return server

    def call(self, tool: str, **arguments: Any) -> dict[str, Any]:
        _content, structured = asyncio.run(self.mcp().call_tool(tool, arguments))
        return structured.get("result", structured)


@pytest.fixture(params=["schema", "no-schema"])
def fake_ad(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tmp_path) -> FakeAD:
    # Some tools (domain, GPO) read the module-level settings, which come from
    # the environment and a .env in the working directory: pin them.
    for name in [n for n in os.environ if n.startswith("ADDS_")]:
        monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)
    for field, value in _settings_values().items():
        monkeypatch.setattr(adds_config.settings, field, value)
    return FakeAD(with_schema=request.param == "schema")
