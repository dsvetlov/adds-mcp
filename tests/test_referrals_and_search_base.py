"""The server must never follow referrals and must refuse search bases outside
the directory it serves.

ldap3's defaults follow a referral to any host and simple-bind there with the
service account's credentials, so a model-supplied base_dn such as
"DC=evil,DC=example" would hand the password to that host. The end-to-end
proof is in test_referral_leak_e2e.py; these tests pin the pieces.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from adds_mcp import client as client_module
from adds_mcp.client import (
    ReadOnlyADClient,
    ReferralNotFollowed,
    SearchBaseOutOfScope,
    dn_within,
)
from adds_mcp.config import Settings
from adds_mcp.tools import register_all

FOREST = "DC=example,DC=test"
CHILD = f"DC=child,{FOREST}"
# A single-domain forest: every naming context lies under the domain.
FOREST_NCS = [
    FOREST,
    f"CN=Configuration,{FOREST}",
    f"CN=Schema,CN=Configuration,{FOREST}",
    f"DC=DomainDnsZones,{FOREST}",
    f"DC=ForestDnsZones,{FOREST}",
]
# A DC of the child domain: Configuration and Schema live under the forest root,
# not under the configured base DN.
CHILD_NCS = [
    CHILD,
    f"CN=Configuration,{FOREST}",
    f"CN=Schema,CN=Configuration,{FOREST}",
    f"DC=ForestDnsZones,{FOREST}",
]
WKGUID_USERS = "a9d1ca15768811d1aded00c04fd8d5cd"


def _settings(base_dn: str = FOREST, port: int = 636) -> Settings:
    return Settings(
        servers=["dc01.example.test"],
        port=port,
        bind_dn=f"CN=svc,{base_dn}",
        bind_password="secret",
        base_dn=base_dn,
        _env_file=None,
    )


class _FakeConnection:
    """Stands in for a bound SAFE_SYNC ldap3 connection.

    Records the search bases it receives and answers with the scripted pages
    (each a (result, response) pair), or with an empty success.
    """

    bound = True
    check_names = False

    def __init__(
        self,
        naming_contexts: list[str] | None,
        pages: list[tuple[dict[str, Any], list[dict[str, Any]]]] | None = None,
        root_domain: str | None = None,
    ) -> None:
        info = None
        if naming_contexts is not None:
            other = {"rootDomainNamingContext": [root_domain]} if root_domain else {}
            info = SimpleNamespace(naming_contexts=naming_contexts, other=other)
        self.server = SimpleNamespace(info=info)
        self.searches: list[str] = []
        self.cookies: list[Any] = []
        self._pages = list(pages or [])

    def search(self, *, search_base: str, paged_cookie: Any = None, **_kw: Any):
        self.searches.append(search_base)
        self.cookies.append(paged_cookie)
        if self._pages:
            result, response = self._pages.pop(0)
        else:
            result, response = {"result": 0, "referrals": None}, []
        return True, result, response, None


def _client_with(conn: _FakeConnection, settings: Settings | None = None) -> ReadOnlyADClient:
    ad = ReadOnlyADClient(settings or _settings())
    ad._connection = conn  # already "bound": no network
    return ad


def _search(ad: ReadOnlyADClient, base: str | None) -> list[dict[str, Any]]:
    return ad.search(search_filter="(objectClass=*)", base_dn=base)


# ------------------------------------------------------------ referrals are off


def test_servers_allow_no_referral_hosts() -> None:
    pool = ReadOnlyADClient(_settings())._build_pool()
    assert pool.servers, "the pool must hold the configured servers"
    for server in pool.servers:
        assert server.allowed_referral_hosts == []


def test_connection_does_not_chase_referrals(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    class _RecordingConnection:
        def __init__(self, *_args, **kwargs) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(client_module, "Connection", _RecordingConnection)
    ReadOnlyADClient(_settings())._connect()
    assert captured.get("auto_referrals") is False


def test_a_referral_answer_is_an_error_not_an_empty_result() -> None:
    # e.g. a child-domain base under a forest-root base DN, on a DC that does
    # not hold the child domain.
    referral = {"result": 10, "referrals": [f"ldap://child.example.test/OU=Staff,{CHILD}"]}
    conn = _FakeConnection(FOREST_NCS, pages=[(referral, [])])
    with pytest.raises(ReferralNotFollowed, match="child.example.test"):
        _search(_client_with(conn), f"OU=Staff,{CHILD}")


def test_referral_not_followed_is_a_runtime_error_like_other_search_failures() -> None:
    assert issubclass(ReferralNotFollowed, RuntimeError)


def _entries(*names: str) -> list[dict[str, Any]]:
    return [{"type": "searchResEntry", "dn": f"CN={n},{FOREST}", "attributes": {}} for n in names]


def test_pages_are_followed_in_order() -> None:
    page_1 = (
        {"result": 0, "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b"next"}}}},
        _entries("a1", "a2"),
    )
    page_2 = (
        {"result": 0, "controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": b""}}}},
        _entries("b1", "b2"),
    )
    conn = _FakeConnection(FOREST_NCS, pages=[page_1, page_2])
    found = _search(_client_with(conn), None)
    assert [entry["dn"] for entry in found] == [e["dn"] for e in _entries("a1", "a2", "b1", "b2")]
    assert conn.cookies == [None, b"next"]


# ----------------------------------------------------------- search-base scope


@pytest.mark.parametrize(
    "base",
    [
        None,  # the configured default
        FOREST,
        f"OU=Staff,{FOREST}",
        "ou=staff,dc=EXAMPLE,dc=test",  # attribute names and values are case-insensitive
        f"OU=Sales\\ ,{FOREST}",  # an escaped trailing space, as AD writes it
        f"CN=Sites,CN=Configuration,{FOREST}",
        "<GUID=5f7ae1f2-3d1c-4e5a-9d1c-1b2a3c4d5e6f>",  # names an object, not a place
        "<SID=S-1-5-21-1-2-3-500>",
        f"<WKGUID={WKGUID_USERS},{FOREST}>",
    ],
)
def test_bases_inside_the_directory_are_searched(base: str | None) -> None:
    conn = _FakeConnection(FOREST_NCS)
    _search(_client_with(conn), base)
    assert conn.searches == [base or FOREST]


@pytest.mark.parametrize(
    "base",
    [
        "DC=evil,DC=example",
        "DC=example,DC=test,DC=evil",  # the configured base as a prefix is not enough
        "DC=notexample,DC=test",  # nor a look-alike RDN
        "DC=evil,DC=example+DC=test",  # nor multi-valued RDNs that list the same pairs
        "DC=evil+DC=example,DC=test",
        "OU=x\\,DC=example,DC=test",  # one RDN "OU=x,DC=example" directly under DC=test
        f"<WKGUID={WKGUID_USERS},DC=evil,DC=example>",
        "<FOO=bar>",
        "not a dn",
    ],
)
def test_bases_outside_the_directory_are_refused_before_any_request(base: str) -> None:
    conn = _FakeConnection(FOREST_NCS)
    with pytest.raises(SearchBaseOutOfScope):
        _search(_client_with(conn), base)
    assert conn.searches == []


def test_out_of_scope_is_a_runtime_error_like_other_search_failures() -> None:
    # Tools such as list_fsmo_roles report RuntimeError per lookup.
    assert issubclass(SearchBaseOutOfScope, RuntimeError)


def test_naming_contexts_extend_the_scope_beyond_the_base_dn() -> None:
    # In a child domain the Configuration partition is not under ADDS_BASE_DN;
    # it is allowed because the DC advertises it.
    sites = f"CN=Sites,CN=Configuration,{FOREST}"
    conn = _FakeConnection(CHILD_NCS)
    _search(_client_with(conn, _settings(CHILD)), sites)
    assert conn.searches == [sites]


def test_without_server_info_only_the_configured_base_is_allowed() -> None:
    sites = f"CN=Sites,CN=Configuration,{FOREST}"
    ad = _client_with(_FakeConnection(None), _settings(CHILD))
    _search(ad, f"OU=Staff,{CHILD}")
    with pytest.raises(SearchBaseOutOfScope):
        _search(ad, sites)


def test_a_partition_the_dc_does_not_hold_is_refused() -> None:
    conn = _FakeConnection(CHILD_NCS, root_domain=FOREST)
    with pytest.raises(SearchBaseOutOfScope):
        _search(_client_with(conn, _settings(CHILD)), f"OU=Staff,{FOREST}")


@pytest.mark.parametrize("port", [3268, 3269])
def test_a_global_catalog_answers_for_the_forest_root_domain(port: int) -> None:
    conn = _FakeConnection(CHILD_NCS, root_domain=FOREST)
    _search(_client_with(conn, _settings(CHILD, port)), f"OU=Staff,{FOREST}")
    assert conn.searches == [f"OU=Staff,{FOREST}"]


def test_the_refusal_lists_each_allowed_root_once() -> None:
    conn = _FakeConnection(FOREST_NCS)  # the base DN is also the first naming context
    with pytest.raises(SearchBaseOutOfScope) as refused:
        _search(_client_with(conn), "DC=evil,DC=example")
    allowed = str(refused.value).split("allowed: ", 1)[1].rstrip(").").split(", ")
    assert [root.lower() for root in allowed] == [root.lower() for root in FOREST_NCS]


@pytest.mark.parametrize(
    ("dn", "root", "expected"),
    [
        (FOREST, FOREST, True),
        (f"CN=a,OU=b,{FOREST}", FOREST, True),
        (f"CN=a\\,b,{FOREST}", FOREST, True),  # an escaped comma stays inside its RDN
        ("DC=test", FOREST, False),
        ("DC=evil,DC=example", FOREST, False),
        ("OU=x+DC=example,DC=test", FOREST, False),
    ],
)
def test_dn_within(dn: str, root: str, expected: bool) -> None:
    assert dn_within(dn, root) is expected


def test_a_cross_domain_gpo_link_is_reported_on_that_link() -> None:
    # An OU of the forest root links a GPO of the child domain; the DC refers
    # the GPO lookup elsewhere. The tool must still list the links.
    ou = f"OU=Staff,{FOREST}"
    gpo = f"cn={{11111111-2222-3333-4444-555555555555}},cn=policies,cn=system,{CHILD}"
    ou_page = (
        {"result": 0},
        [
            {
                "type": "searchResEntry",
                "dn": ou,
                "attributes": {"distinguishedName": ou, "gPLink": f"[LDAP://{gpo};0]"},
                "raw_attributes": {},
            }
        ],
    )
    referral = ({"result": 10, "referrals": [f"ldap://child.example.test/{gpo}"]}, [])
    conn = _FakeConnection(FOREST_NCS, pages=[ou_page, referral])
    server = FastMCP(name="t")
    register_all(server, _client_with(conn))
    _content, structured = asyncio.run(server.call_tool("list_links_on_ou", {"dn": ou}))
    result = structured.get("result", structured)
    assert result["count"] == 1
    link = result["links"][0]
    assert link["gpo_dn"] == gpo
    assert "referred" in link["error"]
