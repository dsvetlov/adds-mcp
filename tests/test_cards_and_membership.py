"""The deployment-branch shaping: group listings that filter and page, cards
that carry sizes instead of huge lists, all readable attributes minus
credentials, and a bind that is not retried after it is rejected.
"""

from __future__ import annotations

from typing import Any

import pytest
from ldap3.core.exceptions import LDAPBindError

from adds_mcp.client import CredentialsRejected, ReadOnlyADClient
from adds_mcp.config import Settings
from adds_mcp.formatting import format_entry

from .conftest import BASE, BIND_DN, FakeAD


def _group(fake: FakeAD, cn: str, **attrs: Any) -> str:
    dn = f"CN={cn},OU=Groups,{BASE}"
    fake.add(
        dn,
        {
            "objectClass": ["top", "group"],
            "objectCategory": "group",
            "cn": cn,
            "sAMAccountName": cn,
            **attrs,
        },
    )
    return dn


def _user(fake: FakeAD, login: str, **attrs: Any) -> str:
    dn = f"CN={login},OU=Staff,{BASE}"
    fake.add(
        dn,
        {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "objectCategory": "person",
            "cn": login,
            "sAMAccountName": login,
            **attrs,
        },
    )
    return dn


# ---------------------------------------------------------- group listing


def test_user_groups_filter_by_name(fake_ad: FakeAD) -> None:
    user_dn = _user(fake_ad, "jdoe")
    _group(fake_ad, "ROLE_Global_Dev", member=[user_dn])
    _group(fake_ad, "Printer-Floor-3", member=[user_dn])
    result = fake_ad.call("list_user_groups", identifier="jdoe", name_filter="ROLE_")
    names = [g["attributes"]["sAMAccountName"] for g in result["groups"]]
    assert names == ["ROLE_Global_Dev"]
    assert result["truncated"] is False


def test_user_groups_are_capped_and_flagged(fake_ad: FakeAD) -> None:
    user_dn = _user(fake_ad, "jdoe")
    for i in range(5):
        _group(fake_ad, f"G{i}", member=[user_dn])
    result = fake_ad.call("list_user_groups", identifier="jdoe", limit=3)
    assert result["count"] == 3
    assert len(result["groups"]) == 3
    assert result["truncated"] is True


# ------------------------------------------------------------- card sizes


def test_user_card_carries_group_count_not_the_list(fake_ad: FakeAD) -> None:
    groups = [f"CN=G{i},OU=Groups,{BASE}" for i in range(120)]
    _user(fake_ad, "heavy", memberOf=groups)
    card = fake_ad.call("get_user", identifier="heavy")["user"]["attributes"]
    assert card["memberOf_count"] == 120
    assert "memberOf" not in card


def test_group_card_carries_member_count_not_the_list(fake_ad: FakeAD) -> None:
    members = [f"CN=U{i},OU=Staff,{BASE}" for i in range(300)]
    _group(fake_ad, "BigGroup", member=members, description="big")
    card = fake_ad.call("get_group", identifier="BigGroup")["group"]["attributes"]
    assert card["member_count"] == 300
    assert "member" not in card
    assert card["description"] == "big"


def test_group_members_limit_and_truncated(fake_ad: FakeAD) -> None:
    group_dn = _group(fake_ad, "Team")
    for i in range(5):
        _user(fake_ad, f"m{i}", memberOf=[group_dn])
    page = fake_ad.call("list_group_members", identifier="Team", limit=2)
    assert page["count"] == 2 and page["truncated"] is True
    assert len(page["members"]) == 2
    whole = fake_ad.call("list_group_members", identifier="Team", limit=10)
    assert whole["count"] == 5 and whole["truncated"] is False


# --------------------------------------------------- attributes / credentials


def test_credential_attributes_are_never_returned() -> None:
    entry = {
        "dn": f"CN=PC01,{BASE}",
        "attributes": {
            "cn": "PC01",
            "ms-Mcs-AdmPwd": "S3cr3t!",  # LAPS
            "msFVE-RecoveryPassword": "123456-...",  # BitLocker
            "unicodePwd": "x",
        },
        "raw_attributes": {},
    }
    out = format_entry(entry)["attributes"]
    assert out == {"cn": "PC01"}


def test_large_binary_is_summarised_not_dumped() -> None:
    photo = bytes(range(256)) * 8  # 2 KiB of non-UTF-8 bytes
    entry = {
        "dn": f"CN=jdoe,{BASE}",
        "attributes": {"thumbnailPhoto": photo, "cn": "jdoe"},
        "raw_attributes": {},
    }
    out = format_entry(entry)["attributes"]
    assert out["thumbnailPhoto"] == f"<binary, {len(photo)} bytes>"


# ------------------------------------------------ bind is not retried


def _rejecting_client() -> ReadOnlyADClient:
    settings = Settings(
        servers=["dc"], bind_dn=BIND_DN, bind_password="wrong", base_dn=BASE, _env_file=None
    )

    class _Client(ReadOnlyADClient):
        binds = 0

        def _connect(self):  # type: ignore[override]
            type(self).binds += 1
            raise LDAPBindError("invalidCredentials")

    return _Client(settings)


def test_bind_is_not_retried_after_rejection() -> None:
    ad = _rejecting_client()
    with pytest.raises(CredentialsRejected):
        ad.search(search_filter="(objectClass=*)")
    with pytest.raises(CredentialsRejected):
        ad.search(search_filter="(objectClass=*)")
    assert type(ad).binds == 1  # the second call did not bind again


def test_http_host_defaults_to_loopback() -> None:
    assert Settings(_env_file=None).http_host == "127.0.0.1"


def test_computer_card_has_no_computed_lockout(fake_ad: FakeAD) -> None:
    # Computer accounts do not lock out; get_computer does not request the
    # computed value, so locked_out / password_expired are unknown (None).
    fake_ad.add(
        f"CN=PC9,OU=Computers,{BASE}",
        {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "objectCategory": "computer",
            "cn": "PC9",
            "sAMAccountName": "PC9$",
            "userAccountControl": "4096",
        },
    )
    result = fake_ad.call("get_computer", identifier="PC9")
    flags = result.get("computer", result)["attributes"]["userAccountControl_decoded"]
    assert flags["locked_out"] is None and flags["password_expired"] is None


def test_dpapi_and_credential_roaming_attributes_are_withheld() -> None:
    entry = {
        "dn": f"CN=x,{BASE}",
        "attributes": {
            "cn": "x",
            "ms-PKI-AccountCredentials": "blob",
            "ms-PKI-DPAPIMasterKeys": "blob",
        },
        "raw_attributes": {},
    }
    assert format_entry(entry)["attributes"] == {"cn": "x"}


def test_transient_bind_failure_is_not_latched() -> None:
    from ldap3.core.exceptions import LDAPSocketOpenError

    settings = Settings(
        servers=["dc"], bind_dn=BIND_DN, bind_password="x", base_dn=BASE, _env_file=None
    )

    class _Client(ReadOnlyADClient):
        attempts = 0

        def _connect(self):  # type: ignore[override]
            type(self).attempts += 1
            raise LDAPSocketOpenError("connection refused")

    ad = _Client(settings)
    for _ in range(2):
        with pytest.raises(LDAPSocketOpenError):
            ad.search(search_filter="(objectClass=*)")
    assert type(ad).attempts == 2  # a transient failure is retried, not latched
