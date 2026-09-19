"""Dates, durations and the lockout / password-expired flags must survive the
way ldap3 formats Active Directory values.

With schema information loaded (get_info=ALL, the server's setting) ldap3
already turns FILETIME attributes into datetime and tick intervals into
timedelta. Decoding them again as integers failed and every date and duration
came back as null. And AD does not keep LOCKOUT or PASSWORD_EXPIRED in the
stored userAccountControl at all - only msDS-User-Account-Control-Computed
carries them - so a locked-out account was reported as not locked out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from adds_mcp.client import to_filetime
from adds_mcp.formatting import (
    INTERVAL_NEVER,
    decode_filetime,
    format_entry,
    windows_ticks_to_timedelta,
)

from .conftest import BASE, FakeAD

PWD_SET = datetime(2026, 9, 1, 8, 30, tzinfo=UTC)
LOCKED = datetime(2026, 9, 19, 9, 15, tzinfo=UTC)
LOGON = datetime(2026, 9, 18, 17, 0, tzinfo=UTC)
EXPIRES = datetime(2027, 3, 31, 21, 0, tzinfo=UTC)
PWD_EXPIRES = datetime(2026, 11, 30, 8, 30, tzinfo=UTC)
NEVER = "9223372036854775807"

UF_LOCKOUT = 0x10
UF_PASSWORD_EXPIRED = 0x800000
TICKS_NEVER = "-9223372036854775808"


def _ft(dt: datetime) -> str:
    return str(to_filetime(dt))


def _user(fake_ad: FakeAD, login: str, **attributes: str) -> None:
    fake_ad.add(
        f"CN={login},OU=Staff,{BASE}",
        {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "objectCategory": "person",
            "cn": login,
            "sAMAccountName": login,
            "userAccountControl": "512",
            **attributes,
        },
    )


def _card(fake_ad: FakeAD, login: str) -> dict:
    result = fake_ad.call("get_user", identifier=login)
    assert result["found"] is True
    return result["user"]["attributes"]


# ------------------------------------------------------------------ dates


def test_user_dates_are_decoded(fake_ad: FakeAD) -> None:
    _user(
        fake_ad,
        "jdoe",
        pwdLastSet=_ft(PWD_SET),
        lockoutTime=_ft(LOCKED),
        lastLogonTimestamp=_ft(LOGON),
        lastLogon=_ft(LOGON),
        badPasswordTime=_ft(LOCKED),
        accountExpires=_ft(EXPIRES),
    )
    card = _card(fake_ad, "jdoe")
    assert card["pwdLastSet"] == PWD_SET.isoformat()
    assert card["lockoutTime"] == LOCKED.isoformat()
    assert card["lastLogonTimestamp"] == LOGON.isoformat()
    assert card["lastLogon"] == LOGON.isoformat()
    assert card["badPasswordTime"] == LOCKED.isoformat()
    assert card["accountExpires"] == EXPIRES.isoformat()


@pytest.mark.parametrize("raw", [NEVER, "0"])
def test_account_that_never_expires_has_no_expiry_date(fake_ad: FakeAD, raw: str) -> None:
    _user(fake_ad, "jdoe", accountExpires=raw)
    assert _card(fake_ad, "jdoe")["accountExpires"] is None


def test_password_expiry_time_is_returned(fake_ad: FakeAD) -> None:
    _user(fake_ad, "jdoe", **{"msDS-UserPasswordExpiryTimeComputed": _ft(PWD_EXPIRES)})
    assert _card(fake_ad, "jdoe")["msDS-UserPasswordExpiryTimeComputed"] == PWD_EXPIRES.isoformat()


def _computer(fake_ad: FakeAD) -> dict:
    fake_ad.add(
        f"CN=PC01,OU=Computers,{BASE}",
        {
            "objectClass": ["top", "person", "organizationalPerson", "user", "computer"],
            "objectCategory": "computer",
            "cn": "PC01",
            "sAMAccountName": "PC01$",
            "userAccountControl": "4096",
            "pwdLastSet": _ft(PWD_SET),
            "lastLogonTimestamp": _ft(LOGON),
        },
    )
    result = fake_ad.call("get_computer", identifier="PC01")
    return result.get("computer", result)["attributes"]


def test_computer_dates_are_decoded(fake_ad: FakeAD) -> None:
    card = _computer(fake_ad)
    assert card["pwdLastSet"] == PWD_SET.isoformat()
    assert card["lastLogonTimestamp"] == LOGON.isoformat()


# -------------------------------------------------------- lockout / expiry


def test_locked_out_account_is_reported_locked(fake_ad: FakeAD) -> None:
    _user(fake_ad, "locked", **{"msDS-User-Account-Control-Computed": str(UF_LOCKOUT)})
    flags = _card(fake_ad, "locked")["userAccountControl_decoded"]
    assert flags["locked_out"] is True
    assert flags["password_expired"] is False
    assert "LOCKOUT" in flags["flags"]


def test_account_with_expired_password_is_reported_expired(fake_ad: FakeAD) -> None:
    _user(fake_ad, "expired", **{"msDS-User-Account-Control-Computed": str(UF_PASSWORD_EXPIRED)})
    flags = _card(fake_ad, "expired")["userAccountControl_decoded"]
    assert flags["password_expired"] is True
    assert flags["locked_out"] is False
    assert "PASSWORD_EXPIRED" in flags["flags"]


def test_healthy_account_is_neither_locked_nor_expired(fake_ad: FakeAD) -> None:
    _user(fake_ad, "fine", **{"msDS-User-Account-Control-Computed": "0"})
    flags = _card(fake_ad, "fine")["userAccountControl_decoded"]
    assert flags["locked_out"] is False
    assert flags["password_expired"] is False
    assert flags["disabled"] is False


def test_lockout_is_unknown_where_the_computed_value_is_not_read(fake_ad: FakeAD) -> None:
    # Computer cards do not request msDS-User-Account-Control-Computed: the
    # stored userAccountControl cannot tell, so the answer is None, not False.
    flags = _computer(fake_ad)["userAccountControl_decoded"]
    assert flags["locked_out"] is None
    assert flags["password_expired"] is None
    assert flags["disabled"] is False


def test_flag_views_ignore_attribute_name_case() -> None:
    entry = {
        "dn": f"CN=x,{BASE}",
        "attributes": {
            "useraccountcontrol": 514,
            "msds-user-account-control-computed": 16,
            "grouptype": -2147483646,
        },
        "raw_attributes": {},
    }
    decoded = format_entry(entry)["attributes"]
    assert decoded["userAccountControl_decoded"]["disabled"] is True
    assert decoded["userAccountControl_decoded"]["locked_out"] is True
    assert decoded["groupType_decoded"]["scope"] == "GLOBAL"
    assert decoded["groupType_decoded"]["security"] is True


def test_only_accounts_locked_now_are_listed_as_locked_out(fake_ad: FakeAD) -> None:
    # lockoutTime stays set after a lockout has expired, until the next logon.
    _user(
        fake_ad,
        "locked",
        lockoutTime=_ft(LOCKED),
        **{"msDS-User-Account-Control-Computed": str(UF_LOCKOUT)},
    )
    _user(
        fake_ad, "expired", lockoutTime=_ft(LOCKED), **{"msDS-User-Account-Control-Computed": "0"}
    )
    result = fake_ad.call("list_locked_out_users")
    assert [u["attributes"]["sAMAccountName"] for u in result["users"]] == ["locked"]
    assert result["count"] == 1


# ------------------------------------------------------------ durations


def test_password_policy_durations_are_decoded(fake_ad: FakeAD) -> None:
    fake_ad.set_domain(
        lockoutDuration="-18000000000",  # 30 minutes
        lockoutObservationWindow="-18000000000",
        minPwdAge="-864000000000",  # 1 day
        maxPwdAge="-36288000000000",  # 42 days
        lockoutThreshold="5",
    )
    policy = fake_ad.call("get_password_policy")["policy"]["attributes"]
    assert policy["lockoutDuration"] == "PT30M"
    assert policy["lockoutObservationWindow"] == "PT30M"
    assert policy["minPwdAge"] == "P1D"
    assert policy["maxPwdAge"] == "P42D"


def test_no_limit_is_reported_as_never(fake_ad: FakeAD) -> None:
    # Passwords that never expire; a lockout only an administrator ends.
    fake_ad.set_domain(maxPwdAge=TICKS_NEVER, lockoutDuration=TICKS_NEVER, lockoutThreshold="5")
    policy = fake_ad.call("get_password_policy")["policy"]["attributes"]
    assert policy["maxPwdAge"] == INTERVAL_NEVER
    assert policy["lockoutDuration"] == INTERVAL_NEVER


def test_a_zero_interval_is_zero_not_missing(fake_ad: FakeAD) -> None:
    fake_ad.set_domain(minPwdAge="0")  # passwords may be changed at once
    policy = fake_ad.call("get_password_policy")["policy"]["attributes"]
    assert policy["minPwdAge"] == "PT0S"


def test_fine_grained_policy_durations_are_decoded(fake_ad: FakeAD) -> None:
    fake_ad.add(
        f"CN=Admins,CN=Password Settings Container,CN=System,{BASE}",
        {
            "objectClass": ["top", "msDS-PasswordSettings"],
            "cn": "Admins",
            "msDS-PasswordSettingsPrecedence": "10",
            "msDS-MinimumPasswordAge": "-864000000000",
            "msDS-MaximumPasswordAge": "-36288000000000",
            "msDS-LockoutDuration": TICKS_NEVER,
            "msDS-LockoutObservationWindow": "-18000000000",
        },
    )
    result = fake_ad.call("list_fine_grained_password_policies")
    assert result["count"] == 1
    policy = result["policies"][0]["attributes"]
    assert policy["msDS-MinimumPasswordAge"] == "P1D"
    assert policy["msDS-MaximumPasswordAge"] == "P42D"
    assert policy["msDS-LockoutDuration"] == INTERVAL_NEVER
    assert policy["msDS-LockoutObservationWindow"] == "PT30M"


# ------------------------------------------------ decoders accept ldap3 types


def test_decode_filetime_accepts_datetime() -> None:
    assert decode_filetime(PWD_SET) == PWD_SET.isoformat()
    assert decode_filetime(datetime(1601, 1, 1, tzinfo=UTC)) is None
    assert decode_filetime(datetime.max.replace(tzinfo=UTC)) is None


def test_ticks_to_duration_accepts_timedelta() -> None:
    assert windows_ticks_to_timedelta(timedelta(minutes=30)) == "PT30M"
    assert windows_ticks_to_timedelta(timedelta.max) == INTERVAL_NEVER
