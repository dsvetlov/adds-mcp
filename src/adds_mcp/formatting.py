"""Helpers for decoding Active Directory-specific attribute formats."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

# userAccountControl flag definitions.
# https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol
UAC_FLAGS: dict[int, str] = {
    0x00000001: "SCRIPT",
    0x00000002: "ACCOUNTDISABLE",
    0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQ_PREAUTH",
    0x00800000: "PASSWORD_EXPIRED",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}

# groupType flag definitions.
# https://learn.microsoft.com/windows/win32/adschema/a-grouptype
GROUP_TYPE_FLAGS: dict[int, str] = {
    0x00000001: "SYSTEM",
    0x00000002: "GLOBAL",
    0x00000004: "DOMAIN_LOCAL",
    0x00000008: "UNIVERSAL",
    0x00000010: "APP_BASIC",
    0x00000020: "APP_QUERY",
    0x80000000: "SECURITY",  # otherwise DISTRIBUTION
}

# Trust attributes/direction/type
TRUST_DIRECTION = {0: "DISABLED", 1: "INBOUND", 2: "OUTBOUND", 3: "BIDIRECTIONAL"}
TRUST_TYPE = {1: "WINDOWS_NON_AD", 2: "WINDOWS_AD", 3: "MIT", 4: "DCE"}

# 100-nanosecond intervals between 1601-01-01 (Windows epoch) and 1970-01-01 (Unix epoch).
_FILETIME_EPOCH_DELTA = 116444736000000000
# Sentinel value used by AD for "never" / unset.
_FILETIME_NEVER = {0, 0x7FFFFFFFFFFFFFFF, -1}
# Tick intervals use the most negative 64-bit value for "no limit": maxPwdAge
# when passwords never expire, lockoutDuration when only an administrator ends
# a lockout. Reported as INTERVAL_NEVER.
_INTERVAL_NEVER = -0x8000000000000000
INTERVAL_NEVER = "never"

# Bits AD reports only in the constructed msDS-User-Account-Control-Computed,
# never in the stored userAccountControl.
_UF_LOCKOUT = 0x0010
_UF_PASSWORD_EXPIRED = 0x800000


def decode_sid(raw: bytes) -> str | None:
    """Decode a binary SID into the standard S-1-... string."""
    if not raw or len(raw) < 8:
        return None
    revision = raw[0]
    sub_authority_count = raw[1]
    # 6-byte big-endian identifier authority.
    identifier_authority = int.from_bytes(raw[2:8], byteorder="big")
    parts = [f"S-{revision}", str(identifier_authority)]
    for i in range(sub_authority_count):
        offset = 8 + 4 * i
        if offset + 4 > len(raw):
            break
        parts.append(str(int.from_bytes(raw[offset : offset + 4], byteorder="little")))
    return "-".join(parts)


def decode_guid(raw: bytes) -> str | None:
    """Decode a binary objectGUID into a string GUID."""
    if not raw or len(raw) != 16:
        return None
    return str(uuid.UUID(bytes_le=raw))


def decode_filetime(value: Any) -> str | None:
    """Decode an AD Windows FILETIME 18-digit integer into ISO-8601 UTC.

    format_entry passes the raw value. For callers holding ldap3's formatted
    value instead, a datetime is accepted too (0 comes out as 1601-01-01 and
    "never" as datetime.max; both give None, as their integers do).
    """
    if isinstance(value, datetime):
        if value.year <= 1601 or value.year >= 9999:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    if value in (None, "", 0, "0"):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n in _FILETIME_NEVER:
        return None
    seconds = (n - _FILETIME_EPOCH_DELTA) / 10_000_000
    try:
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    except (OverflowError, OSError):
        return None
    return dt.isoformat()


def decode_generalized_time(value: Any) -> str | None:
    """Decode an AD generalizedTime (e.g. whenCreated) into ISO-8601 UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    s = str(value)
    # Standard format: YYYYMMDDHHMMSS.0Z
    try:
        clean = s.rstrip("Z").split(".")[0]
        dt = datetime.strptime(clean, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return s


def decode_uac(value: Any, computed: Any = None) -> dict[str, Any] | None:
    """Decode a userAccountControl integer into a dict with raw + flags + booleans.

    AD does not keep LOCKOUT or PASSWORD_EXPIRED in the stored userAccountControl;
    it reports them only in the constructed msDS-User-Account-Control-Computed,
    passed here as ``computed``. ``locked_out`` and ``password_expired`` come from
    it and are None when it was not retrieved.
    """
    if value is None:
        return None
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return None
    try:
        computed_raw = None if computed is None else int(computed)
    except (TypeError, ValueError):
        computed_raw = None
    # LOCKOUT and PASSWORD_EXPIRED can only come from the computed value.
    reported = raw | ((computed_raw or 0) & (_UF_LOCKOUT | _UF_PASSWORD_EXPIRED))
    flags = [name for bit, name in UAC_FLAGS.items() if reported & bit]
    return {
        "raw": raw,
        "flags": flags,
        "disabled": bool(raw & 0x0002),
        "locked_out": None if computed_raw is None else bool(computed_raw & _UF_LOCKOUT),
        "password_never_expires": bool(raw & 0x10000),
        "password_expired": (
            None if computed_raw is None else bool(computed_raw & _UF_PASSWORD_EXPIRED)
        ),
        "smartcard_required": bool(raw & 0x40000),
        "trusted_for_delegation": bool(raw & 0x80000),
        "dont_require_preauth": bool(raw & 0x400000),
    }


def decode_group_type(value: Any) -> dict[str, Any] | None:
    """Decode a groupType integer into scope + security/distribution flags."""
    if value is None:
        return None
    try:
        # groupType is a signed 32-bit int in AD but ldap3 usually returns it as int.
        raw = struct.unpack("<i", struct.pack("<I", int(value) & 0xFFFFFFFF))[0]
    except (TypeError, ValueError, struct.error):
        return None
    unsigned = raw & 0xFFFFFFFF
    flags = [name for bit, name in GROUP_TYPE_FLAGS.items() if unsigned & bit]
    if unsigned & 0x00000002:
        scope = "GLOBAL"
    elif unsigned & 0x00000004:
        scope = "DOMAIN_LOCAL"
    elif unsigned & 0x00000008:
        scope = "UNIVERSAL"
    else:
        scope = "UNKNOWN"
    return {
        "raw": raw,
        "flags": flags,
        "scope": scope,
        "security": bool(unsigned & 0x80000000),
        "distribution": not bool(unsigned & 0x80000000),
    }


def windows_ticks_to_timedelta(value: Any) -> str | None:
    """Convert a negative Windows tick interval (e.g. lockoutDuration) into an ISO duration.

    The "no limit" value is returned as INTERVAL_NEVER ("never"), zero as "PT0S".
    format_entry passes the raw value; for callers holding ldap3's formatted
    value instead, a timedelta is accepted too (timedelta.max is "no limit").
    """
    if isinstance(value, timedelta):
        if value == timedelta.max:
            return INTERVAL_NEVER
        return _iso_duration(abs(value.total_seconds()))
    if value is None or value == "":
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n == _INTERVAL_NEVER:
        return INTERVAL_NEVER
    # AD stores these as negative 100-nanosecond intervals.
    return _iso_duration(abs(n) / 10_000_000)


def _iso_duration(seconds: float) -> str:
    if seconds == 0:
        return "PT0S"
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}D")
    time_parts = []
    if hours:
        time_parts.append(f"{hours}H")
    if minutes:
        time_parts.append(f"{minutes}M")
    if secs:
        time_parts.append(f"{secs}S")
    duration = "P" + "".join(parts)
    if time_parts:
        duration += "T" + "".join(time_parts)
    return duration if duration != "P" else "PT0S"


# Attributes that should be interpreted with specific decoders.
_SID_ATTRS = {"objectsid", "sidhistory"}
_GUID_ATTRS = {"objectguid"}
_FILETIME_ATTRS = {
    "msds-userpasswordexpirytimecomputed",
    "lastlogontimestamp",
    "lastlogon",
    "pwdlastset",
    "accountexpires",
    "badpasswordtime",
    "lockouttime",
    "lastlogoff",
    "ms-mcs-admpwdexpirationtime",
}
_GENTIME_ATTRS = {"whencreated", "whenchanged"}
_INTERVAL_ATTRS = {
    "lockoutduration",
    "lockoutobservationwindow",
    "maxpwdage",
    "minpwdage",
    # The same values on a fine-grained password policy (PSO).
    "msds-lockoutduration",
    "msds-lockoutobservationwindow",
    "msds-maximumpasswordage",
    "msds-minimumpasswordage",
}
# Decoded from the raw bytes rather than from ldap3's formatted value, so the
# result does not depend on whether ldap3 loaded the schema (the server loads
# it: get_info=ALL makes ldap3 turn FILETIMEs into datetime and tick intervals
# into timedelta, which int() cannot read).
_FROM_RAW_ATTRS = _SID_ATTRS | _GUID_ATTRS | _FILETIME_ATTRS | _INTERVAL_ATTRS
_BOOLEAN_ATTRS = set()  # ldap3 already decodes booleans


def _normalize_value(attr_lower: str, value: Any) -> Any:
    if isinstance(value, bytes):
        if attr_lower in _SID_ATTRS:
            return decode_sid(value)
        if attr_lower in _GUID_ATTRS:
            return decode_guid(value)
        if attr_lower in _FILETIME_ATTRS:
            return decode_filetime(value)
        if attr_lower in _INTERVAL_ATTRS:
            return windows_ticks_to_timedelta(value)
        # Fallback: try to decode as UTF-8; otherwise return hex.
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if attr_lower in _FILETIME_ATTRS:
        return decode_filetime(value)
    if attr_lower in _GENTIME_ATTRS:
        return decode_generalized_time(value)
    if attr_lower in _INTERVAL_ATTRS:
        return windows_ticks_to_timedelta(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return value


def _get_ci(values: dict[str, Any], name: str) -> Any:
    """values[name], matching the attribute name case-insensitively."""
    wanted = name.lower()
    return next((v for k, v in values.items() if k.lower() == wanted), None)


def format_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Convert an ldap3 entry-as-dict into a JSON-friendly, decoded dict.

    Expects the shape produced by ldap3's ``connection.response`` with
    ``get_operational_attributes=True`` and ``attributes=ALL_ATTRIBUTES``:
    ``{"dn": ..., "attributes": {...}, "raw_attributes": {...}}``.
    """
    if "attributes" not in entry:
        return entry
    attrs = entry.get("attributes") or {}
    raw = entry.get("raw_attributes") or {}
    result: dict[str, Any] = {"dn": entry.get("dn")}
    decoded: dict[str, Any] = {}
    for name, value in attrs.items():
        attr_lower = name.lower()
        # SIDs/GUIDs, FILETIMEs and tick intervals come from the raw bytes.
        if attr_lower in _FROM_RAW_ATTRS:
            raw_values = raw.get(name) or []
            if isinstance(raw_values, list):
                decoded_values = [_normalize_value(attr_lower, v) for v in raw_values]
                decoded[name] = decoded_values[0] if len(decoded_values) == 1 else decoded_values
            else:
                decoded[name] = _normalize_value(attr_lower, raw_values)
            continue
        if isinstance(value, list):
            new_list = [_normalize_value(attr_lower, v) for v in value]
            decoded[name] = new_list[0] if len(new_list) == 1 else new_list
        else:
            decoded[name] = _normalize_value(attr_lower, value)
    # Convenience decoded views for common flag attrs (from the unwrapped values:
    # without schema information ldap3 returns even single values as lists).
    uac_value = _get_ci(decoded, "userAccountControl")
    if uac_value is not None:
        computed = _get_ci(decoded, "msDS-User-Account-Control-Computed")
        uac = decode_uac(uac_value, computed)
        if uac is not None:
            decoded["userAccountControl_decoded"] = uac
    group_type = _get_ci(decoded, "groupType")
    if group_type is not None:
        gt = decode_group_type(group_type)
        if gt is not None:
            decoded["groupType_decoded"] = gt
    result["attributes"] = decoded
    return result
