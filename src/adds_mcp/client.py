"""Thin, read-only wrapper around ldap3 for Active Directory queries."""

from __future__ import annotations

import logging
import ssl
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator

from ldap3 import (
    ALL,
    ALL_ATTRIBUTES,
    BASE,
    Connection,
    LEVEL,
    SAFE_SYNC,
    SUBTREE,
    Server,
    ServerPool,
    Tls,
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPInvalidCredentialsResult,
    LDAPInvalidDnError,
    LDAPSessionTerminatedByServerError,
    LDAPSocketReceiveError,
    LDAPSocketSendError,
)
from ldap3.core.results import RESULT_REFERRAL
from ldap3.utils.dn import parse_dn, safe_dn

from .config import Settings
from .formatting import format_entry

log = logging.getLogger(__name__)

# 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
_FILETIME_EPOCH_DELTA = 116444736000000000

SCOPE_MAP = {"base": BASE, "one": LEVEL, "level": LEVEL, "sub": SUBTREE, "subtree": SUBTREE}

# Global Catalog ports: a GC also answers for the other domains of the forest.
_GC_PORTS = {3268, 3269}
_PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"


def _describe(exc: BaseException) -> str:
    """A short, credential-free description of an ldap3 exception."""
    return str(exc).splitlines()[0] if str(exc) else type(exc).__name__


def _is_invalid_credentials(exc: BaseException) -> bool:
    """True when a bind failure means the password was wrong (LDAP result 49),
    as opposed to a transient failure (a DC down, a network error)."""
    if isinstance(exc, LDAPInvalidCredentialsResult):
        return True
    text = str(exc).lower()
    return "invalidcredentials" in text or "data 52e" in text or "result 49" in text


class CredentialsRejected(RuntimeError):
    """The bind account was rejected; calls are refused until a restart.

    A RuntimeError, like every other search failure, so the tools report it.
    """


class SearchBaseOutOfScope(RuntimeError):
    """A search base outside the naming contexts this directory serves.

    A RuntimeError, like every other search failure, so that tools which
    already report per-lookup errors keep doing so.
    """


class ReferralNotFollowed(RuntimeError):
    """The directory answered with a referral, which this server never follows."""


class ReadOnlyADClient:
    """Manages a single, lazily-created ldap3 connection for read-only queries."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._connection: Connection | None = None
        # Set once a bind is rejected for bad credentials. The bind account is
        # a real domain account (the bot's own), so retrying a wrong or rotated
        # password on every call would lock it out after the lockout threshold.
        # We refuse further calls until the process is restarted with a good
        # password instead.
        self._credentials_rejected: str | None = None

    # ------------------------------------------------------------------ setup
    def _build_tls(self) -> Tls:
        validate = ssl.CERT_REQUIRED if self._settings.tls_validate else ssl.CERT_NONE
        kwargs: dict[str, Any] = {"validate": validate, "version": ssl.PROTOCOL_TLS_CLIENT}
        if self._settings.ca_cert_file:
            kwargs["ca_certs_file"] = self._settings.ca_cert_file
        return Tls(**kwargs)

    def _build_pool(self) -> ServerPool:
        tls = self._build_tls()
        servers = [
            Server(
                host,
                port=self._settings.port,
                use_ssl=True,
                tls=tls,
                get_info=ALL,
                connect_timeout=self._settings.query_timeout_seconds,
                # ldap3 defaults to following referrals to any host *with the bind
                # credentials*; see the note in _connect.
                allowed_referral_hosts=[],
            )
            for host in self._settings.servers
        ]
        return ServerPool(servers, pool_strategy="FIRST", active=True, exhaust=True)

    def _connect(self) -> Connection:
        self._settings.require_ready()
        pool = self._build_pool()
        conn = Connection(
            pool,
            user=self._settings.bind_dn,
            password=self._settings.bind_password,
            auto_bind=True,
            client_strategy=SAFE_SYNC,
            read_only=True,
            receive_timeout=self._settings.query_timeout_seconds,
            raise_exceptions=True,
            # Never chase referrals. ldap3's defaults (auto_referrals=True and
            # allowed_referral_hosts=[('*', True)]) make a search whose base lies
            # outside this directory - e.g. base_dn="DC=evil,DC=example" supplied
            # by a model - open a new connection to the host named in the
            # referral and simple-bind there with the service account's DN and
            # password, in clear text for ldap:// referrals.
            auto_referrals=False,
        )
        log.info("Bound to AD as %s via %s", self._settings.bind_dn, self._settings.servers)
        return conn

    def _get_connection(self) -> Connection:
        with self._lock:
            if self._credentials_rejected is not None:
                raise CredentialsRejected(self._credentials_rejected)
            if self._connection is None or not self._connection.bound:
                try:
                    self._connection = self._connect()
                except (LDAPBindError, LDAPInvalidCredentialsResult) as exc:
                    # Latch only on *wrong credentials*: a wrong or rotated
                    # password would otherwise be retried on every call and lock
                    # the account out. A different bind failure (a DC down, a
                    # network blip) is transient — re-raise it so the next call
                    # tries again instead of disabling the sidecar for good.
                    if not _is_invalid_credentials(exc):
                        raise
                    self._credentials_rejected = (
                        f"the bind account was rejected ({_describe(exc)}); refusing "
                        "further attempts so the account is not locked out — restart "
                        "with a correct password"
                    )
                    raise CredentialsRejected(self._credentials_rejected) from exc
            return self._connection

    @property
    def max_entries(self) -> int:
        """The hard ceiling client.search will ever return (the paging cap)."""
        return self._settings.max_page_size

    def _discard_connection(self) -> None:
        """Drop the cached connection so the next call binds afresh.

        An idle LDAP(S) connection is closed by the DC (idle timeout, SSL
        session expiry) without the client noticing: ldap3 leaves ``.bound``
        True, so _get_connection would hand back the dead socket forever and
        every query would fail with a broken pipe / bad-length SSL error until
        the process restarts. search() calls this on a communication error and
        retries once against a fresh bind.
        """
        with self._lock:
            if self._connection is not None:
                try:
                    self._connection.unbind()
                except LDAPException:
                    pass
                self._connection = None

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                try:
                    self._connection.unbind()
                except LDAPException:
                    pass
                self._connection = None

    # ---------------------------------------------------------------- scoping
    def _allowed_roots(self, conn: Connection) -> list[str]:
        """The configured base DN, the naming contexts the DC advertises and,
        on a Global Catalog port, the forest root domain.

        The naming contexts cover the Configuration partition that list_sites
        reads, which in a child domain does not lie under the base DN. On a GC
        port the forest root admits the root domain and every domain beneath
        it; a second tree of the same forest is still refused. This is a coarse
        bound: a child domain lies beneath a forest-root base DN, and a DC that
        does not hold it answers with a referral - see _paged_entries.
        """
        roots = [self._settings.base_dn]
        info = getattr(conn.server, "info", None)
        roots.extend(getattr(info, "naming_contexts", None) or [])
        if self._settings.port in _GC_PORTS:
            other = getattr(info, "other", None) or {}
            roots.extend(other.get("rootDomainNamingContext") or [])
        unique: dict[str, str] = {}
        for root in roots:
            if root:
                unique.setdefault(root.lower(), root)
        return list(unique.values())

    def _scoped_base(self, conn: Connection, base: str) -> str:
        """Return ``base`` unchanged if it lies within this directory, else raise.

        Defence in depth: the referral settings in _build_pool and _connect are
        what keep credentials from leaving; this refuses a base outside the
        directory before any request, with an error the caller can act on.
        """
        roots = self._allowed_roots(conn)
        try:
            dn = _base_to_check(base)
            inside = dn is None or any(dn_within(dn, root) for root in roots)
        except ValueError as exc:
            raise SearchBaseOutOfScope(str(exc)) from None
        if inside:
            return base
        raise SearchBaseOutOfScope(
            f"Search base {base!r} is outside the directory served by this "
            f"server (allowed: {', '.join(roots)})."
        )

    @staticmethod
    def _paged_entries(
        conn: Connection,
        *,
        base: str,
        search_filter: str,
        scope: Any,
        attributes: Any,
        page: int,
    ) -> Iterator[dict[str, Any]]:
        """Yield the responses of a paged search, page by page.

        ldap3's own paged_search drops a referral result without a word once
        referrals are not followed (resultCode 10 is never raised), so a search
        whose base the DC does not hold would look empty. It is reported here.
        """
        if conn.check_names:
            base = safe_dn(base)
        cookie = None
        while True:
            outcome = conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes,
                get_operational_attributes=True,
                paged_size=page,
                paged_cookie=cookie,
            )
            if isinstance(outcome, tuple):  # thread-safe strategies (SAFE_SYNC)
                _status, result, response, _request = outcome
            else:
                result, response = conn.result, conn.response
            result = result or {}
            if result.get("result") == RESULT_REFERRAL or result.get("referrals"):
                targets = ", ".join(result.get("referrals") or []) or "another server"
                raise ReferralNotFollowed(
                    f"The directory referred the search for {base!r} to {targets}; "
                    "referrals are not followed."
                )
            yield from response or []
            try:
                cookie = result["controls"][_PAGED_RESULTS_OID]["value"]["cookie"]
            except (KeyError, TypeError):
                cookie = None
            if not cookie:
                return

    # ---------------------------------------------------------------- queries
    def search(
        self,
        *,
        search_filter: str,
        base_dn: str | None = None,
        scope: str = "subtree",
        attributes: Iterable[str] | str | None = ALL_ATTRIBUTES,
        page_size: int | None = None,
        size_limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Perform a paged LDAP search and return decoded entries.

        If the cached connection has been closed by the DC while idle (idle
        timeout, SSL session expiry), the first query on it fails with a
        broken-pipe / bad-length socket error, yet ldap3 leaves ``.bound`` True
        — so the dead socket would be reused on every later call. On such a
        *mid-use* socket error, drop the connection and try once more against a
        fresh bind. Connect-time failures propagate as before (the first
        _get_connection is outside the try); any other LDAP error is reported.
        """
        kwargs: dict[str, Any] = {
            "search_filter": search_filter,
            "base_dn": base_dn,
            "scope": scope,
            "attributes": attributes,
            "page_size": page_size,
            "size_limit": size_limit,
        }
        conn = self._get_connection()
        try:
            return self._run_search(conn, **kwargs)
        except (
            LDAPSocketSendError,
            LDAPSocketReceiveError,
            LDAPSessionTerminatedByServerError,
        ):
            self._discard_connection()
        except LDAPException as exc:
            raise RuntimeError(f"LDAP search failed: {exc}") from exc
        # The connection died mid-use; reconnect and try once more.
        try:
            conn = self._get_connection()
            return self._run_search(conn, **kwargs)
        except LDAPException as exc:
            raise RuntimeError(f"LDAP search failed: {exc}") from exc

    def _run_search(
        self,
        conn: Connection,
        *,
        search_filter: str,
        base_dn: str | None,
        scope: str,
        attributes: Iterable[str] | str | None,
        page_size: int | None,
        size_limit: int | None,
    ) -> list[dict[str, Any]]:
        scope_val = SCOPE_MAP.get(scope.lower(), SUBTREE)
        base = self._scoped_base(conn, base_dn or self._settings.base_dn)
        page = page_size or self._settings.default_page_size
        cap = min(
            size_limit if size_limit else self._settings.max_page_size,
            self._settings.max_page_size,
        )

        if isinstance(attributes, str):
            attrs: Any = attributes
        elif attributes is None:
            attrs = ALL_ATTRIBUTES
        else:
            attrs = list(attributes)

        results: list[dict[str, Any]] = []
        for entry in self._paged_entries(
            conn,
            base=base,
            search_filter=search_filter,
            scope=scope_val,
            attributes=attrs,
            page=min(page, cap),
        ):
            if entry.get("type") != "searchResEntry":
                continue
            results.append(format_entry(entry))
            if len(results) >= cap:
                break
        return results

    def read_object(
        self,
        dn: str,
        attributes: Iterable[str] | str | None = ALL_ATTRIBUTES,
    ) -> dict[str, Any] | None:
        """Read a single object by DN. Returns None if not found."""
        results = self.search(
            search_filter="(objectClass=*)",
            base_dn=dn,
            scope="base",
            attributes=attributes,
            page_size=1,
            size_limit=1,
        )
        return results[0] if results else None

    def domain_info(self) -> dict[str, Any]:
        """Return rootDSE + domain naming context info."""
        conn = self._get_connection()
        info = conn.server.info
        schema = {}
        if info is not None:
            schema = {
                "vendor_name": getattr(info, "vendor_name", None),
                "vendor_version": getattr(info, "vendor_version", None),
                "naming_contexts": list(getattr(info, "naming_contexts", []) or []),
                "supported_ldap_versions": list(getattr(info, "supported_ldap_versions", []) or []),
                "supported_sasl_mechanisms": list(
                    getattr(info, "supported_sasl_mechanisms", []) or []
                ),
                "alt_servers": list(getattr(info, "alt_servers", []) or []),
            }
        return schema


# ---------------------------------------------------------------------- filters


def escape_filter(value: str) -> str:
    """RFC 4515 escape a value for use inside an LDAP filter."""
    if value is None:
        return ""
    out = []
    for ch in value:
        if ch == "\\":
            out.append("\\5c")
        elif ch == "*":
            out.append("\\2a")
        elif ch == "(":
            out.append("\\28")
        elif ch == ")":
            out.append("\\29")
        elif ch == "\x00":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)


def _rdns(dn: str) -> list[frozenset[tuple[str, str]]]:
    """The RDNs of a DN, most specific first, each as a set of (attribute, value)
    pairs compared case-insensitively (a multi-valued RDN joins pairs with '+')."""
    try:
        parts = parse_dn(dn, escape=False, strip=False)
    except LDAPInvalidDnError as exc:
        raise ValueError(f"Invalid DN: {dn!r}") from exc
    rdns: list[frozenset[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    for attr, value, separator in parts:
        current.append((attr.lower(), value.lower()))
        if separator != "+":
            rdns.append(frozenset(current))
            current = []
    return rdns


def dn_within(dn: str, root: str) -> bool:
    """True if ``dn`` equals ``root`` or lies beneath it, RDN by RDN, case-insensitively.

    Raises ValueError for a malformed ``dn``.
    """
    inner = _rdns(dn)
    outer = _rdns(root)
    if not outer or len(inner) < len(outer):
        return False
    return inner[len(inner) - len(outer) :] == outer


def _base_to_check(base: str) -> str | None:
    """The DN a search base names, or None when it names no location.

    AD also accepts extended forms. <GUID=...> and <SID=...> name an object by
    identity and carry no location to check; <WKGUID=guid,DN> names a
    well-known container under DN, and DN is what is checked.
    """
    text = base.strip()
    if not (text.startswith("<") and text.endswith(">")):
        return base
    kind, _, rest = text[1:-1].partition("=")
    kind = kind.strip().upper()
    if kind in ("GUID", "SID"):
        return None
    if kind == "WKGUID":
        _guid, comma, dn = rest.partition(",")
        if comma and dn.strip():
            return dn
    raise ValueError(f"Unsupported search base: {base!r}")


def escape_dn(value: str) -> str:
    """Escape a DN component for embedding into a search base."""
    if value is None:
        return ""
    # DNs need different escaping than filters; only the most dangerous characters.
    return value.replace("\\", "\\\\").replace(",", "\\,")


def to_filetime(dt: datetime) -> int:
    """Convert a UTC datetime into a Windows FILETIME integer."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    epoch_seconds = (dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
    return int(epoch_seconds * 10_000_000) + _FILETIME_EPOCH_DELTA


def filetime_days_ago(days: int) -> int:
    """FILETIME representing now minus ``days`` days."""
    return to_filetime(datetime.now(timezone.utc) - timedelta(days=days))
