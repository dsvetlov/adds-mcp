"""User-related read-only tools."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import ReadOnlyADClient, escape_filter, filetime_days_ago
from ._common import USER_ATTRS


def _user_filter(search_filter: str | None) -> str:
    """Wrap a user-only object class filter around a caller-provided filter."""
    base = "(&(objectCategory=person)(objectClass=user))"
    if not search_filter:
        return base
    return f"(&{base}{search_filter})"


def _resolve_user(client: ReadOnlyADClient, identifier: str) -> dict[str, Any]:
    """Look up a user by any common identifier. Returns a resolution dict."""
    ident = escape_filter(identifier)
    filt = _user_filter(
        f"(|(sAMAccountName={ident})(userPrincipalName={ident})(mail={ident})(distinguishedName={ident}))"
    )
    results = client.search(search_filter=filt, attributes=USER_ATTRS, size_limit=2)
    if not results:
        return {"found": False, "identifier": identifier}
    if len(results) > 1:
        return {"found": True, "identifier": identifier, "ambiguous": True, "matches": results}
    return {"found": True, "identifier": identifier, "user": results[0]}


def register(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def search_users(
        query: Annotated[
            str,
            Field(
                description=(
                    "Free-text substring matched against sAMAccountName, "
                    "userPrincipalName, displayName, mail, cn, givenName, sn. "
                    "Pass an empty string to list all users (respecting limit)."
                )
            ),
        ] = "",
        base_dn: Annotated[
            str,
            Field(
                default="",
                description="Optional OU DN to scope the search. Defaults to the configured base DN.",
            ),
        ] = "",
        include_disabled: Annotated[
            bool,
            Field(default=True, description="Include disabled accounts in the results."),
        ] = True,
        limit: Annotated[
            int,
            Field(default=50, ge=1, le=500, description="Maximum users to return."),
        ] = 50,
    ) -> dict[str, Any]:
        """Search Active Directory users by substring across common identity fields."""
        parts: list[str] = []
        if query:
            q = escape_filter(query)
            parts.append(
                "(|"
                f"(sAMAccountName=*{q}*)"
                f"(userPrincipalName=*{q}*)"
                f"(displayName=*{q}*)"
                f"(mail=*{q}*)"
                f"(cn=*{q}*)"
                f"(givenName=*{q}*)"
                f"(sn=*{q}*)"
                ")"
            )
        if not include_disabled:
            parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
        combined = "".join(parts) if parts else None
        results = client.search(
            search_filter=_user_filter(combined),
            base_dn=base_dn or None,
            attributes=USER_ATTRS,
            size_limit=limit,
            page_size=limit,
        )
        return {"count": len(results), "users": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_user(
        identifier: Annotated[
            str,
            Field(
                description=(
                    "User identifier: sAMAccountName, userPrincipalName, "
                    "mail, or full distinguishedName."
                )
            ),
        ],
    ) -> dict[str, Any]:
        """Return the full attribute set for a single user."""
        return _resolve_user(client, identifier)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_user_groups(
        identifier: Annotated[
            str,
            Field(description="User sAMAccountName, UPN, mail, or DN."),
        ],
        recursive: Annotated[
            bool,
            Field(
                default=False,
                description=(
                    "If true, expand nested group memberships via the "
                    "LDAP_MATCHING_RULE_IN_CHAIN OID."
                ),
            ),
        ] = False,
    ) -> dict[str, Any]:
        """List all groups a user is a direct (or transitive) member of."""
        user = _resolve_user(client, identifier)
        if not user.get("found") or user.get("ambiguous"):
            return {"found": False, "identifier": identifier}
        user_dn = user["user"]["dn"]
        if recursive:
            filt = f"(member:1.2.840.113556.1.4.1941:={escape_filter(user_dn)})"
        else:
            filt = f"(member={escape_filter(user_dn)})"
        results = client.search(
            search_filter=f"(&(objectCategory=group){filt})",
            attributes=["cn", "distinguishedName", "sAMAccountName", "groupType", "description"],
        )
        return {"user_dn": user_dn, "recursive": recursive, "count": len(results), "groups": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_locked_out_users(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List accounts currently locked out by the domain lockout policy."""
        results = client.search(
            search_filter=_user_filter("(lockoutTime>=1)"),
            attributes=USER_ATTRS,
            size_limit=limit,
        )
        # lockoutTime stays set after a lockout expires, until the next logon; only
        # the computed flag says whether the account is locked now.
        locked = [
            user
            for user in results
            if user.get("attributes", {}).get("userAccountControl_decoded", {}).get("locked_out")
            is not False
        ]
        return {"count": len(locked), "users": locked}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_disabled_users(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List disabled user accounts."""
        results = client.search(
            search_filter=_user_filter("(userAccountControl:1.2.840.113556.1.4.803:=2)"),
            attributes=USER_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "users": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_stale_users(
        days: Annotated[
            int,
            Field(default=90, ge=1, le=3650, description="No logon within this many days."),
        ] = 90,
        include_disabled: Annotated[bool, Field(default=False)] = False,
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List enabled user accounts whose lastLogonTimestamp is older than N days."""
        threshold = filetime_days_ago(days)
        # (lastLogonTimestamp<=X) covers stale accounts; combine with an existence check
        # to skip records where the attribute has never been set (which would look "stale"
        # for brand-new accounts).
        parts = [f"(lastLogonTimestamp<={threshold})", "(lastLogonTimestamp=*)"]
        if not include_disabled:
            parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
        results = client.search(
            search_filter=_user_filter("".join(parts)),
            attributes=USER_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "threshold_days": days, "users": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_recently_changed_users(
        days: Annotated[
            int,
            Field(default=7, ge=1, le=365, description="Look-back window in days."),
        ] = 7,
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List users whose directory record changed within the last N days."""
        from datetime import datetime, timedelta, timezone

        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y%m%d%H%M%S.0Z")
        results = client.search(
            search_filter=_user_filter(f"(whenChanged>={cutoff})"),
            attributes=USER_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "since_days": days, "users": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_password_never_expires(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List enabled users whose password is configured to never expire."""
        results = client.search(
            search_filter=_user_filter(
                "(&(userAccountControl:1.2.840.113556.1.4.803:=65536)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            ),
            attributes=USER_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "users": results}
