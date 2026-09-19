"""Group-related read-only tools."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import ReadOnlyADClient, escape_filter
from ._common import FULL_GROUP_ATTRS, GROUP_ATTRS


def _group_filter(inner: str | None) -> str:
    base = "(objectCategory=group)"
    if not inner:
        return base
    return f"(&{base}{inner})"


def _resolve_group(
    client: ReadOnlyADClient, identifier: str, attributes: list[str] = GROUP_ATTRS
) -> dict[str, Any]:
    ident = escape_filter(identifier)
    filt = _group_filter(f"(|(sAMAccountName={ident})(cn={ident})(distinguishedName={ident}))")
    results = client.search(search_filter=filt, attributes=attributes, size_limit=2)
    if not results:
        return {"found": False, "identifier": identifier}
    if len(results) > 1:
        return {"found": True, "identifier": identifier, "ambiguous": True, "matches": results}
    return {"found": True, "identifier": identifier, "group": results[0]}


def register(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def search_groups(
        query: Annotated[
            str,
            Field(
                description=(
                    "Substring matched against sAMAccountName, cn, description, mail. "
                    "Empty string returns all groups (respecting limit)."
                )
            ),
        ] = "",
        base_dn: Annotated[str, Field(default="")] = "",
        security_only: Annotated[
            bool,
            Field(default=False, description="If true, return only security groups."),
        ] = False,
        limit: Annotated[int, Field(default=50, ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        """Search Active Directory groups by substring."""
        parts: list[str] = []
        if query:
            q = escape_filter(query)
            parts.append(
                "(|"
                f"(sAMAccountName=*{q}*)"
                f"(cn=*{q}*)"
                f"(description=*{q}*)"
                f"(mail=*{q}*)"
                ")"
            )
        if security_only:
            # groupType has the 0x80000000 bit set for security groups.
            parts.append("(groupType:1.2.840.113556.1.4.803:=2147483648)")
        inner = "".join(parts) if parts else None
        results = client.search(
            search_filter=_group_filter(inner),
            base_dn=base_dn or None,
            attributes=GROUP_ATTRS,
            size_limit=limit,
            page_size=limit,
        )
        return {"count": len(results), "groups": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_group(
        identifier: Annotated[
            str,
            Field(description="Group sAMAccountName, cn, or full distinguishedName."),
        ],
    ) -> dict[str, Any]:
        """Return the full attribute set for a single group."""
        return _resolve_group(client, identifier, attributes=FULL_GROUP_ATTRS)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_group_members(
        identifier: Annotated[
            str,
            Field(description="Group sAMAccountName, cn, or DN."),
        ],
        recursive: Annotated[
            bool,
            Field(
                default=False,
                description=(
                    "If true, expand nested memberships via LDAP_MATCHING_RULE_IN_CHAIN."
                ),
            ),
        ] = False,
        object_types: Annotated[
            str,
            Field(
                default="all",
                description="Filter members by type: 'users', 'groups', 'computers', or 'all'.",
            ),
        ] = "all",
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List the members of a group. Direct by default, transitive with recursive=True.

        Returns up to ``limit`` members; ``truncated`` says whether the group
        has more (get_group's ``member_count`` is the total). For a group larger
        than the server page cap, narrow with ``object_types`` rather than
        paging: LDAP gives no stable order to page a plain member search by.
        """
        grp = _resolve_group(client, identifier)
        if not grp.get("found") or grp.get("ambiguous"):
            return {"found": False, "identifier": identifier}
        group_dn = grp["group"]["dn"]
        dn_escaped = escape_filter(group_dn)

        if recursive:
            member_filter = f"(memberOf:1.2.840.113556.1.4.1941:={dn_escaped})"
        else:
            member_filter = f"(memberOf={dn_escaped})"

        type_filter = {
            "users": "(&(objectCategory=person)(objectClass=user))",
            "groups": "(objectCategory=group)",
            "computers": "(objectCategory=computer)",
            "all": "(objectClass=*)",
        }.get(object_types.lower(), "(objectClass=*)")

        combined = f"(&{type_filter}{member_filter})"
        results = client.search(
            search_filter=combined,
            attributes=[
                "cn",
                "distinguishedName",
                "sAMAccountName",
                "userPrincipalName",
                "displayName",
                "mail",
                "objectClass",
            ],
            size_limit=limit + 1,
            page_size=limit + 1,
        )
        # More than the page fit, or the search itself hit the server cap
        # (client.search never returns beyond max_entries): either way there
        # is more than this page shows.
        truncated = len(results) > limit or len(results) >= client.max_entries
        return {
            "group_dn": group_dn,
            "recursive": recursive,
            "object_types": object_types,
            "count": min(len(results), limit),
            "truncated": truncated,
            "members": results[:limit],
        }

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_empty_groups(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List security/distribution groups with no direct members."""
        results = client.search(
            search_filter=_group_filter("(!(member=*))"),
            attributes=GROUP_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "groups": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_privileged_groups(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List built-in privileged groups (adminCount=1); each card carries member_count (use list_group_members for the names)."""
        results = client.search(
            search_filter=_group_filter("(adminCount=1)"),
            attributes=GROUP_ATTRS + ["adminCount"],
            size_limit=limit,
        )
        return {"count": len(results), "groups": results}
