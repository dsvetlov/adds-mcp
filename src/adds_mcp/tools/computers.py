"""Computer-account tools."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import ReadOnlyADClient, escape_filter, filetime_days_ago
from ._common import COMPUTER_ATTRS, FULL_COMPUTER_ATTRS


def _computer_filter(inner: str | None) -> str:
    base = "(objectCategory=computer)"
    if not inner:
        return base
    return f"(&{base}{inner})"


def register(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def search_computers(
        query: Annotated[
            str,
            Field(
                default="",
                description="Substring match on cn, sAMAccountName, dNSHostName, operatingSystem.",
            ),
        ] = "",
        base_dn: Annotated[str, Field(default="")] = "",
        include_disabled: Annotated[bool, Field(default=True)] = True,
        limit: Annotated[int, Field(default=50, ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        """Search computer accounts."""
        parts: list[str] = []
        if query:
            q = escape_filter(query)
            parts.append(
                "(|"
                f"(cn=*{q}*)"
                f"(sAMAccountName=*{q}*)"
                f"(dNSHostName=*{q}*)"
                f"(operatingSystem=*{q}*)"
                ")"
            )
        if not include_disabled:
            parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
        inner = "".join(parts) if parts else None
        results = client.search(
            search_filter=_computer_filter(inner),
            base_dn=base_dn or None,
            attributes=COMPUTER_ATTRS,
            size_limit=limit,
            page_size=limit,
        )
        return {"count": len(results), "computers": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_computer(
        identifier: Annotated[
            str,
            Field(
                description=(
                    "Computer sAMAccountName (with or without trailing $), "
                    "cn, dNSHostName, or full DN."
                )
            ),
        ],
    ) -> dict[str, Any]:
        """Return the full attribute set for a single computer."""
        ident = escape_filter(identifier)
        # If they gave a plain hostname, also match sAMAccountName=host$ (that's how AD stores it).
        with_dollar = escape_filter(identifier + "$") if not identifier.endswith("$") else ident
        filt = _computer_filter(
            "(|"
            f"(sAMAccountName={ident})"
            f"(sAMAccountName={with_dollar})"
            f"(cn={ident})"
            f"(dNSHostName={ident})"
            f"(distinguishedName={ident})"
            ")"
        )
        results = client.search(search_filter=filt, attributes=FULL_COMPUTER_ATTRS, size_limit=2)
        if not results:
            return {"found": False, "identifier": identifier}
        if len(results) > 1:
            return {
                "found": True,
                "identifier": identifier,
                "ambiguous": True,
                "matches": results,
            }
        return {"found": True, "identifier": identifier, "computer": results[0]}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_domain_controllers(
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List domain controllers (userAccountControl SERVER_TRUST_ACCOUNT flag = 0x2000)."""
        results = client.search(
            search_filter=_computer_filter("(userAccountControl:1.2.840.113556.1.4.803:=8192)"),
            attributes=COMPUTER_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "domain_controllers": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_stale_computers(
        days: Annotated[
            int,
            Field(default=90, ge=1, le=3650, description="Not logged on within this many days."),
        ] = 90,
        include_disabled: Annotated[bool, Field(default=False)] = False,
        limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """List computer accounts whose lastLogonTimestamp is older than N days."""
        threshold = filetime_days_ago(days)
        parts = [f"(lastLogonTimestamp<={threshold})", "(lastLogonTimestamp=*)"]
        if not include_disabled:
            parts.append("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
        results = client.search(
            search_filter=_computer_filter("".join(parts)),
            attributes=COMPUTER_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "threshold_days": days, "computers": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def summarize_computer_os(
        limit: Annotated[int, Field(default=2000, ge=1, le=2000)] = 2000,
    ) -> dict[str, Any]:
        """Count enabled computers by operatingSystem string."""
        results = client.search(
            search_filter=_computer_filter("(!(userAccountControl:1.2.840.113556.1.4.803:=2))"),
            attributes=["operatingSystem", "operatingSystemVersion"],
            size_limit=limit,
        )
        counts: dict[str, int] = {}
        for entry in results:
            os_name = entry.get("attributes", {}).get("operatingSystem") or "(unknown)"
            counts[os_name] = counts.get(os_name, 0) + 1
        summary = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        return {
            "total": len(results),
            "distinct_os": len(counts),
            "by_os": [{"operating_system": k, "count": v} for k, v in summary],
        }
