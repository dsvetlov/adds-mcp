"""Group Policy Object tools."""

from __future__ import annotations

import re
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import ReadOnlyADClient, escape_filter
from ..config import settings
from ._common import GPO_ATTRS

# gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;options][...][...]
_GPLINK_RE = re.compile(r"\[LDAP://([^;]+);(\d+)\]")


def _resolve_gpo(client: ReadOnlyADClient, identifier: str) -> dict[str, Any]:
    base = f"CN=Policies,CN=System,{settings.base_dn}" if settings.base_dn else None
    ident = escape_filter(identifier)
    filt = (
        "(&(objectClass=groupPolicyContainer)"
        f"(|(displayName={ident})(cn={ident})(distinguishedName={ident})))"
    )
    results = client.search(
        search_filter=filt, base_dn=base, attributes=GPO_ATTRS, size_limit=2
    )
    if not results:
        return {"found": False, "identifier": identifier}
    if len(results) > 1:
        return {"found": True, "identifier": identifier, "ambiguous": True, "matches": results}
    return {"found": True, "identifier": identifier, "gpo": results[0]}


def _parse_gplink(raw: str | None) -> list[dict[str, Any]]:
    if not raw:
        return []
    links: list[dict[str, Any]] = []
    for dn, options in _GPLINK_RE.findall(raw):
        opts = int(options)
        links.append(
            {
                "gpo_dn": dn,
                "options_raw": opts,
                "disabled": bool(opts & 1),
                "enforced": bool(opts & 2),
            }
        )
    return links


def register(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_gpos(
        query: Annotated[
            str,
            Field(default="", description="Substring match on displayName / cn."),
        ] = "",
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List Group Policy Objects in the domain."""
        base = f"CN=Policies,CN=System,{settings.base_dn}" if settings.base_dn else None
        filt = "(objectClass=groupPolicyContainer)"
        if query:
            q = escape_filter(query)
            filt = f"(&{filt}(|(displayName=*{q}*)(cn=*{q}*)))"
        results = client.search(
            search_filter=filt,
            base_dn=base,
            attributes=GPO_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "gpos": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_gpo(
        identifier: Annotated[
            str,
            Field(
                description=(
                    "GPO displayName, cn (e.g. {GUID}), or full DN."
                )
            ),
        ],
    ) -> dict[str, Any]:
        """Return the full attribute set for a single GPO."""
        return _resolve_gpo(client, identifier)

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def find_gpo_links(
        gpo_identifier: Annotated[
            str,
            Field(description="GPO displayName, cn, or DN whose links you want to enumerate."),
        ],
    ) -> dict[str, Any]:
        """Find every OU / domain / site that links a given GPO (parses gPLink)."""
        gpo = _resolve_gpo(client, gpo_identifier)
        if not gpo.get("found") or gpo.get("ambiguous"):
            return {"found": False, "identifier": gpo_identifier}
        gpo_dn = gpo["gpo"]["dn"]
        # gPLink stores DNs in lowercase LDAP:// form; do case-insensitive substring search.
        # Search domain-wide for containers with any gPLink referencing this GPO.
        filt = f"(gPLink=*{escape_filter(gpo_dn)}*)"
        results = client.search(
            search_filter=filt,
            attributes=["distinguishedName", "ou", "cn", "gPLink", "objectClass"],
        )
        parsed = []
        for entry in results:
            attrs = entry.get("attributes", {})
            links = _parse_gplink(attrs.get("gPLink"))
            matching = [
                lnk for lnk in links if gpo_dn.lower() in lnk["gpo_dn"].lower()
            ]
            parsed.append(
                {
                    "dn": entry["dn"],
                    "object_class": attrs.get("objectClass"),
                    "linked_as": matching,
                }
            )
        return {"gpo_dn": gpo_dn, "linked_from_count": len(parsed), "linked_from": parsed}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_links_on_ou(
        dn: Annotated[
            str,
            Field(description="OU or domain DN whose gPLink you want to decode."),
        ],
    ) -> dict[str, Any]:
        """List all GPOs linked to a specific OU (parses that OU's gPLink attribute)."""
        obj = client.read_object(dn, attributes=["distinguishedName", "gPLink"])
        if obj is None:
            return {"found": False, "dn": dn}
        links = _parse_gplink(obj.get("attributes", {}).get("gPLink"))
        # Enrich with GPO displayName lookups.
        enriched: list[dict[str, Any]] = []
        for lnk in links:
            # A link may point at a GPO of another domain, which this directory
            # does not hold: report it on that link rather than failing them all.
            try:
                gpo_obj = client.read_object(
                    lnk["gpo_dn"], attributes=["displayName", "cn"]
                )
            except RuntimeError as exc:
                enriched.append(
                    {**lnk, "gpo_display_name": None, "gpo_cn": None, "error": str(exc)}
                )
                continue
            attrs = (gpo_obj or {}).get("attributes", {})
            enriched.append(
                {
                    **lnk,
                    "gpo_display_name": attrs.get("displayName"),
                    "gpo_cn": attrs.get("cn"),
                }
            )
        return {"container_dn": dn, "count": len(enriched), "links": enriched}
