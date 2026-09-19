"""Shared attribute sets used by multiple tool modules."""

from __future__ import annotations

# Constructed attributes AD does not return under "*" and that the cards need.
_COMPUTED_ATTRS = [
    "msDS-User-Account-Control-Computed",
    "msDS-UserPasswordExpiryTimeComputed",
    "msDS-ResultantPSO",
]
# What a single-object read requests: every attribute the bind account may see,
# plus the constructed ones. format_entry withholds credential attributes and
# summarises large binaries, so "*" is safe to ask for. The multi-object search
# and list tools keep the compact sets below, so a page of results stays small.
FULL_USER_ATTRS = ["*", *_COMPUTED_ATTRS]
FULL_GROUP_ATTRS = ["*"]
FULL_COMPUTER_ATTRS = ["*", "msDS-User-Account-Control-Computed"]

USER_ATTRS = [
    "cn",
    "distinguishedName",
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "givenName",
    "sn",
    "mail",
    "title",
    "department",
    "company",
    "manager",
    "telephoneNumber",
    "mobile",
    "physicalDeliveryOfficeName",
    "employeeID",
    "employeeType",
    "description",
    "userAccountControl",
    # Constructed: the only place AD reports lockout and password expiry.
    "msDS-User-Account-Control-Computed",
    "msDS-UserPasswordExpiryTimeComputed",
    "accountExpires",
    "pwdLastSet",
    "lastLogonTimestamp",
    "lastLogon",
    "badPwdCount",
    "badPasswordTime",
    "lockoutTime",
    "logonCount",
    "memberOf",
    "primaryGroupID",
    "objectSid",
    "objectGUID",
    "whenCreated",
    "whenChanged",
    "userWorkstations",
    "servicePrincipalName",
]

GROUP_ATTRS = [
    "cn",
    "distinguishedName",
    "sAMAccountName",
    "description",
    "groupType",
    "member",
    "memberOf",
    "managedBy",
    "info",
    "mail",
    "objectSid",
    "objectGUID",
    "whenCreated",
    "whenChanged",
]

OU_ATTRS = [
    "ou",
    "distinguishedName",
    "description",
    "gPLink",
    "gPOptions",
    "managedBy",
    "objectGUID",
    "whenCreated",
    "whenChanged",
]

COMPUTER_ATTRS = [
    "cn",
    "distinguishedName",
    "sAMAccountName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "operatingSystemServicePack",
    "userAccountControl",
    "lastLogonTimestamp",
    "lastLogon",
    "pwdLastSet",
    "servicePrincipalName",
    "memberOf",
    "description",
    "location",
    "managedBy",
    "objectSid",
    "objectGUID",
    "whenCreated",
    "whenChanged",
]

GPO_ATTRS = [
    "cn",
    "displayName",
    "distinguishedName",
    "gPCFileSysPath",
    "gPCMachineExtensionNames",
    "gPCUserExtensionNames",
    "flags",
    "versionNumber",
    "objectGUID",
    "whenCreated",
    "whenChanged",
]

DOMAIN_ATTRS = [
    "distinguishedName",
    "name",
    "objectSid",
    "objectGUID",
    "maxPwdAge",
    "minPwdAge",
    "minPwdLength",
    "pwdHistoryLength",
    "pwdProperties",
    "lockoutDuration",
    "lockoutObservationWindow",
    "lockoutThreshold",
    "ms-DS-MachineAccountQuota",
    "msDS-Behavior-Version",
    "fSMORoleOwner",
    "whenCreated",
    "whenChanged",
]

TRUST_ATTRS = [
    "cn",
    "distinguishedName",
    "trustPartner",
    "trustType",
    "trustDirection",
    "trustAttributes",
    "flatName",
    "whenCreated",
    "whenChanged",
]
