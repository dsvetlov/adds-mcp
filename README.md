# ms-ad-mcp

**Read-only Model Context Protocol (MCP) servers for the Microsoft Active
Directory family.** Three sibling servers in one repository, one shared LDAPS
bind, one optional WinRM bind for the online issuing CAs. Designed for
monitoring, investigation, and answering "who / what / where" questions about
a Windows domain without ever mutating directory state.

- **`adds-mcp`** — AD DS: users, groups, OUs, computers, GPOs, domain metadata
- **`adcs-mcp`** — AD CS: CAs, certificate templates, issued/pending/revoked certs, CA config, and the CRL/AIA web endpoints clients fetch over HTTP(S)
- **`addns-mcp`** — AD-integrated DNS: zones, records, delegations, stale entries, IP/name search

Every tool has `readOnlyHint: true`. `adds-mcp` opens LDAP with
`read_only=True`, so mutating LDAP verbs are rejected even if a tool tried to
issue one. `adcs-mcp` runs only `Get-*` PowerShell and read-only registry
reads on the CA hosts.

---

## Table of contents

1. [Architecture at a glance](#architecture-at-a-glance)
2. [Credentials you need to provision](#credentials-you-need-to-provision)
   1. [LDAPS service account (shared)](#1-ldaps-service-account-shared)
   2. [WinRM service account (adcs-mcp only)](#2-winrm-service-account-adcs-mcp-only)
3. [Network access matrix](#network-access-matrix)
4. [What each server queries — data sources in detail](#what-each-server-queries--data-sources-in-detail)
   1. [`adds-mcp` — Active Directory Domain Services](#adds-mcp--active-directory-domain-services)
   2. [`adcs-mcp` — Active Directory Certificate Services](#adcs-mcp--active-directory-certificate-services)
   3. [`addns-mcp` — AD-integrated DNS](#addns-mcp--ad-integrated-dns)
5. [Preparing the environment](#preparing-the-environment)
   1. [Domain controllers](#domain-controllers)
   2. [Issuing CAs (adcs-mcp only)](#issuing-cas-adcs-mcp-only)
   3. [The MCP host itself](#the-mcp-host-itself)
6. [Installation](#installation)
7. [Configuration reference](#configuration-reference)
8. [Running the servers](#running-the-servers)
9. [Wiring into an MCP client](#wiring-into-an-mcp-client)
10. [Security posture](#security-posture)
11. [Troubleshooting](#troubleshooting)
12. [Tool reference](#tool-reference)
13. [Repository layout](#repository-layout)

---

## Architecture at a glance

```
                ┌──────────────────────────────────────────────────┐
                │                MCP host (Linux)                  │
                │                                                  │
                │  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
                │  │ adds-mcp │  │ adcs-mcp │  │addns-mcp │        │
                │  │  :8080   │  │  :8081   │  │  :8082   │        │
                │  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
                │       │             │             │              │
                │       └──────┬──────┴──────┬──────┘              │
                │              │             │                     │
                │    ┌────────▼───┐ ┌───▼──────┐ ┌───▼──────┐     │
                │    │  LDAPS 636 │ │WinRM 5986│ │ HTTP(S)  │     │
                │    │  (shared)  │ │ (Kerberos│ │ CRL/AIA  │     │
                │    │            │ │  or NTLM)│ │  fetch   │     │
                │    └──────┬─────┘ └────┬─────┘ └────┬─────┘     │
                └───────────┼────────────┼────────────┼──────────┘
                            │            │            │
          ┌─────────────────▼─┐  ┌───────▼──────┐  ┌──▼───────────────┐
          │                   │  │ Issuing /    │  │ CRL / AIA web    │
          │ Domain Controllers│  │ Enterprise   │  │ server (CDP/AIA  │
          │  (any DC — pool)  │  │ CAs listed in │  │ HTTP endpoints   │
          │                   │  │ ADCS_CA_HOSTS │  │ in ADCS_CRL_     │
          │  • adds-mcp       │  │              │  │ AIA_URLS)        │
          │  • adcs-mcp (AD   │  │ • adcs-mcp   │  │                  │
          │      PKI subtree) │  │ • PS + PSPKI │  │ • adcs-mcp only  │
          │  • addns-mcp      │  │ • CA-ISSUE01 │  │ • fetch_crl /    │
          │                   │  │   CA-ISSUE02 │  │   fetch_ca_cert  │
          │                   │  │ ⚠ NOT offline│  │ • check_crl_aia_ │
          │                   │  │  Root/Policy │  │   endpoints      │
          └───────────────────┘  └──────────────┘  └──────────────────┘
```

This maps one-to-one onto the classic AD CS insight topology:

| Leg | Transport | Reaches | Tools |
|-----|-----------|---------|-------|
| AD directory | LDAP(S) 636 | Domain Controllers (PKI subtree) | `list_root_cas`, `list_aia_entries`, `list_cdp_entries`, `list_certificate_templates`, … |
| Issuing CAs | Kerberos/WinRM 5986 | `CA-ISSUE01`, `CA-ISSUE02` (`ADCS_CA_HOSTS`) | `check_ca_hosts_health`, `list_issued_certificates`, `get_ca_configuration`, … |
| CRL/AIA web | HTTP(S) | CRL/AIA distribution web server | `fetch_crl`, `fetch_ca_certificate`, `check_crl_aia_endpoints` |
| Policy/Root CA | *(offline — optional)* | Exported certs/CRLs only | `parse_certificate_pem`, `parse_crl_pem` |

**Not queried live**: Tier 0 (offline Root) and Tier 1 (offline Policy) CAs.
There's no live endpoint on an offline CA. Use `parse_certificate_pem` /
`parse_crl_pem` on exported certs/CRLs from those tiers instead, then
cross-check the trust chain against `list_ntauth_cas` / `list_aia_entries` /
`list_root_cas`.

---

## Credentials you need to provision

Two distinct service accounts. Provision them separately even if the same
person operates both — keeping them separate is what makes least-privilege
auditable.

### 1. LDAPS service account (shared)

**Used by:** `adds-mcp`, `adcs-mcp` (AD-side tools), `addns-mcp` (all tools).

**Purpose:** Bind to any DC over LDAPS and read AD content. Never writes.

| Item                  | Value                                                                             |
|-----------------------|-----------------------------------------------------------------------------------|
| Suggested name        | `svc-msadmcp-ro`                                                                  |
| Object class          | User (standard domain user account)                                               |
| Password              | Long, random, rotated on your normal schedule. Stored in a secret manager, not in git. |
| Group memberships     | **None special.** Any authenticated domain user has enough rights for ~95% of tools. See below for the exceptions. |
| Logon rights          | Deny interactive/local logon everywhere; allow only "Access this computer from the network" on DCs. |
| UAC flags to set      | `PASSWD_CANT_CHANGE`, `SMARTCARD_REQUIRED`=no. Never `DONT_EXPIRE_PASSWORD`.      |
| Kerberos SPNs         | None required                                                                     |

**Where its bind DN goes:** `ADDS_BIND_DN` in the environment. Example:
`CN=svc-msadmcp-ro,OU=Service Accounts,DC=corp,DC=example,DC=com`.

**Optional extra rights** (only if you want the corresponding tools to work
fully — they degrade gracefully otherwise):

| Extra right                                                        | Enables                                                                                |
|--------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| Read on `CN=Password Settings Container,CN=System,DC=…`            | `adds-mcp` → `list_fine_grained_password_policies` returns PSO contents               |
| Read on `nTSecurityDescriptor` on certificate templates            | `adcs-mcp` → template ACL fields populate on `get_certificate_template`               |
| Read on `msLAPS-Password` / `ms-Mcs-AdmPwd` (LAPS)                 | Future LAPS tools (not yet exposed); do not grant unless you specifically want this   |

By default we recommend granting **none** of the above — the tools still work,
they just return `null` where the account lacks read rights.

### 2. WinRM service account (`adcs-mcp` only)

**Used by:** the WinRM-side tools in `adcs-mcp`
(`list_issued_certificates`, `get_ca_configuration`, `list_ca_role_holders`, …).
Roughly a third of `adcs-mcp`'s 29 tools. If you never call those tools, you
don't need this account at all.

**Purpose:** Run `Get-*` PowerShell (mostly the `PSPKI` module) on each online
issuing CA to read the CA database and configuration.

| Item                  | Value                                                                             |
|-----------------------|-----------------------------------------------------------------------------------|
| Suggested name        | `svc-adcsmcp-ro`                                                                  |
| Object class          | User                                                                              |
| Password              | Same policy as above. Prefer a Kerberos keytab in production and don't put the password in `.env` at all. |
| Group memberships     | On **each** CA host: `Remote Management Users` (for WinRM listen access) + `Event Log Readers` (only if you enable the audit-log tool). |
| CA-role assignment    | On **each** CA host: **CA Auditor** role (assigned via `certsrv.msc` → CA → Security). Auditor is read-only and is exactly what we need. Do **not** grant Manage CA or Issue and Manage Certificates. |
| Logon rights          | Deny interactive; allow only "Access this computer from the network".             |
| Kerberos SPNs         | None (the CA host publishes its own HTTP SPN for WinRM).                          |

**Where its credentials go:** `ADCS_WINRM_USER` and `ADCS_WINRM_PASSWORD`.
Recommended format: `CORP\svc-adcsmcp-ro` for NTLM/negotiate, or
`svc-adcsmcp-ro@CORP.EXAMPLE.COM` for Kerberos.

**Preferred auth: Kerberos.** With Kerberos you can drop the password entirely
and use a keytab; see the [Kerberos setup on the MCP host](#the-mcp-host-itself)
section.

---

## Network access matrix

From wherever the MCP servers run, to wherever they read from. If you're
deploying inside a segmented environment, this is the firewall ask.

| Source (MCP host)   | Destination                         | Protocol | Port  | Required by                                     |
|---------------------|-------------------------------------|----------|-------|-------------------------------------------------|
| MCP host            | Every DC (or a load-balanced VIP)   | TCP TLS  | **636**   | `adds-mcp`, `adcs-mcp` (AD-side), `addns-mcp` |
| MCP host            | DCs (Global Catalog, optional)      | TCP TLS  | 3269  | Not required for any current tool               |
| MCP host            | Each issuing CA in `ADCS_CA_HOSTS`  | TCP TLS  | **5986**  | `adcs-mcp` (WinRM-side tools)                 |
| MCP host            | CRL/AIA web server (`ADCS_CRL_AIA_URLS`) | TCP  | **80 / 443** | `adcs-mcp` (`fetch_crl`, `fetch_ca_certificate`, `check_crl_aia_endpoints`) |
| MCP host            | KDCs (usually the DCs)              | TCP+UDP  | 88    | Only if `ADCS_WINRM_AUTH=kerberos`              |
| MCP host            | KDCs (Kerberos password change)     | TCP+UDP  | 464   | Only if you actively rotate the keytab from Linux |
| MCP host            | Internal DNS resolvers              | UDP/TCP  | 53    | To resolve DC + CA hostnames (and Kerberos)     |
| Any MCP client      | MCP host                            | HTTP     | 8080/8081/8082 | MCP over Streamable HTTP                |

Notes:

- **LDAPS TCP 636 is non-negotiable.** Do not fall back to plain LDAP 389 —
  the LDAPS bind carries the service account password.
- **WinRM 5986 (HTTPS) is required**, not 5985. Plain-HTTP WinRM sends
  credentials in the clear on the wire even with Kerberos auth, and is
  disabled by default on Windows Server.
- **Reverse DNS** for every DC and every CA host must be correct if you use
  Kerberos WinRM auth. `nslookup <ip>` on the MCP host must return the same
  FQDN that the certificate presents.

---

## What each server queries — data sources in detail

### `adds-mcp` — Active Directory Domain Services

| Data | Where it lives (LDAP path) | Which tools read it |
|------|---------------------------|----------------------|
| User accounts | `CN=Users` and any OU under `ADDS_BASE_DN` | `search_users`, `get_user`, `list_locked_out_users`, `list_disabled_users`, `list_stale_users`, `list_recently_changed_users`, `list_password_never_expires` |
| Group memberships | `member` / `memberOf` on user and group objects | `list_user_groups`, `list_group_members` |
| Security & distribution groups | `CN=Users` and any OU | `search_groups`, `get_group`, `list_empty_groups`, `list_privileged_groups` |
| Organizational Units | Any DN under `ADDS_BASE_DN` | `list_ous`, `get_ou`, `list_ou_children`, `get_ou_tree` |
| Computer accounts | `CN=Computers` and OUs | `search_computers`, `get_computer`, `list_domain_controllers`, `list_stale_computers`, `summarize_computer_os` |
| Group Policy Objects | `CN=Policies,CN=System,<base>` (metadata) | `list_gpos`, `get_gpo` |
| GPO links | `gPLink` attribute on OUs, domain root, sites | `find_gpo_links`, `list_links_on_ou` |
| Password / lockout policy | Domain root attributes on `<base>` | `get_password_policy` |
| Fine-grained password policies (PSOs) | `CN=Password Settings Container,CN=System,<base>` | `list_fine_grained_password_policies` |
| FSMO owners | `fSMORoleOwner` on 5 well-known containers under `CN=Schema`, `CN=Partitions`, `CN=RID Manager$`, `CN=Infrastructure`, and the domain root | `list_fsmo_roles` |
| Trust relationships | `CN=System,<base>` (`objectClass=trustedDomain`) | `list_trusts` |
| Sites / subnets / site links | `CN=Sites,CN=Configuration,<forest root>` | `list_sites` |

**Servers this hits:** any domain controller reachable on port 636. `adds-mcp`
uses `ldap3`'s `ServerPool` with `strategy=FIRST` so you can list multiple DCs
in `ADDS_SERVERS` and it will fail over.

### `adcs-mcp` — Active Directory Certificate Services

Split into three data-source halves. All share the `adcs-mcp` process, but each
is independent: you can leave the WinRM half or the web half unconfigured and
still use the AD-side reads.

#### AD-side half (LDAPS to any DC)

All Enterprise CA metadata is published in the Configuration NC:

```
CN=Public Key Services,CN=Services,CN=Configuration,<forest root>
```

| AD child container | Object class | Tools |
|--------------------|--------------|-------|
| `CN=Enrollment Services` | `pKIEnrollmentService` | `list_enrollment_services`, `get_enrollment_service`, `find_templates_offered_by_ca` |
| `CN=Certification Authorities` | `certificationAuthority` | `list_root_cas` |
| `CN=NTAuthCertificates` (single object) | — | `list_ntauth_cas` |
| `CN=Certificate Templates` | `pKICertificateTemplate` | `list_certificate_templates`, `get_certificate_template`, `list_templates_by_eku` |
| `CN=AIA` | `certificationAuthority` | `list_aia_entries` |
| `CN=CDP` (subtree) | `cRLDistributionPoint` / `container` | `list_cdp_entries` |
| `CN=KRA` | `msPKI-PrivateKeyRecoveryAgent` | `list_kra_certificates` |
| `CN=OID` | `msPKI-Enterprise-Oid` | `list_pki_oids` |

**Servers this hits:** the same DCs `adds-mcp` uses. Reuses the same LDAPS
bind.

#### WinRM half (PowerShell on each online issuing CA)

The **CA database** — the actual issued / pending / revoked cert history — is
**not** in AD. It's a Jet database on each issuing CA (`certsrv.mdb`). We
read it by running PowerShell over WinRM.

Tools in this half:

| Tool | PowerShell it runs | Requires on the CA |
|------|-------------------|---------------------|
| `check_ca_hosts_health` | `Get-Service certsvc` + `Get-CertificationAuthority` per host, fanned out over all of `ADCS_CA_HOSTS` | PSPKI; WinRM listen (Auditor optional) |
| `list_issued_certificates` | `Get-CertificationAuthority \| Get-IssuedRequest` (PSPKI) | PSPKI installed; CA Auditor role |
| `list_pending_requests` | ` `` `                                                     | ` `` `                             |
| `list_failed_requests` | ` `` `                                                     | ` `` `                             |
| `list_revoked_certificates` | ` `` `                                                | ` `` `                             |
| `get_certificate_by_serial` | ` `` ` filtered by serial                             | ` `` `                             |
| `count_certificates_by_disposition` | `Get-IssuedRequest \| Group-Object`             | ` `` `                             |
| `get_ca_configuration` | `Get-CACrlDistributionPoint`, `Get-CAAuthorityInformationAccess`, `Get-CATemplate` | PSPKI; CA Auditor |
| `list_ca_role_holders` | `Get-CertificationAuthorityAcl`                            | PSPKI; CA Auditor |
| `list_officer_rights` | `Get-CertificateManagerRights`                              | PSPKI; CA Auditor |
| `get_ca_certificate_chain` | `Get-CertificationAuthorityCertificate`                | PSPKI; CA Auditor |
| `list_ca_backup_settings` | `Get-ItemProperty HKLM:\...\CertSvc\Configuration`      | Read on the CertSvc config registry (usually implied by CA Auditor) |

#### Web half (HTTP(S) to the CRL/AIA distribution points)

Issued certificates carry CDP and AIA extensions pointing at HTTP(S) URLs
(`http://pki.corp.example.com/crl/...`, `.../aia/...`). Clients fetch those to
check revocation and build chains. This half reaches the same endpoints a
client would, so you can confirm they're reachable and the CRL they serve is
current — something the LDAP view (what AD *publishes*) and the WinRM view
(what the CA *holds*) can't tell you.

| Tool | What it does | Notes |
|------|--------------|-------|
| `fetch_crl` | GET a CRL URL, decode it, report `this_update` / `next_update` / `is_expired` / revoked count | Accepts DER or PEM CRLs |
| `fetch_ca_certificate` | GET a CA cert from an AIA URL and decode it | `.crt` / `.cer`, DER or PEM |
| `check_crl_aia_endpoints` | Probe every URL in `ADCS_CRL_AIA_URLS` (or a passed list) for reachability + CRL freshness | One row per endpoint; per-URL errors don't abort the batch |

**Servers this hits:** the CRL/AIA web server(s) named in `ADCS_CRL_AIA_URLS`
(typically an IIS site or load-balanced VIP), over ports 80/443. TLS
validation follows `ADCS_WEB_TLS_VALIDATE` / `ADCS_WEB_CA_CERT_FILE`.

**Standalone half (no directory or WinRM access):**
- `parse_certificate_pem` — pure `cryptography` X.509 decode. Feed it any PEM
  or base64 DER (including offline Root/Policy CA certs).
- `parse_crl_pem` — decode a CRL exported from an offline Root/Policy CA
  (PEM `-----BEGIN X509 CRL-----` or base64 DER) with the same freshness
  summary as `fetch_crl`.

**Servers this hits:** every host you list in `ADCS_CA_HOSTS`. Typically your
two-or-more online Enterprise/Issuing CAs. Not the offline root or policy
CAs — they aren't reachable over the network by design.

### `addns-mcp` — AD-integrated DNS

DNS zones and records that live in Active Directory. Three partitions are
searched; whichever one holds the zone wins:

| Partition | DN | When it's used |
|-----------|----|-----|
| Domain-scoped DNS | `DC=DomainDnsZones,<base>` | Default for new zones since Windows 2003 |
| Forest-scoped DNS | `DC=ForestDnsZones,<base>` | Forest-wide zones (e.g. `_msdcs`) |
| Legacy System container | `CN=MicrosoftDNS,CN=System,<base>` | Pre-2003 or zones explicitly stored in the domain NC |

| Data | Object class / storage | Tools |
|------|------------------------|-------|
| Zone objects | `dnsZone` | `list_zones`, `get_zone`, `list_conditional_forwarders` |
| RR nodes | `dnsNode` (children of a zone) | `list_records`, `get_record`, `list_stale_records`, `list_zone_delegations`, `search_by_name` |
| Record data | `dnsRecord` binary attribute on each node | Decoded in-process per MS-DNSP `DNS_RECORD` |
| Reverse zones | `dnsZone` where `dc=*.in-addr.arpa` / `*.ip6.arpa` | `search_by_ip` |

**Servers this hits:** the same DCs `adds-mcp` uses. All DCs typically hold
the DNS partitions.

---

## Preparing the environment

### Domain controllers

You almost certainly already have LDAPS enabled — modern Windows requires it
for a variety of common tasks. Confirm with:

```powershell
# On any DC:
Get-Certificate -Template DomainController -CertStoreLocation Cert:\LocalMachine\My
netstat -an | Select-String ":636"
```

If port 636 doesn't listen, you're on plain LDAP only and need to publish a
DC cert first (`certreq` with the DomainController template, or the
DomainController template auto-enrolls if it's assigned to Domain
Controllers). This is a one-time domain-wide fix and out of scope for this
README.

### Issuing CAs (adcs-mcp only)

On **each** host you plan to list in `ADCS_CA_HOSTS`:

```powershell
# 1. Enable WinRM over HTTPS with a machine-cert listener.
Enable-PSRemoting -Force
# Ensure an HTTPS listener exists; run this only if one is missing:
New-Item WSMan:\LocalHost\Listener -Transport HTTPS -Address * `
  -CertificateThumbPrint (Get-ChildItem Cert:\LocalMachine\My |
      Where-Object { $_.EnhancedKeyUsageList.FriendlyName -contains 'Server Authentication' } |
      Select-Object -First 1).Thumbprint -Force

# 2. Allow the firewall to accept 5986 from your MCP host.
New-NetFirewallRule -Name winrm-https-mcp -DisplayName "WinRM HTTPS from MCP" `
  -Protocol TCP -LocalPort 5986 -Direction Inbound -Action Allow `
  -RemoteAddress <MCP-HOST-IP>/32

# 3. Install PSPKI (Microsoft-owned, open source).
Install-Module PSPKI -Scope AllUsers -Force

# 4. Add the service account to the Remote Management Users group.
Add-LocalGroupMember -Group "Remote Management Users" -Member "CORP\svc-adcsmcp-ro"

# 5. Grant the Auditor role on the CA. Do this from certsrv.msc:
#    Right-click the CA → Properties → Security tab → Add
#    → CORP\svc-adcsmcp-ro → check "Read" and "Audit" (Auditor role)
# Programmatic equivalent:
$acl = Get-CertificationAuthorityAcl
$acl.Access.Add((New-CertificationAuthorityAccessRule `
    -Identity "CORP\svc-adcsmcp-ro" -Rights ReadOnly,Auditor -AccessControlType Allow))
$acl | Set-CertificationAuthorityAcl -RestartCA
```

### The MCP host itself

Linux, Python 3.11+. If you want Kerberos-authenticated WinRM (recommended):

```bash
# Install Kerberos client + GSSAPI libraries.
sudo apt-get install -y krb5-user libkrb5-dev libssl-dev

# /etc/krb5.conf — minimum sane config for CORP.EXAMPLE.COM.
sudo tee /etc/krb5.conf > /dev/null <<'EOF'
[libdefaults]
    default_realm = CORP.EXAMPLE.COM
    rdns = false
    dns_canonicalize_hostname = true
    forwardable = true

[realms]
    CORP.EXAMPLE.COM = {
        # KDCs are typically your DCs.
        kdc = dc01.corp.example.com
        kdc = dc02.corp.example.com
    }

[domain_realm]
    .corp.example.com = CORP.EXAMPLE.COM
    corp.example.com  = CORP.EXAMPLE.COM
EOF

# Optionally create a keytab for the WinRM service account so
# you don't have to store its password in .env:
sudo ktutil -k /etc/krb5.keytab.svc-adcsmcp-ro
# then export KRB5_CLIENT_KTNAME=/etc/krb5.keytab.svc-adcsmcp-ro in your service unit.
```

You do **not** need to domain-join the MCP host. Any Linux host that can
resolve the domain's DNS, reach the DCs on 636, and (for adcs-mcp) reach the
CAs on 5986 is enough.

---

## Installation

```bash
git clone https://github.com/<your-org>/ms-ad-mcp.git
cd ms-ad-mcp
pip install -e .            # adds-mcp, addns-mcp, and adcs-mcp's AD + web halves
pip install -e ".[adcs]"    # adds pypsrp/kerberos deps for adcs-mcp's WinRM half
```

The base install already covers `adcs-mcp`'s AD-side (LDAP) and CRL/AIA web
(`requests`) halves; the `[adcs]` extra is only needed for the WinRM half.

Or use the pinned images:

```bash
docker build -t adds-mcp  -f Dockerfile        .
docker build -t adcs-mcp  -f Dockerfile.adcs   .   # includes Kerberos client libs
docker build -t addns-mcp -f Dockerfile.addns  .
```

---

## Configuration reference

All configuration is environment-driven and supports `.env` files. Copy
`.env.example` → `.env` and edit.

### Shared LDAPS settings (read by all three servers)

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `ADDS_SERVERS` | ✓ | — | Comma-separated DC hostnames or IPs. First reachable wins. |
| `ADDS_PORT` |   | `636` | LDAPS port. |
| `ADDS_BIND_DN` | ✓ | — | Full DN of the read-only service account. |
| `ADDS_BIND_PASSWORD` | ✓ | — | Password (or use secret-manager templating in the environment). |
| `ADDS_BASE_DN` | ✓ | — | Default search base. Usually the domain NC. |
| `ADDS_DOMAIN` |   | — | DNS/NetBIOS domain name, for display only. |
| `ADDS_TLS_VALIDATE` |   | `true` | Set to `false` **only** for lab work. |
| `ADDS_CA_CERT_FILE` |   | — | Path to a CA bundle if the DC cert isn't chained to system trust. |
| `ADDS_HTTP_HOST` |   | `0.0.0.0` | Bind host for `adds-mcp`. |
| `ADDS_HTTP_PORT` |   | `8080` | Bind port for `adds-mcp`. |
| `ADDS_MAX_PAGE_SIZE` |   | `500` | Hard cap on rows per tool call. |
| `ADDS_DEFAULT_PAGE_SIZE` |   | `50` | Default page size for paged searches. |
| `ADDS_QUERY_TIMEOUT_SECONDS` |   | `30` | Per-query timeout. |
| `ADDS_TRANSPORT` |   | `streamable-http` | `stdio` also supported. |
| `ADDS_LOG_LEVEL` |   | `INFO` | Python logging level. |

### adcs-mcp WinRM settings

| Variable | Required (WinRM tools only) | Default | Description |
|----------|:--------------------------:|---------|-------------|
| `ADCS_CA_HOSTS` | ✓ | — | Comma-separated online issuing CA hostnames. |
| `ADCS_WINRM_USER` | ✓ | — | `CORP\svc-adcsmcp-ro` (NTLM/negotiate) or `svc@CORP.EXAMPLE.COM` (Kerberos). |
| `ADCS_WINRM_PASSWORD` | ✓ (unless keytab) | — | Password. Omit if using Kerberos keytab. |
| `ADCS_WINRM_AUTH` |   | `negotiate` | `negotiate`, `kerberos`, `ntlm`, `basic`, or `credssp`. Prefer `kerberos`. |
| `ADCS_WINRM_PORT` |   | `5986` | WinRM HTTPS port. |
| `ADCS_WINRM_USE_HTTPS` |   | `true` | Should stay `true`. |
| `ADCS_WINRM_CERT_VALIDATION` |   | `true` | Set to `false` only for lab work. |
| `ADCS_WINRM_READ_TIMEOUT` |   | `60` | Seconds. |
| `ADCS_WINRM_OPERATION_TIMEOUT` |   | `45` | Seconds. |
| `ADCS_HTTP_HOST` |   | `0.0.0.0` | Bind host for `adcs-mcp`. |
| `ADCS_HTTP_PORT` |   | `8081` | Bind port for `adcs-mcp`. |
| `ADCS_TRANSPORT` |   | `streamable-http` | Same as `ADDS_TRANSPORT`. |
| `ADCS_LOG_LEVEL` |   | `INFO` | |

### adcs-mcp CRL/AIA web settings

Only needed for the web half (`fetch_crl`, `fetch_ca_certificate`,
`check_crl_aia_endpoints`). All optional — the fetch tools take an explicit URL,
so these only set defaults and TLS behavior.

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `ADCS_CRL_AIA_URLS` |   | — | Comma-separated CDP/AIA HTTP(S) URLs `check_crl_aia_endpoints` probes when called with no arguments. |
| `ADCS_WEB_TIMEOUT` |   | `20` | Per-fetch timeout in seconds. |
| `ADCS_WEB_TLS_VALIDATE` |   | `true` | Validate TLS on `https://` endpoints. `false` only for lab work. |
| `ADCS_WEB_CA_CERT_FILE` |   | — | Optional CA bundle for validating the web server cert. |
| `ADCS_WEB_MAX_CRL_SAMPLE` |   | `25` | Max revoked entries sampled per CRL summary. |

### addns-mcp settings

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `ADDNS_HTTP_HOST` |   | `0.0.0.0` | Bind host for `addns-mcp`. |
| `ADDNS_HTTP_PORT` |   | `8082` | Bind port for `addns-mcp`. |
| `ADDNS_TRANSPORT` |   | `streamable-http` | |
| `ADDNS_LOG_LEVEL` |   | `INFO` | |

All `ADDS_*` variables above are also read by `addns-mcp` (it reuses the same
LDAPS bind).

---

## Running the servers

### Locally with the installed entrypoints

```bash
adds-mcp    # HTTP :8080/mcp
adcs-mcp    # HTTP :8081/mcp
addns-mcp   # HTTP :8082/mcp
```

### Docker

```bash
docker run --rm -p 8080:8080 --env-file .env adds-mcp
docker run --rm -p 8081:8081 --env-file .env adcs-mcp
docker run --rm -p 8082:8082 --env-file .env addns-mcp
```

### systemd (all three on one host)

Minimal unit — repeat for each server. Use secret manager or `EnvironmentFile`
from a locked-down path; do not stash secrets in the unit itself.

```ini
# /etc/systemd/system/adds-mcp.service
[Unit]
Description=ms-ad-mcp adds-mcp (read-only AD DS MCP server)
After=network-online.target
Wants=network-online.target

[Service]
User=msadmcp
Group=msadmcp
EnvironmentFile=/etc/ms-ad-mcp/adds.env
ExecStart=/opt/ms-ad-mcp/venv/bin/adds-mcp
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

---

## Wiring into an MCP client

All three servers speak MCP over **Streamable HTTP** by default. The endpoint
path is `/mcp`, so a client config looks like:

```json
{
  "mcpServers": {
    "ms-ad-adds":  { "url": "https://mcp.internal.example.com:8080/mcp" },
    "ms-ad-adcs":  { "url": "https://mcp.internal.example.com:8081/mcp" },
    "ms-ad-addns": { "url": "https://mcp.internal.example.com:8082/mcp" }
  }
}
```

Front them with a TLS-terminating proxy (nginx / Caddy / Traefik) if you're
exposing them beyond localhost. This repo doesn't terminate TLS itself.

For stdio-only clients, set `ADDS_TRANSPORT=stdio` (equivalently
`ADCS_TRANSPORT`, `ADDNS_TRANSPORT`) and launch the command directly.

---

## Security posture

- **Read-only end to end.** `ldap3.Connection(read_only=True)` at the client
  layer; every tool uses `SEARCH` only. No `add`, `modify`, `delete`,
  `modifyDN`. On the CA hosts we execute only `Get-*` PowerShell cmdlets and
  read-only registry reads.
- **Least privilege.** Both service accounts described above are unprivileged
  domain users. The WinRM account gets one narrowly-scoped role (`Auditor`)
  on each CA — nothing else.
- **Two-account separation.** LDAPS and WinRM use different accounts on
  purpose; compromise of one doesn't cross services and each rotates on its
  own schedule.
- **LDAPS with cert validation.** `ADDS_TLS_VALIDATE=true` is the default.
  If your DC certs chain through a private root, ship the root as a bundle
  and set `ADDS_CA_CERT_FILE`. Don't disable validation.
- **Prefer Kerberos.** For WinRM, `ADCS_WINRM_AUTH=kerberos` with a keytab
  eliminates the plaintext password from `.env` entirely.
- **RFC 4515 filter escaping.** All user-controlled substrings in LDAP
  filters go through an escape helper before hitting the DC.
- **Result caps.** `ADDS_MAX_PAGE_SIZE` (default 500) hard-caps any single
  tool's return size to keep responses bounded and prevent inadvertent DC
  load.
- **No writes anywhere.** If a future tool ever needed to mutate state, that
  belongs in a **different** MCP server with a **different** service account.
  We won't add write capabilities to these servers.

---

## Troubleshooting

**`LDAPBindError: invalidCredentials`**
- The service account password is wrong, or the bind DN doesn't resolve.
- Test with `ldapsearch -H ldaps://dc01 -x -D "CN=svc-…" -W -b "DC=corp,…" "(sAMAccountName=administrator)"`.

**`ldap3.core.exceptions.LDAPSSLConfigurationError` / `LDAPSocketOpenError`**
- The DC cert isn't trusted on the MCP host. Point `ADDS_CA_CERT_FILE` at
  your root CA bundle, or verify the DC cert isn't expired
  (`openssl s_client -connect dc01:636 -showcerts`).

**`kerberos: Server not found in Kerberos database`**
- The CA host doesn't have an HTTP SPN, **or** DNS reverse lookup returned
  a different name than the one you're connecting to.
- Verify: `setspn -L <ca-host>` on Windows and `nslookup <ca-ip>` on Linux.

**`Access is denied` in a PowerShell tool response**
- WinRM auth succeeded but the service account lacks the CA role.
- On the CA: `certutil -getreg CA\Security` shows the ACL; re-grant Auditor.

**`Get-CertificationAuthority : The term is not recognized`**
- PSPKI isn't installed on the CA. Run `Install-Module PSPKI -Scope AllUsers`.

**Records come back as strings of gibberish from addns-mcp**
- Some ldap3 builds UTF-8-decode the `dnsRecord` binary attribute. The
  decoder tolerates this via a `latin-1` re-encode, but if you see garbage,
  set the `dnsRecord` attribute to binary in your ldap3 config or file an
  issue with the exact ldap3 version.

**`WinRMUnavailable: pypsrp is not installed`**
- The `[adcs]` extra wasn't installed. Run `pip install ".[adcs]"` or use
  `Dockerfile.adcs` which does this for you.

---

## Tool reference

### `adds-mcp` — 35 tools

| Domain | Tools |
|--------|-------|
| Users | `search_users`, `get_user`, `list_user_groups`, `list_locked_out_users`, `list_disabled_users`, `list_stale_users`, `list_recently_changed_users`, `list_password_never_expires` |
| Groups | `search_groups`, `get_group`, `list_group_members`, `list_empty_groups`, `list_privileged_groups` |
| OUs | `list_ous`, `get_ou`, `list_ou_children`, `get_ou_tree` |
| Computers | `search_computers`, `get_computer`, `list_domain_controllers`, `list_stale_computers`, `summarize_computer_os` |
| Group Policy | `list_gpos`, `get_gpo`, `find_gpo_links`, `list_links_on_ou` |
| Domain | `get_domain_info`, `get_password_policy`, `list_fine_grained_password_policies`, `list_fsmo_roles`, `list_trusts`, `list_sites` |
| Escape hatch | `ldap_search`, `get_object_by_dn`, `count_objects` |

Attribute decoding: SIDs → `S-1-5-…`, GUIDs → canonical form, FILETIMEs →
ISO-8601 (null for AD's zero and "never" values), `userAccountControl` →
decoded flag list + booleans, `groupType` → scope + security/distribution,
`lockoutDuration` / `maxPwdAge` and the `msDS-*` durations of fine-grained
password policies → ISO-8601 durations (`"never"` for AD's "no limit" value),
`gPLink` → structured list of GPO links with enforced/disabled flags.
`locked_out` and `password_expired` come from the constructed
`msDS-User-Account-Control-Computed` (AD never sets those bits in the stored
`userAccountControl`) and are null where it is not requested, e.g. on
computers; `flags` includes `LOCKOUT` / `PASSWORD_EXPIRED` when it sets them.

### `adcs-mcp` — 29 tools

**AD-side (LDAPS):**
`list_enrollment_services`, `get_enrollment_service`, `list_root_cas`,
`list_ntauth_cas`, `list_certificate_templates`, `get_certificate_template`,
`list_templates_by_eku`, `find_templates_offered_by_ca`, `list_aia_entries`,
`list_cdp_entries`, `list_kra_certificates`, `list_pki_oids`.

**WinRM-side (PowerShell + PSPKI):**
`check_ca_hosts_health`, `list_issued_certificates`, `list_pending_requests`,
`list_failed_requests`, `list_revoked_certificates`, `get_certificate_by_serial`,
`count_certificates_by_disposition`, `get_ca_configuration`,
`list_ca_role_holders`, `list_officer_rights`, `get_ca_certificate_chain`,
`list_ca_backup_settings`.

**Web-side (HTTP(S) to CRL/AIA endpoints):**
`fetch_crl`, `fetch_ca_certificate`, `check_crl_aia_endpoints`.

**Standalone:**
`parse_certificate_pem` — decode any PEM or base64 DER cert
(subject/issuer/EKU/SAN/key usage/fingerprints/PEM). `parse_crl_pem` — decode
a PEM/DER CRL (issuer, this/next update, revoked entries).

### `addns-mcp` — 9 tools

`list_zones`, `get_zone`, `list_records`, `get_record`, `list_stale_records`,
`list_conditional_forwarders`, `list_zone_delegations`, `search_by_name`,
`search_by_ip`.

Decodes `dnsRecord` blobs for A, AAAA, CNAME, NS, PTR, MX, SRV, TXT, SOA;
aging timestamps (hours since 1601-01-01) are surfaced as ISO-8601.

---

## Repository layout

```
src/
  adds_mcp/          # AD DS server
    __init__.py
    config.py        # ADDS_* settings from env
    client.py        # ldap3 wrapper (read_only=True, filter/DN escaping, paged search)
    formatting.py    # SID / GUID / FILETIME / UAC / groupType decoders
    server.py        # FastMCP entrypoint (Streamable HTTP)
    tools/           # users, groups, ous, computers, gpos, domain, search

  adcs_mcp/          # AD CS server (reuses adds_mcp.client for LDAPS)
    __init__.py
    config.py        # ADCS_* + reuses ADDS_* for LDAPS
    ldap_source.py   # Points reused ldap client at CN=Public Key Services
    winrm_source.py  # pypsrp WinRM PowerShell runner (optional extra)
    cert_utils.py    # X.509 parsing (cryptography)
    server.py
    tools/           # cas, templates, trust, issued, admin, parsing

  addns_mcp/         # AD-integrated DNS server (reuses adds_mcp.client for LDAPS)
    __init__.py
    config.py        # ADDNS_* + reuses ADDS_*
    ldap_source.py   # DomainDnsZones + ForestDnsZones + legacy MicrosoftDNS
    records.py       # MS-DNSP DNS_RECORD blob decoder
    server.py
    tools/           # zones, records, search
```
