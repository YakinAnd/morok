# morok enum

Full AD enumeration — runs all analysis modules and generates a self-contained HTML report.

## Usage

```bash
morok enum -d <domain> -u <user> -p <pass> --dc <dc> [flags]
```

## Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--domain` | `-d` | Target domain FQDN (required) | |
| `--username` | `-u` | Username | |
| `--password` | `-p` | Password | |
| `--hashes` | `-H` | NT hash for Pass-the-Hash (`LM:NT` or `:NT`) | |
| `--ccache` | | Path to Kerberos ccache file | |
| `--dc` | | DC IP or hostname | |
| `--proxy` | | SOCKS5 proxy URL (`socks5://host:port`) | |
| `--ldaps` | | Force LDAPS (port 636) from the start — auto-detected and applied automatically when the DC enforces signing, even without this flag | |
| `--scope` | | Restrict enumeration to specific OU/DN | |
| `--report` | | HTML report output path | `<domain>_<timestamp>.html` |
| `--json` | | Export AD objects as JSON to directory (e.g. `json_out/`) | |
| `--max-depth` | | BFS depth for attack path search | `10` |
| `--sysvol` | | Scan SYSVOL share for GPP cPassword XML, executables, archives, scripts outside `Scripts\` — off by default (slow over proxy/tunnels) | |
| `--stealth` | | Stealth mode — minimal LDAP queries, no GC, no ACL/ADCS/GPO/delegation | |
| `--verbose` | | Show all findings without truncation (disables 5-item limit per section) | |
| `--quiet` | | Quiet mode — print only risk verdict line (for CI/scripting) | |
| `--vuln-check` | | Active SMB probes to confirm vulnerability candidates found in phase 1 — generates SMB traffic to candidate hosts (port 445) | |
| `--follow-trusts` | | Enumerate trusted domains reachable from the current DC — opt-in; verify these domains are in scope before use | off |

## What it runs

`enum` executes every module in sequence and prints a summary for each. Use standalone commands (e.g. `morok acl`) to see full output with exploit next steps.

| Module | What it checks |
|--------|----------------|
| **RootDSE** | Domain, forest, functional level, responding DC — no auth required |
| **LDAP Security** | Signing/channel binding, SASL mechanisms, anonymous read |
| **Audit Policy** | Legacy audit categories, AD Recycle Bin, machine account quota |
| **Enumeration** | Users, groups, computers (forest-wide via Global Catalog) |
| **Graph** | In-memory attack path graph |
| **Attack Paths** | BFS to DA, EA, Backup Ops, Account Ops, Server Ops, Print Ops, DNSAdmins, GPO Creator Owners |
| **Kerberos** | Kerberoastable + AS-REP roastable accounts |
| **ACL** | GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember, DCSync |
| **Delegation** | Unconstrained, constrained, RBCD |
| **GPO** | Password policy audit, GPO write ACL, GPP cpassword |
| **Exposure** | Stale accounts, krbtgt age, LAPS coverage, passwords in descriptions |
| **PSO** | Fine-Grained Password Policy (msDS-PasswordSettings objects) |
| **ADCS** | ESC1–ESC9, ESC11, ESC13 certificate template vulnerabilities |
| **Protected Users** | Privileged accounts not in Protected Users group |
| **AdminSDHolder** | Orphaned adminCount=1, custom backdoor ACEs |
| **Trusts** | Trust direction/type, SID filtering, FSPs in privileged groups |
| **Shadow Credentials** | Write access to msDS-KeyCredentialLink on DA/EA/DC objects |
| **SMB Signing** | SMB signing status on the DC (port 445) — NTLM relay risk |
| **SYSVOL** | GPP Preferences XML (cPassword/MS14-025), executables, archives, scripts outside `Scripts\` — only with `--sysvol` |
| **Vulnerability Checks** | Known-CVE candidate detection from already-collected OS build/MAQ/LDAP-signing data; `--vuln-check` adds active SMB probes to confirm EternalBlue, Zerologon, PrintNightmare |

## Vulnerability checks (`--vuln-check`)

`enum` runs vulnerability detection in two phases:

**Phase 1 — candidate detection (always runs, no `--stealth`)**

Uses data already collected during normal enumeration — `operatingSystemVersion` build numbers, Machine Account Quota, and LDAP signing enforcement status — to flag hosts that are *plausibly* vulnerable to known CVEs. This generates **zero additional network traffic**.

| CVE | Name | Detection basis |
|---|---|---|
| MS17-010 | EternalBlue | OS build older than March 2017 CU (all hosts) |
| CVE-2020-1472 | Zerologon | DC build older than August 2020 CU |
| CVE-2021-42278/42287 | noPac | Machine Account Quota > 0 + DC build older than November 2021 CU |
| CVE-2021-36942 | PetitPotam | LDAP signing not enforced (EFS RPC coercion path open) |
| CVE-2021-1675/34527 | PrintNightmare | OS build older than July 2021 CU (all hosts) |

Findings from this phase are marked `[?] candidate` (yellow) — the build check cannot see revision-level patch state from LDAP alone, so it errs toward flagging.

**Phase 2 — active confirmation (`--vuln-check` only)**

For each phase-1 candidate, morok opens an SMB connection (port 445) to the host and runs a targeted probe:

- **EternalBlue** — anonymous SMBv1 `Trans2 SESSION_SETUP` probe (same technique as `nmap --script smb-vuln-ms17-010`); a vulnerable host responds `STATUS_INSUFF_SERVER_RESOURCES`.
- **Zerologon** — sends `NetrServerAuthenticate2` over the Netlogon RPC pipe with an all-zero client credential; a vulnerable DC accepts it (`STATUS_SUCCESS`).
- **PrintNightmare** — checks whether the `\spoolss` named pipe is reachable, confirming the Print Spooler service is running.

Confirmed findings are marked `[!] CONFIRMED` (red). If the probe cannot reach the host (firewalled, wrong network path, service down), the finding is marked `[~] unverified` (grey) and the build-based candidate status stands.

**noPac and PetitPotam stay candidate-only** — there is no safe active probe for either in morok; confirming them requires exploitation tooling (`noPac.py`, `PetitPotam.py`) that is out of scope for a passive/probe-only enumerator. Treat these two as "verify manually before treating as confirmed."

**Caveat:** `--vuln-check` generates real SMB traffic to every candidate host, which may trigger IDS/EDR alerts. Omit the flag (or use `--stealth`) for a fully passive run. For independent verification outside morok, `nmap --script smb-vuln-ms17-010 -p445 <host>` cross-checks the EternalBlue finding.

```bash
# Passive candidates only (default, zero extra traffic)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Active confirmation via SMB probes
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --vuln-check
```

## Multi-domain / trust following (`--follow-trusts`)

By default `enum` only enumerates the target domain — trusted domains are enumerated but **not automatically followed**. Trust following is opt-in via `--follow-trusts`, because it means morok will connect to and run a full LDAP enumeration against DCs in a *different* domain than the one you authenticated against — a scope boundary that should be confirmed with the client before crossing it, not assumed.

With `--follow-trusts`, for each reachable trusted domain in the same forest, morok runs a full enumeration and merges results:

- CLI output prints a `══ domain.local ══` separator before each domain's findings
- HTML report shows a domain tab per domain on all finding tables
- Computers and users are deduplicated by ObjectSID — no duplicates when the GC query and trusted-domain enumeration overlap

Without the flag, trust relationships are still reported (see the **Trusts** module — direction, type, SID filtering), just not enumerated.

To enumerate a specific secondary domain only (without following all trusts), target its DC directly with `--dc`.

```bash
# Follow all reachable trusted domains
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --follow-trusts
```

## HTML report

The report is saved to `<domain>_<timestamp>.html` by default (next to the binary). Specify a custom path with `--report`.

```bash
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/corp.html
```

The report is a **self-contained single HTML file** — no server needed, works offline, can be emailed or archived.

## JSON export

```bash
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --json ./json_out/
```

Generates `users.json`, `groups.json`, `computers.json`, `domains.json`. The format is compatible with **BloodHound CE v5** — import via: BloodHound CE → Administration → File Ingest.

## Examples

```bash
# Standard run
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
morok enum -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c \
  --dc 10.0.0.1 --report /tmp/corp.html

# Pass-the-Ticket
morok enum -d corp.local --ccache admin.ccache --dc dc01.corp.local

# Through SOCKS5 proxy
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --proxy socks5://127.0.0.1:1080

# Scoped to Finance OU
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --scope "OU=Finance,DC=corp,DC=local"

# Full run + JSON export
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/corp.html --json ./json_out/

# Quiet mode — single line output for CI pipelines
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --quiet

# Verbose — show all findings without 5-item truncation
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --verbose

# SYSVOL scan (opt-in — slow over proxy/tunnels)
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --sysvol

# Vulnerability checks with active SMB confirmation
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 --vuln-check
```
