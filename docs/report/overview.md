# HTML Report Overview

The `enum` command generates a self-contained HTML report after every run.

## Key properties

- **Single file** — all CSS, JavaScript, and data are embedded inline. No server, no external requests.
- **Works offline** — share via email or archive. Analysts can open it on air-gapped systems.
- **Dark/light theme** — toggle in the top-right corner; preference saved to localStorage.
- **Global search** — search bar above tabs finds matches across all sections simultaneously, shows match count per tab, auto-jumps to the tab with most matches.
- **D3.js attack path graph** — interactive force-directed graph; node size represents path count, red arrows indicate admin-level paths, hover tooltips, zoom/pan, Reset Zoom button.

## Report path

By default the report is saved next to the binary with a timestamp in the name:

```
corp.local_2026-04-22_10-30-45.html
```

Override with `--report`:

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --report /tmp/engagement_corp.html
```

## Summary page

The first tab shows an executive summary:

- Object counts (users, groups, computers)
- Findings bar chart by severity (Critical / High / Medium / Info)
- Summary cards — each card is **clickable** and jumps to the corresponding tab:
  - Attack Paths, Kerberoastable, AS-REP, Dangerous ACLs, Delegation, Stale accounts, ADCS, Shadow Credentials, etc.

## Exploit / Fix accordion

Every finding card (attack path, ACL, delegation, ADCS, etc.) has a collapsible **Exploit / Fix** section with:

- Contextual exploit commands (bloodyAD, GetUserSPNs, getST.py, certipy, etc.) filled with discovered names/hashes
- Remediation steps

## MITRE ATT&CK badges

Every finding section and individual finding row includes a purple **T-code badge** linking to the corresponding MITRE ATT&CK technique page (e.g. `T1558.003` for Kerberoasting). Click any badge to open the technique on attack.mitre.org.

## Section tooltips

Every section header has a `?` icon. Hover to get a brief explanation of what the section checks and why it matters.
