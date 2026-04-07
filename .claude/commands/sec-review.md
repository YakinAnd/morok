---
description: Security review focused on AD/LDAP attack surface and credential exposure
---

Review the current code changes or specified file for security issues specific to adpath:

1. **Credential exposure** — API keys, LDAP passwords, bind credentials hardcoded or logged
2. **LDAP injection** — unsanitized input in LDAP filters (use ldap.EscapeFilter)
3. **SID/ACL parsing** — buffer overflows or incorrect offset calculations in binary SD parsing
4. **Error messages** — sensitive AD info (usernames, domain structure) leaked in errors
5. **--ai-report flag** — Anthropic API key not exposed in logs or output
6. **TLS** — LDAP connections using StartTLS or LDAPS where required

Report findings with severity (Critical/High/Medium/Low) and exact line references.
Be concise — only real issues, no style nitpicks.
