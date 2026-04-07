---
description: Implement or improve the --ai-report Pro feature using anthropic-sdk-go
argument-hint: "[module-name or 'all']"
---

Work on the `--ai-report` Pro feature for adpath.

Target module: $ARGUMENTS (default: all findings)

Tasks:
1. In `internal/report/html.go` — add AI-generated analysis section per finding
2. The Anthropic SDK call should:
   - Use `claude-opus-4-6` model (Pro tier quality)
   - Send: finding title, severity, affected object, raw LDAP attributes
   - Request: executive summary, attack scenario, business impact, remediation steps
   - Handle API errors gracefully — fall back to standard report if API unavailable
3. API key loaded via `godotenv` from `.env` — variable name `ANTHROPIC_API_KEY`
4. Gate behind `--ai-report` flag (cobra bool flag, default false)
5. Add loading indicator while waiting for API response
6. Output tokens should be ≤1024 per finding to keep costs low for users

This is a Pro monetization feature — quality of output directly affects conversion rate.
