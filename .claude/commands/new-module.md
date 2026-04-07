---
description: Create a new analysis module in internal/analysis/ with tests
argument-hint: "<module-name> <description>"
---

Create a new analysis module for adpath.

Module name: $1
Description: $2

Steps:
1. Create `internal/analysis/$1.go` following the pattern of `acl.go` and `kerberos.go`
2. Define the main struct and constructor
3. Implement the Analyze() method returning `[]Finding`
4. Each Finding must include: Title, Severity (Critical/High/Medium/Low), CVSS float, AffectedObject, Description, Remediation
5. Add LDAP attribute queries needed in `internal/ldap/enumerate.go` if missing
6. Wire up the new module in the appropriate cobra command in `cmd/adpath/`
7. Create `internal/analysis/$1_test.go` with at least 3 test cases
8. Update HTML report in `internal/report/html.go` to include the new module's findings

Follow existing error handling patterns: `fmt.Errorf("$1: %w", err)`
