# adpath — Active Directory Attack Path Enumerator

## Project Overview
Go CLI tool for AD attack path enumeration. Open-source core + paid Pro tier (~$300–500/yr).
GitHub: github.com/YakinAnd/adpath | Current version: v0.3.0

## Build & Test
```bash
go build ./cmd/adpath/...          # build
go test ./...                       # all tests
go test ./internal/... -v           # verbose internal tests
go vet ./...                        # vet
golangci-lint run                   # lint (if installed)
```

## Architecture
```
cmd/adpath/main.go                  # entrypoint, cobra root
internal/ldap/
  client.go                         # LDAP connection, auth
  enumerate.go                      # LDAP queries, object fetching
internal/graph/
  model.go                          # Node/Edge types
  builder.go                        # builds AD graph from LDAP data
  paths.go                          # attack path traversal
internal/analysis/
  kerberos.go                       # Kerberoastable, AS-REP detection
  acl.go                            # dangerous ACL parsing (GenericAll, WriteDACL, etc.)
  delegation.go                     # delegation checks (v0.3)
internal/report/
  html.go                           # HTML report generation
```

## Commands (v0.3)
- `enum` — LDAP enumeration + attack paths + HTML report
- `kerberos` — Kerberoastable/AS-REP detection
- `acl` — dangerous ACLs: GenericAll, WriteDACL, WriteOwner, ForceChangePassword, AddMember

## Dependencies
- github.com/spf13/cobra
- github.com/go-ldap/ldap/v3
- github.com/fatih/color
- github.com/olekukonko/tablewriter
- github.com/anthropics/anthropic-sdk-go (for --ai-report)
- github.com/joho/godotenv

## Coding Conventions
- Error handling: always wrap with `fmt.Errorf("context: %w", err)`
- No global state — pass dependencies explicitly
- Windows Security Descriptor parsing: use binary format, not string
- ACL analysis: use SID-based lookups, not name-based
- New analysis modules go in `internal/analysis/`
- New commands wire up in `cmd/adpath/` with cobra
- HTML report: severity levels map to CVSS scores (Critical≥9, High≥7, Medium≥4, Low<4)

## Test Lab
- GOAD-Light on VMware Fusion
- Workspace: 458cf1-goad-light-vmware
- Test with real AD data from GOAD before any release

## Important Patterns
- `--ai-report` flag triggers Anthropic SDK call (Pro feature)
- API key loaded via godotenv from `.env`
- HTML report is the primary output format
- Attack paths are directed graphs: source → edge_type → target

## Do NOT
- Add global variables
- Use string parsing for Windows Security Descriptors
- Break existing CLI interface (backward compat required)
- Commit `.env` or any credentials
