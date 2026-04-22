# adpath computers

Enumerate all AD computers and display a summary table.

## Usage

```bash
adpath computers -d <domain> -u <username> -p <password> [--dc <dc>]
```

## Output

**Summary section** (always shown):

- Total computer count
- Enabled / disabled counts
- LAPS-managed hosts count (green if > 0, yellow warning if 0)
- Hosts with unconstrained delegation (red — high-risk)

**Per-computer table** with dynamic column widths:

| Column | Description |
|---|---|
| HOSTNAME | dNSHostName (falls back to sAMAccountName) |
| OS | operatingSystem + operatingSystemVersion |
| ENABLED | Account active status |

**Row colors:**

- Red — unconstrained delegation (high impact — TGT theft possible)
- Dim — disabled computer accounts

## Examples

```bash
# Basic enumeration
adpath computers -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1

# Pass-the-Hash
adpath computers -d corp.local -u administrator -H :8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1
```

## Flags

All standard connection flags apply — see [Authentication](../getting-started/auth.md).

## Notes

- Uses **forest-wide Global Catalog** (port 3268) enumeration — same as `adpath enum`. All computers across all domains in the forest are shown.
- Falls back to domain-only enumeration if GC is unavailable.
- For full delegation analysis (unconstrained, constrained, RBCD), use [`adpath delegation`](delegation.md).
