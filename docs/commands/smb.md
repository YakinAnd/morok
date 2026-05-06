# morok smb

Check SMB signing status on the domain controller — no credentials required, only TCP access to port 445.

## Usage

```bash
morok smb -d <domain> --dc <dc>
```

## How it works

morok sends a raw SMB2 Negotiate request to the DC and reads the `SecurityMode` field from the response:

| SecurityMode | Meaning |
|---|---|
| `0x0002` (signing required) | ✓ Safe — NTLM relay to SMB not possible |
| `0x0001` (signing enabled, not required) | ⚠ Medium — relay possible if attacker downgrades |
| `0x0000` (signing disabled) | ✗ High — NTLM relay fully possible |

## Output example

```
  SMB SIGNING
  host                         192.168.56.10
  dialect                      SMB 3.1.1
  signing                      NOT required

  [High] SMB signing not required
         SMB signing is not required on 192.168.56.10 (SecurityMode=0x0001).
         An attacker with network position can perform NTLM relay attacks...
```

## Flags

| Flag | Description |
|---|---|
| `-d` / `--domain` | Target domain FQDN (required) |
| `--dc` | DC IP or hostname (defaults to domain if omitted) |

## Notes

- No credentials required — check runs before authentication.
- This check is also included in `morok enum` output (summary line + HTML report).
- Remediate: GPO → Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → **"Microsoft network server: Digitally sign communications (always)"** = Enabled.
- Domain Controllers in Windows Server 2022+ require SMB signing by default.
