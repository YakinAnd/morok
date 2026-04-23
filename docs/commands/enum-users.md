# adpath enum-users

Enumerate valid AD usernames via Kerberos AS-REQ **without credentials** — only network access to port 88 (Kerberos) on the DC is required.

## Usage

```bash
adpath enum-users -d <domain> --dc <dc> --wordlist users.txt
```

## How it works

For each username in the wordlist, adpath sends a raw AS-REQ (TGT request) to the KDC and classifies the response:

| Response | Meaning | Output |
|---|---|---|
| `KDC_ERR_PREAUTH_REQUIRED` (25) | User exists, pre-auth required | `[+] EXISTS` |
| `AS-REP` received | User exists, **no pre-auth** — AS-REP roastable | `[!] EXISTS (AS-REP roastable)` |
| `KDC_ERR_CLIENT_REVOKED` (18) | Account disabled or locked | `[-] DISABLED` |
| `KDC_ERR_KEY_EXPIRED` (23) | User exists, password expired | `[~] EXISTS (password expired)` |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) | User not found | (suppressed) |

Not-found results are suppressed by default — only valid accounts are printed.

## Output example

```
  ENUM-USERS
  domain                   sevenkingdoms.local
  kdc                      192.168.56.10:88
  wordlist size            50

  [+] jon.snow             EXISTS
  [!] brandon.stark        EXISTS  (AS-REP roastable — no pre-auth)
  [-] oldaccount           DISABLED
  [~] cersei               EXISTS  (password expired)
  [+] administrator        EXISTS

  found                    5 / 50
```

## Examples

```bash
# Basic username enumeration
adpath enum-users -d corp.local --dc 10.0.0.1 --wordlist users.txt

# With a large wordlist (e.g. statistically common AD usernames)
adpath enum-users -d corp.local --dc 10.0.0.1 --wordlist /usr/share/wordlists/usernames.txt
```

## Flags

| Flag | Description |
|---|---|
| `-d` / `--domain` | Target domain FQDN (required) |
| `--dc` | DC IP or hostname (defaults to domain if omitted) |
| `--wordlist` | Path to wordlist file — one username per line (required) |

## Wordlist format

One username per line. Lines starting with `#` and blank lines are ignored:

```
administrator
jon.snow
cersei
# this line is a comment
brandon.stark
```

## Notes

- No credentials required — only TCP access to port 88 on the DC.
- Discovered AS-REP roastable accounts can be cracked offline — use `adpath kerberos` with valid credentials to extract the full AS-REP hash.
- This technique is detectable if the DC logs failed AS-REQ attempts (event ID 4768 with `Failure Code: 0x6`). Use with awareness.
