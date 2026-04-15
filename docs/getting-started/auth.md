# Authentication

adpath supports four authentication methods. All commands accept the same auth flags.

## Password

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

## Pass-the-Hash (NTLM)

Use an NT hash instead of a plaintext password. Useful when you have a hash from secretsdump, mimikatz, or a previous compromise.

```bash
adpath enum -d corp.local -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c --dc 10.0.0.1
```

The `-H` flag accepts both `LM:NT` and `NT` formats.

## Pass-the-Ticket (Kerberos ccache)

Use an existing Kerberos ticket from a `.ccache` file. Requires the DC to be specified by FQDN (not IP), as Kerberos requires name resolution.

```bash
# Obtain a TGT first (impacket)
getTGT.py corp.local/administrator:'Password1' -dc-ip 10.0.0.1

# Use the ticket
adpath enum -d corp.local --ccache administrator.ccache --dc dc01.corp.local
```

!!! note
    When using `--ccache`, `--dc` must be a hostname, not an IP. adpath performs a reverse DNS lookup automatically if you provide an IP.

## Anonymous bind

If no credentials are provided, adpath attempts an anonymous LDAP bind. Modern AD environments typically restrict anonymous reads to RootDSE only, but some legacy domains allow broader enumeration.

```bash
adpath enum -d corp.local --dc 10.0.0.1
```

## Common flags

| Flag | Short | Description |
|------|-------|-------------|
| `--domain` | `-d` | Target domain (required) |
| `--username` | `-u` | Username |
| `--password` | `-p` | Password |
| `--hashes` | `-H` | NT hash (`LM:NT` or `NT`) |
| `--ccache` | | Path to Kerberos ccache file |
| `--dc` | | Domain controller IP or hostname |
| `--verbose` | `-v` | Verbose LDAP output |
