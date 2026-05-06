# Authentication

morok supports four authentication methods. The same flags work on every command.

## Password

Standard username + password bind. Works with both `DOMAIN\user` and `user@domain` formats.

```bash
morok enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

## Pass-the-Hash (NTLM)

Use an NT hash instead of a plaintext password. Useful after extracting hashes with secretsdump, mimikatz, or a previous compromise.

```bash
morok enum -d corp.local -u administrator \
  -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  --dc 10.0.0.1
```

The `-H` / `--hashes` flag accepts both `LM:NT` and `NT`-only formats:

```bash
-H :8846f7eaee8fb117ad06bdd830b7586c   # NT only (recommended)
-H aad3b435...:8846f7ea...             # LM:NT
```

!!! note
    The LM part is ignored. Use any value or leave it as `aad3b435b51404eeaad3b435b51404ee` (empty LM hash).

## Pass-the-Ticket (Kerberos ccache)

Use an existing Kerberos TGT from a `.ccache` file. Common after `getTGT.py` (impacket), `Rubeus asktgt`, or ticket extraction from lsass.

```bash
# Obtain TGT with impacket
getTGT.py corp.local/administrator:'Password1' -dc-ip 10.0.0.1

# Use the ticket
morok enum -d corp.local --ccache administrator.ccache --dc dc01.corp.local
```

!!! warning
    `--ccache` requires `--dc` to be a **hostname**, not an IP address. Kerberos uses DNS for service name resolution. If you provide an IP, morok performs a reverse DNS lookup automatically.

!!! warning
    `--ccache` and `--proxy` cannot be used together. Kerberos authentication requires a direct TCP connection to the KDC and cannot be routed through a SOCKS5 proxy.

## Anonymous bind

If no credentials are provided, morok attempts an anonymous LDAP bind. Modern AD environments restrict anonymous reads to RootDSE only. morok detects and reports if anonymous reads expose more than that.

```bash
morok enum -d corp.local --dc 10.0.0.1
```

Output shows what is and isn't accessible:

```
  no credentials — anonymous bind (limited enumeration)
  RootDSE                      ✓ readable
  hint                         obtain any domain account for full enumeration
```

If the domain allows anonymous LDAP reads beyond RootDSE, morok adds a **Medium** finding: "Anonymous LDAP read enabled."

## Auth flags reference

| Flag | Short | Description |
|------|-------|-------------|
| `--domain` | `-d` | Target domain FQDN (required) |
| `--username` | `-u` | Username |
| `--password` | `-p` | Password |
| `--hashes` | `-H` | NT hash (`LM:NT` or `:NT`) |
| `--ccache` | | Path to Kerberos `.ccache` file |
| `--dc` | | DC IP or hostname (autodetects if omitted) |
| `--verbose` | `-v` | Show all LDAP queries |
