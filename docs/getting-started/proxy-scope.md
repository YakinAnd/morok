# Proxy & Scope

## SOCKS5 proxy (`--proxy`)

Route all LDAP/LDAPS traffic through a SOCKS5 proxy. This is useful when the target DC is only reachable through a pivot host (Chisel, SSH tunnel, Ligolo-ng, etc.).

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --proxy socks5://127.0.0.1:1080
```

### How it works

adpath replaces the standard TCP dialer with a SOCKS5 dialer. The proxy establishes the TCP connection to the DC on adpath's behalf. DNS resolution happens **on the proxy side** (remote DNS), so you can use DC hostnames even if they're not resolvable locally.

LDAPS (TLS) over SOCKS5 is handled by manually negotiating TLS on top of the SOCKS5 tunnel.

### Supported proxy formats

```
socks5://127.0.0.1:1080
socks5://user:password@127.0.0.1:1080
```

### Setting up a tunnel

=== "Chisel"
    ```bash
    # On pivot host
    chisel server -p 8080 --reverse

    # On attacker machine
    chisel client pivot-host:8080 R:1080:socks
    ```

=== "SSH"
    ```bash
    ssh -D 1080 user@pivot-host
    ```

=== "Ligolo-ng"
    ```bash
    # After tunnel is established
    # Use the proxy interface directly — no SOCKS5 needed
    # Or add a listener: listener_add --addr 0.0.0.0:1080 --to 127.0.0.1:1080
    ```

!!! warning "PTT not supported through proxy"
    `--proxy` and `--ccache` cannot be combined. Kerberos authentication requires a direct TCP connection to the KDC. Use password or PTH when going through a proxy.

---

## Scope filtering (`--scope`)

Restrict all LDAP queries to a specific OU or container instead of the full domain base DN.

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --scope "OU=Finance,DC=corp,DC=local"
```

### When to use it

- **Large environments** with thousands of objects — limit noise to the relevant business unit
- **Focused audits** — e.g. "audit only the Finance OU" or "only Domain Controllers OU"
- **Faster runs** — fewer LDAP queries, less enumeration time

### Scope examples

```bash
# Single OU
--scope "OU=Finance,DC=corp,DC=local"

# Nested OU
--scope "OU=Workstations,OU=IT,DC=corp,DC=local"

# Domain Controllers OU
--scope "OU=Domain Controllers,DC=corp,DC=local"

# Custom container
--scope "CN=Computers,DC=corp,DC=local"
```

!!! note
    `--scope` replaces the base DN for **all** LDAP searches in the run. Objects outside the specified scope will not be returned. This affects enumeration (users, groups, computers), ACL analysis, Kerberos checks, etc.

### Combining proxy and scope

Both flags can be used together:

```bash
adpath enum -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1 \
  --proxy socks5://127.0.0.1:1080 \
  --scope "OU=Finance,DC=corp,DC=local"
```
