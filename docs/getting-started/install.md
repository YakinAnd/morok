# Installation

## Requirements

- Linux, macOS, or Windows
- Network access to a Domain Controller on port 389 (LDAP) or 636 (LDAPS)
- A domain account (any valid user is enough for most checks)

## Pre-built binary

Download the latest release for your platform from [GitHub Releases](https://github.com/YakinAnd/morok/releases).

=== "Linux / macOS"
    ```bash
    chmod +x morok
    ./morok version
    ```

=== "Windows"
    ```powershell
    .\morok.exe version
    ```

## Build from source

Requires **Go 1.21+**.

```bash
git clone https://github.com/YakinAnd/morok
cd morok
go build -o morok ./cmd/morok/...
```

On Windows:
```powershell
go build -o morok.exe .\cmd\morok\...
```

## Verify

```
$ morok version
morok v1.1.1
AD Attack Path Enumerator
https://github.com/YakinAnd/morok
```

## No additional dependencies

morok is a single statically-linked binary. It does not require:

- BloodHound or Neo4j
- Python / impacket
- SMB access or local admin rights on target machines
- Domain Admin or elevated AD privileges
