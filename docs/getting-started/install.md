# Installation

## Requirements

- Linux, macOS, or Windows
- Network access to a Domain Controller on port 389 (LDAP) or 636 (LDAPS)
- A domain account (any valid user is enough for most checks)

## Pre-built binary

Download the latest release for your platform from [GitHub Releases](https://github.com/YakinAnd/adpath/releases).

=== "Linux / macOS"
    ```bash
    chmod +x adpath
    ./adpath version
    ```

=== "Windows"
    ```powershell
    .\adpath.exe version
    ```

## Build from source

Requires **Go 1.21+**.

```bash
git clone https://github.com/YakinAnd/adpath
cd adpath
go build -o adpath ./cmd/adpath/...
```

On Windows:
```powershell
go build -o adpath.exe .\cmd\adpath\...
```

## Verify

```
$ adpath version
adpath v1.0
AD Attack Path Enumerator
https://github.com/YakinAnd/adpath
```

## No additional dependencies

adpath is a single statically-linked binary. It does not require:

- BloodHound or Neo4j
- Python / impacket
- SMB access or local admin rights on target machines
- Domain Admin or elevated AD privileges
