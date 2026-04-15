# Installation

## Pre-built binary

Download the latest release for your platform from [GitHub Releases](https://github.com/YakinAnd/adpath/releases).

```bash
# Linux / macOS
chmod +x adpath
./adpath version

# Windows
adpath.exe version
```

## Build from source

Requires Go 1.21+.

```bash
git clone https://github.com/YakinAnd/adpath
cd adpath
go build -o adpath ./cmd/adpath/...
```

## Verify

```
adpath version
```

```
adpath v0.8.3
AD Attack Path Enumerator
https://github.com/YakinAnd/adpath
```
