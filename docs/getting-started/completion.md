# Shell Autocompletion

morok supports tab completion for **bash**, **zsh**, **fish**, and **PowerShell**.

## Bash

```bash
# Load for current session
source <(morok completion bash)

# Install permanently
morok completion bash > /etc/bash_completion.d/morok
```

## Zsh

```zsh
# Load for current session
source <(morok completion zsh)

# Install permanently
morok completion zsh > "${fpath[1]}/_morok"
```

If you get `command not found: compdef`, add this to your `~/.zshrc` first:
```zsh
autoload -Uz compinit && compinit
```

## Fish

```fish
morok completion fish | source

# Install permanently
morok completion fish > ~/.config/fish/completions/morok.fish
```

## PowerShell

```powershell
# Load for current session
morok completion powershell | Out-String | Invoke-Expression

# Install permanently — add this line to your PowerShell profile ($PROFILE)
morok completion powershell | Out-String | Invoke-Expression
```

## What gets completed

- All subcommands (`enum`, `acl`, `kerberos`, `kerb-enum`, ...)
- All flags (`--domain`, `--dc`, `--report`, `--quiet`, ...)
- Flag values where applicable
