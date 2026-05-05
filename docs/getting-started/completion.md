# Shell Autocompletion

adpath supports tab completion for **bash**, **zsh**, **fish**, and **PowerShell**.

## Bash

```bash
# Load for current session
source <(adpath completion bash)

# Install permanently
adpath completion bash > /etc/bash_completion.d/adpath
```

## Zsh

```zsh
# Load for current session
source <(adpath completion zsh)

# Install permanently
adpath completion zsh > "${fpath[1]}/_adpath"
```

If you get `command not found: compdef`, add this to your `~/.zshrc` first:
```zsh
autoload -Uz compinit && compinit
```

## Fish

```fish
adpath completion fish | source

# Install permanently
adpath completion fish > ~/.config/fish/completions/adpath.fish
```

## PowerShell

```powershell
# Load for current session
adpath completion powershell | Out-String | Invoke-Expression

# Install permanently — add this line to your PowerShell profile ($PROFILE)
adpath completion powershell | Out-String | Invoke-Expression
```

## What gets completed

- All subcommands (`enum`, `acl`, `kerberos`, `kerb-enum`, ...)
- All flags (`--domain`, `--dc`, `--report`, `--quiet`, ...)
- Flag values where applicable
