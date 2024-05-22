# PowerShell Profile Aliases

This README provides an overview of the custom aliases and functions defined in your PowerShell profile. These aliases are designed to enhance your productivity and simplify common tasks.

## Table of Contents

- [Navigation Shortcuts](#navigation-shortcuts)
- [Git Shortcuts](#git-shortcuts)
- [System Utilities](#system-utilities)
- [File and Directory Management](#file-and-directory-management)
- [Networking Utilities](#networking-utilities)
- [Clipboard Utilities](#clipboard-utilities)
- [Enhanced PowerShell Experience](#enhanced-powershell-experience)
- [Application Shortcuts](#application-shortcuts)

## Navigation Shortcuts

| Alias         | Command               | Description                                         |
| ------------- | --------------------- | --------------------------------------------------- |
| `home`        | `go-home`             | Change to the C: drive                              |
| `work`        | `go-work`             | Change to the C:\Work directory                     |
| `profile`     | `go-profile`          | Change to the C:\Users\an4rc\Documents\Powershell   |
| `work-Profile`| `go-work-profile`     | Change to the work profile directory                |
| `home-Profile`| `go-profile`          | Alias for `profile`                                 |
| `docs`        | `docs`                | Change to the Documents directory                   |
| `dtop`        | `dtop`                | Change to the Desktop directory                     |
| `openProfile` | `open-profile`        | Open the PowerShell profile in VS Code              |
| `ep`          | `vim $PROFILE`        | Edit the PowerShell profile with Vim                |

## Git Shortcuts

| Alias     | Command                        | Description                                                                 |
| --------- | ------------------------------ | --------------------------------------------------------------------------- |
| `gs`      | `git status`                   | Show the status of the Git repository                                       |
| `ga`      | `ga [file]`                    | Add a specific file or all files to the staging area                        |
| `gc`      | `gc "commit message"`          | Commit changes with a message                                               |
| `gp`      | `git push origin master`       | Push changes to the `origin` remote and the `master` branch                 |
| `gcom`    | `gcom "commit message"`        | Add all files, commit with a message, but do not push                       |
| `lazyg`   | `lazyg "commit message"`       | Add all files, commit with a message, and push to `origin master`           |

## System Utilities

| Alias    | Command                 | Description                                  |
| -------- | ----------------------- | -------------------------------------------- |
| `sysinfo`| `Get-ComputerInfo`      | Get detailed system information              |
| `flushdns`| `Clear-DnsClientCache` | Clear the DNS client cache                   |
| `uptime` | `uptime`                | Show system uptime                           |
| `reload-profile` | `reload-profile`| Clear the screen and reload the PowerShell profile |

## File and Directory Management

| Alias | Command                                      | Description                                    |
| ----- | -------------------------------------------- | ---------------------------------------------- |
| `touch` | `touch <file>`                             | Create a new empty file                        |
| `nf`    | `nf <name>`                                | Create a new file                              |
| `mkcd`  | `mkcd <dir>`                               | Create a new directory and change to it        |
| `unzip` | `unzip <file>`                             | Unzip a file in the current directory          |
| `ff`    | `ff <name>`                                | Find files with the specified name             |
| `la`    | `la`                                       | List all files and directories in a table      |
| `ll`    | `ll`                                       | List all files, including hidden ones, in a table |
| `head`  | `head <Path> [-n <lines>]`                 | Display the first `n` lines of a file          |
| `tail`  | `tail <Path> [-n <lines>]`                 | Display the last `n` lines of a file           |
| `sed`   | `sed <file> <find> <replace>`              | Replace text in a file                         |

## Networking Utilities

| Alias   | Command                      | Description                                    |
| ------- | ---------------------------- | ---------------------------------------------- |
| `Get-PubIP` | `Get-PubIP`              | Get the public IP address                      |
| `grep`  | `grep <regex> [dir]`         | Search for a regex pattern in files            |
| `hb`    | `hb <file>`                  | Upload the contents of a file to hastebin      |

## Clipboard Utilities

| Alias   | Command                  | Description                                |
| ------- | ------------------------ | ------------------------------------------ |
| `cpy`   | `cpy <text>`             | Copy text to the clipboard                 |
| `pst`   | `pst`                    | Paste text from the clipboard              |

## Enhanced PowerShell Experience

| Command | Description                              |
| ------- | ---------------------------------------- |
| `Set-PSReadLineOption -Colors @{ ... }` | Set custom colors for the PowerShell prompt |

## Application Shortcuts

| Alias    | Command          | Description                      |
| -------- | ---------------- | -------------------------------- |
| `spotify`| `open-spotify`   | Open the Spotify application     |
| `brave`  | `open-brave`     | Open the Brave browser           |
| `readme` | `Show-Readme`    | Display the README file contents |
| `open-here`| `open-here`    | Open Windows Explorer in the current directory |

### Example Usage

```powershell
# Navigate to the work profile directory
work-Profile

# Add a specific file to the staging area
ga path/to/your/file

# Commit changes with a message
gc "Fixed a bug in the script"

# Push changes to the origin master branch
gp

# Combined add, commit, and push operation
lazyg "Implemented new feature"

# Open Spotify
spotify

# Open Brave browser
brave

# Display the README file contents
readme

# Open Windows Explorer in the current directory
open-here
