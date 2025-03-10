# PowerShell Profile Aliases

This README provides an overview of the custom aliases and functions defined in your PowerShell profile. These aliases are designed to enhance your productivity and simplify common tasks.

**Note:** The original base script used was made by Chris Titus & his original script can be found [here](https://github.com/ChrisTitusTech/powershell-profile).

## Table of Contents

- [Navigation Shortcuts](#navigation-shortcuts)
- [Git Shortcuts](#git-shortcuts)
- [System Utilities](#system-utilities)
- [File and Directory Management](#file-and-directory-management)
- [Networking Utilities](#networking-utilities)
- [Clipboard Utilities](#clipboard-utilities)
- [Enhanced PowerShell Experience](#enhanced-powershell-experience)
- [Application Shortcuts](#application-shortcuts)
- [System Maintenance](#system-maintenance)
- [Process Utilities](#process-utilities)

## Navigation Shortcuts

| Alias         | Command               | Description                                         |
| ------------- | --------------------- | --------------------------------------------------- |
| `home`        | `go-home`             | Change to the C: drive                              |
| `work`        | `go-work`             | Change to the C:\Work directory                     |
| `profile`     | `go-profile`          | Change to the user's profile directory              |
| `docs`        | `docs`                | Change to the Documents directory                   |
| `dtop`        | `dtop`                | Change to the Desktop directory                     |
| `openProfile` | `open-profile`        | Open the PowerShell profile in VS Code              |
| `ep`          | `vim $PROFILE`        | Edit the PowerShell profile with Vim                |
| `openReadme`  | `open-readme`         | Open the README file in VSCode                      |

## Git Shortcuts

| Alias     | Command                        | Description                                                                 |
| --------- | ------------------------------ | --------------------------------------------------------------------------- |
| `gs`      | `git status`                   | Show the status of the Git repository                                       |
| `ga`      | `ga [file]`                    | Add a specific file or all files to the staging area                        |
| `gc`      | `gc "commit message"`          | Commit changes with a message                                               |
| `gp`      | `git push origin master`       | Push changes to the `origin` remote and the `master` branch                 |
| `gcom`    | `gcom "commit message"`        | Add all files, commit with a message, but do not push                       |
| `lazyg`   | `lazyg "commit message"`       | Add all files, commit with a message, and push to `origin master`           |
| `gitreset`| `git-reset`                    | Reset the local repository to match the remote repository                   |
| `gitupdate`| `update-git`                  | Update Git to the latest version                                            |

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
| `GetAvailPort` | `Get-AvailablePort [StartingPort] [EndingPort]` | Find an available port within the specified range |

## Clipboard Utilities

| Alias   | Command                  | Description                                |
| ------- | ------------------------ | ------------------------------------------ |
| `cpy`   | `cpy <text>`             | Copy text to the clipboard                 |
| `pst`   | `pst`                    | Paste text from the clipboard              |

## Enhanced PowerShell Experience

## Enhanced PowerShell Experience

| Command | Description                              |
| ------- | ---------------------------------------- |
| `Set-PSReadLineOption -Colors @{ ... }` | Set custom colors for the PowerShell prompt |
| `Set-PSReadLineOption -PredictionSource HistoryAndPlugin` | Enable predictive IntelliSense based on history and plugins |
| `Set-PSReadLineOption -PredictionViewStyle ListView` | Display predictive IntelliSense suggestions in a list view |
| `Set-PSReadLineOption -MaximumHistoryCount 4096` | Set the maximum number of commands to save in the history |
| `Set-PSReadLineOption -HistorySavePath $historyFile` | Specify the path where the history file should be saved |

## Application Shortcuts

| Alias    | Command          | Description                      |
| -------- | ---------------- | -------------------------------- |
| `spotify`| `open-spotify`   | Open the Spotify application     |
| `brave`  | `open-brave`     | Open the Brave browser           |
| `signal` | `open-signal`    | Open the Signal Messenger app    |
| `keepassxc` | `open-keepassxc` | Open KeePassXC                 |
| `readme` | `Show-Readme`    | Display the README file contents |
| `open-here`| `open-here`    | Open Windows Explorer in the current directory |
| `explorer` | `open-explorer` | Open Windows Explorer at the C:\ directory |
| `battlenet`| `open-battlenet` | Open Battle.net Launcher       |
| `gog`     | `open-gog`      | Open GOG Galaxy Launcher         |
| `steam`   | `open-steam`    | Open Steam                       |
| `ubisoft` | `open-ubisoft`  | Open Ubisoft Connect             |
| `ea`      | `open-ea`       | Open EA app                      |
| `epic`    | `open-epic`     | Open Epic Games Launcher         |
| `discord` | `open-discord`  | Open Discord                     |
| `turtl`   | `open-turtl`    | Open Turtl                       |
| `parsec`  | `open-parsec`   | Open Parsec                      |
| `notepad`  | `open-notepad++`   | Open Notepad++                      |
| `postman`  | `open-postman`   | Open Postman                      |
| `kleo`  | `open-kleopatra`   | Open Kleopatra                      |
| `proton` | `open-proton` | Open Proton VPN |

## System Maintenance

| Alias       | Command              | Description                                  |
| ----------- | -------------------- | -------------------------------------------- |
| `dism`      | `run-dism`           | Run DISM to repair Windows image             |
| `sfc`       | `run-sfc`            | Run System File Checker                      |
| `chkdsk`    | `run-chkdsk`         | Run CHKDSK to check and repair disk errors   |
| `cleanmgr`  | `run-cleanmgr`       | Run Disk Cleanup                             |
| `windowsupdate` | `run-windowsupdate` | Check for Windows Updates                   |
| `signoutshutdown` | `signout-shutdown` | Sign out and shut down the PC             |

## Process Utilities

| Alias       | Command              | Description                                  |
| ----------- | -------------------- | -------------------------------------------- |
| `GetProcByPort` | `Get-ProcessByPort <Port>` | Find the PID and process name for a specified port number |
| `kill`      | `Kill-ProcessByPID <PID>` | Kill a process by its PID                    |
| `signout`   | `signout-user`       | Sign out the current user                    |
| `shutdown`  | `shutdown-pc`        | Shut down the PC                             |
