### PowerShell Profile Refactor
### Version 1.03 - Refactored

# Initial GitHub.com connectivity check with 1 second timeout
$canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet -TimeoutSeconds 1

# Import Modules and External Profiles
# Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

function Update-PowerShell {
    if (-not $global:canConnectToGitHub) {
        Write-Host "Skipping PowerShell update check due to GitHub.com not responding within 1 second." -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        } else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}
Update-PowerShell

# Dynamic Welcome Message
$username = $env:USERNAME
if ($username -eq 'an4rc') {
    Write-Host "Hello Dave, would you like to play a game" -ForegroundColor Red
} elseif ($username -eq 'Work') {
    Write-Host "Hello Dave, what are we working on today" -ForegroundColor Green
} else {
    Write-Host "Hello $username, welcome to PowerShell" -ForegroundColor Blue
}

# Admin Check and Prompt Customization
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

# Utility Functions
function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

# Editor Configuration
$EDITOR = if (Test-CommandExists nvim) { 'nvim' }
          elseif (Test-CommandExists pvim) { 'pvim' }
          elseif (Test-CommandExists vim) { 'vim' }
          elseif (Test-CommandExists vi) { 'vi' }
          elseif (Test-CommandExists code) { 'code' }
          elseif (Test-CommandExists notepad++) { 'notepad++' }
          elseif (Test-CommandExists sublime_text) { 'sublime_text' }
          else { 'notepad' }
Set-Alias -Name vim -Value $EDITOR

function Edit-Profile {
    code $PROFILE.CurrentUserAllHosts
}
function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)\$($_)"
    }
}

# Network Utilities
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

# System Utilities
function uptime {
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        Get-WmiObject win32_operatingsystem | Select-Object @{Name='LastBootUpTime'; Expression={$_.ConverttoDateTime($_.lastbootuptime)}} | Format-Table -HideTableHeaders
    } else {
        net statistics workstation | Select-String "since" | ForEach-Object { $_.ToString().Replace('Statistics since ', '') }
    }
}

function reload-profile {
    Clear-Host
    & $profile
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}
function hb {
    if ($args.Length -eq 0) {
        Write-Error "No file path specified."
        return
    }
    
    $FilePath = $args[0]
    
    if (Test-Path $FilePath) {
        $Content = Get-Content $FilePath -Raw
    } else {
        Write-Error "File path does not exist."
        return
    }
    
    $uri = "http://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "http://bin.christitus.com/$hasteKey"
        Write-Output $url
    } catch {
        Write-Error "Failed to upload the document. Error: $_"
    }
}
function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function df {
    get-volume
}

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function pgrep($name) {
    Get-Process $name
}

function head {
  param($Path, $n = 10)
  Get-Content $Path -Head $n
}

function tail {
  param($Path, $n = 10)
  Get-Content $Path -Tail $n
}

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
function docs { Set-Location -Path "$env:USERPROFILE\Documents" }

function dtop { Set-Location -Path "$env:USERPROFILE\Desktop" }

# Function to change to the C: drive
function go-home {
    Set-Location C:\
}

# Function to change to the C:\Work directory
function go-work {
    Set-Location C:\Work
}

# Determine if the user is at "home" or "work"
function Get-ProfileType {
    if (Test-Path "$env:USERPROFILE\OneDrive - Commtel Ltd T A Telguard\Documents\PowerShell") {
        return "work"
    } else {
        return "home"
    }
}

# Function to change to the user's profile directory
function go-profile {
    $type = Get-ProfileType
    if ($type -eq "work") {
        Set-Location "$env:USERPROFILE\OneDrive - Commtel Ltd T A Telguard\Documents\PowerShell"
    } else {
        Set-Location "$env:USERPROFILE\Documents\Powershell"
    }
}

# Function to open the PowerShell profile
function Open-profile {
    $type = Get-ProfileType
    if ($type -eq "work") {
        code "$env:USERPROFILE\OneDrive - Commtel Ltd T A Telguard\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
    } else {
        code "$env:USERPROFILE\Documents\Powershell\Microsoft.PowerShell_profile.ps1"
    }
}

# Creating aliases
Set-Alias -Name home go-home
Set-Alias -Name work go-work
Set-Alias -Name profile go-profile
Set-Alias -Name openProfile open-profile

# Quick Access to Editing the Profile
function ep { vim $PROFILE }

# Simplified Process Management
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }

function ga {
    param(
        [string]$file = ""
    )
    if ($file -eq "") {
        git add .
    } else {
        git add $file
    }
}

function gc {
    param(
        [string]$m
    )
    git commit -m "$m"
}

function gp {
    git push origin master
}

function g { z Github }

function gcom {
    param(
        [string]$m
    )
    git add .
    git commit -m "$m"
}

function lazyg {
    param(
        [string]$m
    )
    git add .
    git commit -m "$m"
    git push origin master
}

# Function to reset the local repository to match the remote repository
function git-reset {
    git fetch origin
    git reset --hard origin/master
}

# Alias for the git-reset function
Set-Alias -Name gitreset -Value git-reset

# Function to update Git
function update-git {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco upgrade git -y
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        scoop update git
    } elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        winget upgrade --id Git.Git --accept-package-agreements
    } else {
        Write-Host "No supported package manager found (choco, scoop, or winget)." -ForegroundColor Red
    }
}

# Alias for updating Git
Set-Alias -Name gitupdate -Value update-git

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns { Clear-DnsClientCache }

# Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }

# Enhanced PowerShell Experience
Set-PSReadLineOption -Colors @{
    Command = 'Yellow'
    Parameter = 'Green'
    String = 'DarkCyan'
}

# Function to open Spotify
function open-spotify {
    Start-Process "shell:AppsFolder\SpotifyAB.SpotifyMusic_zpdnekdrzrea0!Spotify"
}

# Alias for opening Spotify
Set-Alias -Name spotify -Value open-spotify

# Function to open Brave browser
function open-brave {
    Start-Process "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
}

# Alias for opening Brave browser
Set-Alias -Name brave -Value open-brave

# Function to remove temporary files
function Remove-TempFiles {
    param (
        [string]$outputFile,
        [string]$errorFile,
        [string[]]$processNames
    )

    # Wait until all specified processes are no longer running
    foreach ($processName in $processNames) {
        while (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
            Start-Sleep -Seconds 5
        }
    }

    Write-Host "Processes have ended. Removing temporary files..." -ForegroundColor Yellow

    # Remove the temporary files
    while ($true) {
        try {
            Remove-Item $outputFile, $errorFile -Force
            Write-Host "Temporary files removed." -ForegroundColor Green
            break
        } catch {
            # Wait and try again if the files are in use
            Start-Sleep -Seconds 5
        }
    }
}

# Function to open Signal Messenger and suppress output
function open-signal {
    $outputFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    $errorFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())

    Start-Process "C:\Users\$env:USERNAME\AppData\Local\Programs\signal-desktop\Signal.exe" -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile

    # Start a background job to clean up the temporary files
    Start-Job -ScriptBlock {
        param ($outputFile, $errorFile)
        Remove-TempFiles -outputFile $outputFile -errorFile $errorFile -processNames @("Signal")
    } -ArgumentList $outputFile, $errorFile | Out-Null
}

# Alias for opening Signal Messenger
Set-Alias -Name signal -Value open-signal

# Function to open KeePassXC
function open-keepassxc {
    Start-Process "C:\Program Files\KeePassXC\KeePassXC.exe"
}

# Alias for opening KeePassXC
Set-Alias -Name keepassxc -Value open-keepassxc

# Function to open Battle.net
function open-battlenet {
    Start-Process "C:\Program Files (x86)\Battle.net\Battle.net Launcher.exe"
}

# Alias for opening Battle.net
Set-Alias -Name battlenet -Value open-battlenet

# Function to open GOG Galaxy
function open-gog {
    Start-Process "C:\Program Files (x86)\GOG Galaxy\GalaxyClient.exe"
}

# Alias for opening GOG Galaxy
Set-Alias -Name gog -Value open-gog

# Function to open Steam
function open-steam {
    Start-Process "C:\Program Files (x86)\Steam\Steam.exe"
}

# Alias for opening Steam
Set-Alias -Name steam -Value open-steam

# Function to open Ubisoft Connect
function open-ubisoft {
    Start-Process "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\UbisoftConnect.exe"
}

# Alias for opening Ubisoft Connect
Set-Alias -Name ubisoft -Value open-ubisoft

# Function to open EA app
function open-ea {
    Start-Process "C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EA Desktop.exe"
}

# Alias for opening EA app
Set-Alias -Name ea -Value open-ea

# Function to open Epic Games Launcher
function open-epic {
    Start-Process "C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win32\EpicGamesLauncher.exe"
}

# Alias for opening Epic Games Launcher
Set-Alias -Name epic -Value open-epic

# Function to open Discord
function open-discord {
    Start-Process "C:\ProgramData\SquirrelMachineInstalls\Discord.exe"
}

# Alias for opening Discord
Set-Alias -Name discord -Value open-discord

# Function to open the README file in VSCode
function open-readme {
    code "$env:USERPROFILE\Documents\Powershell\readme.md"
}

# Alias for opening the README file in VSCode
Set-Alias -Name openReadme -Value open-readme

# Function to open the README file
function Show-Readme {
    $readmePath = "$env:USERPROFILE\Documents\Powershell\readme.md"
    if (Test-Path $readmePath) {
        Get-Content $readmePath | Out-Host
    } else {
        Write-Host "README file not found at path: $readmePath" -ForegroundColor Red
    }
}

# Alias for displaying the README file contents
Set-Alias -Name readme -Value Show-Readme

# Function to open Windows Explorer in the current directory
function openExplorerHere {
    Start-Process explorer.exe -ArgumentList $PWD
}

# Alias for opening Windows Explorer in the current directory
Set-Alias -Name open-here -Value openExplorerHere

# Function to open Windows Explorer at the C:\ directory
function open-explorer {
    Start-Process explorer.exe "C:\"
}

# Alias for opening Windows Explorer at the C:\ directory
Set-Alias -Name explorer -Value open-explorer

# Function to open Turtl and suppress output
function open-turtl {
    $outputFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    $errorFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())

    Start-Process "C:\Program Files\Turtl\turtl.exe" -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile

    # Start a background job to clean up the temporary files
    Start-Job -ScriptBlock {
        param ($outputFile, $errorFile)
        Remove-TempFiles -outputFile $outputFile -errorFile $errorFile -processNames @("Turtl")
    } -ArgumentList $outputFile, $errorFile | Out-Null
}

# Alias for opening Turtl
Set-Alias -Name turtl -Value open-turtl

# Function to open Parsec
function open-parsec {
    Start-Process "C:\Program Files\Parsec\parsecd.exe"
}

# Alias for opening Parsec
Set-Alias -Name parsec -Value open-parsec

# Function to run DISM
function run-dism {
    Start-Process "dism.exe" "/online /cleanup-image /restorehealth" -NoNewWindow -Wait
}

# Alias for running DISM
Set-Alias -Name dism -Value run-dism

# Function to run SFC
function run-sfc {
    Start-Process "sfc.exe" "/scannow" -NoNewWindow -Wait
}

# Alias for running SFC
Set-Alias -Name sfc -Value run-sfc

# Function to run CHKDSK
function run-chkdsk {
    $drive = "C:"
    $message = "chkdsk cannot run because the volume is in use by another process. Would you like to schedule this volume to be checked the next time the system restarts? (Y/N)"
    $scheduleChkDsk = Read-Host "$message"
    if ($scheduleChkDsk -match '^[Yy]$') {
        Start-Process "chkdsk.exe" "$drive /f /r" -NoNewWindow -Wait
    } else {
        Write-Host "Cancelled CHKDSK scheduling."
    }
}

# Alias for running CHKDSK
Set-Alias -Name chkdsk -Value run-chkdsk

# Function to run Disk Cleanup
function run-cleanmgr {
    Start-Process "cleanmgr.exe"
}

# Alias for running Disk Cleanup
Set-Alias -Name cleanmgr -Value run-cleanmgr

# Function to check for Windows Updates
function run-windowsupdate {
    Start-Process "powershell.exe" "-Command Get-WindowsUpdate -Install -AcceptAll -AutoReboot"
}

# Alias for checking Windows Updates
Set-Alias -Name windowsupdate -Value run-windowsupdate

# Function to get the PID and process name for a given port number
function Get-ProcessByPort {
    param (
        [int]$Port
    )

    # Get the PID associated with the port
    $netstatOutput = netstat -ano | Select-String ":$Port\s"
    if (-not $netstatOutput) {
        Write-Host "No process found using port $Port" -ForegroundColor Red
        return
    }

    # Extract the PID from the netstat output
    $pid = ($netstatOutput -split "\s+")[-1]

    # Get the process name using the PID
    $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
    if ($process) {
        [PSCustomObject]@{
            Port       = $Port
            PID        = $pid
            ProcessName = $process.Name
        } | Format-Table -AutoSize
    } else {
        Write-Host "No process found with PID $pid" -ForegroundColor Red
    }
}

# Alias for the Get-ProcessByPort function
Set-Alias -Name GetProcByPort -Value Get-ProcessByPort

# Function to kill a process by PID
function Kill-ProcessByPID {
    param (
        [int]$PID
    )

    try {
        Stop-Process -Id $PID -Force -Confirm
        Write-Host "Process with PID $PID has been terminated." -ForegroundColor Green
    } catch {
        Write-Host "Failed to terminate process with PID $PID. Error: $_" -ForegroundColor Red
    }
}

# Alias for the Kill-ProcessByPID function
Set-Alias -Name kill -Value Kill-ProcessByPID

# Function to find an available port
function Get-AvailablePort {
    param (
        [int]$StartingPort = 1024,
        [int]$EndingPort = 65535
    )

    for ($port = $StartingPort; $port -le $EndingPort; $port++) {
        if (-not (netstat -an | Select-String -Pattern "TCP.*:$port\s")) {
            Write-Output $port
            return
        }
    }
    Write-Error "No available ports found in the range $StartingPort to $EndingPort."
}

# Alias for the Get-AvailablePort function
Set-Alias -Name GetAvailPort -Value Get-AvailablePort

# Function to sign out the current user and shut down the PC
function signout-shutdown {
    param (
        [int]$delayMinutes = 1
    )
    # Schedule shutdown task to run in the specified number of minutes
    schtasks /create /tn "ShutdownPC" /tr "shutdown.exe /s /f /t 0" /sc once /st $(Get-Date).AddMinutes($delayMinutes).ToString("HH:mm")

    # Log off the current user
    shutdown.exe /l
}

# Alias for signing out and shutting down
Set-Alias -Name signoutshutdown -Value signout-shutdown

## Final Line to set prompt
oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/cobalt2.omp.json | Invoke-Expression
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init powershell | Out-String) })
} else {
    Write-Host "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Host "zoxide installed successfully. Initializing..."
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
    } catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}
