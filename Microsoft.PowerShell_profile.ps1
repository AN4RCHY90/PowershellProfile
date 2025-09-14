### PowerShell Profile Refactor
### Version 1.1.06 - Home Only, Optimized for Fast Startup

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

# Manual PowerShell update function (call 'Update-PowerShell' when needed)
function Update-PowerShell {
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

# Dynamic Welcome Message
$username = $env:USERNAME
if ($username -eq 'an4rc') {
    Write-Host "Hello Dave, would you like to play a game" -ForegroundColor Red
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

function Edit-Profile { code $PROFILE.CurrentUserAllHosts }
function touch($file) { "" | Out-File $file -Encoding ASCII }
function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.directory)\$($_)"
    }
}

# Ensure PSReadLine module is imported
if (-not (Get-Module -ListAvailable -Name PSReadLine)) {
    Install-Module -Name PSReadLine -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name PSReadLine

# Enable Predictive IntelliSense
Set-PSReadLineOption -PredictionSource HistoryAndPlugin
Set-PSReadLineOption -PredictionViewStyle ListView

# Set the maximum number of history items
Set-PSReadLineOption -MaximumHistoryCount 4096

# Set the location to save the history
$historyFile = "$env:USERPROFILE\Documents\PowerShell_history.txt"
Set-PSReadLineOption -HistorySavePath $historyFile

# Optionally, set some key bindings for navigating history
Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward

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

function reload-profile { Clear-Host; & $profile }

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}

function hb {
    if ($args.Length -eq 0) { Write-Error "No file path specified."; return }
    $FilePath = $args[0]
    if (Test-Path $FilePath) { $Content = Get-Content $FilePath -Raw } else { Write-Error "File path does not exist."; return }
    $uri = "http://bin.christitus.com/documents"
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Content -ErrorAction Stop
        $hasteKey = $response.key
        $url = "http://bin.christitus.com/$hasteKey"
        Write-Output $url
    } catch { Write-Error "Failed to upload the document. Error: $_" }
}

function grep($regex, $dir) { if ($dir) { Get-ChildItem $dir | select-string $regex; return }; $input | select-string $regex }
function df { get-volume }
function sed($file, $find, $replace) { (Get-Content $file).replace("$find", $replace) | Set-Content $file }
function which($name) { Get-Command $name | Select-Object -ExpandProperty Definition }
function export($name, $value) { set-item -force -path "env:$name" -value $value }
function pkill($name) { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }
function pgrep($name) { Get-Process $name }
function head { param($Path, $n = 10) Get-Content $Path -Head $n }
function tail { param($Path, $n = 10) Get-Content $Path -Tail $n }

# Quick File Creation
function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

# Directory Management
function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

### Quality of Life Aliases

# Navigation Shortcuts
function docs { Set-Location -Path "$env:USERPROFILE\Documents" }
function dtop { Set-Location -Path "$env:USERPROFILE\Desktop" }

# Function to change to the C: drive
function go-home { Set-Location C:\ }

# Function to change to the user's PowerShell profile directory (home-only)
function go-profile { Set-Location "$env:USERPROFILE\OneDrive\Documents\Powershell" }

# Function to open the PowerShell profile (home-only)
function Open-profile { code "$env:USERPROFILE\OneDrive\Documents\Powershell\Microsoft.PowerShell_profile.ps1" }

# Creating aliases
Set-Alias -Name home -Value go-home
Set-Alias -Name profile -Value go-profile
Set-Alias -Name openProfile -Value open-profile

# Quick Access to Editing the Profile
function ep { vim $PROFILE }

# Simplified Process Management
function k9 { Stop-Process -Name $args[0] }

# Enhanced Listing
function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }
function ll { Get-ChildItem -Path . -Force -Hidden | Format-Table -AutoSize }

# Git Shortcuts
function gs { git status }
function ga { param([string]$file = "") if ($file -eq "") { git add . } else { git add $file } }
function gc { param([string]$m) git commit -m "$m" }
function gp { git push origin master }
function g { z Github }
function gcom { param([string]$m) git add .; git commit -m "$m" }
function lazyg { param([string]$m) git add .; git commit -m "$m"; git push origin master }

# Function to reset the local repository to match the remote repository
function git-reset { git fetch origin; git reset --hard origin/master }
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
Set-Alias -Name gitupdate -Value update-git

# Quick Access to System Information
function sysinfo { Get-ComputerInfo }

# Networking Utilities
function flushdns { Clear-DnsClientCache }
function cpy { Set-Clipboard $args[0] }
function pst { Get-Clipboard }

# Enhanced PowerShell Experience
Set-PSReadLineOption -Colors @{ Command='Yellow'; Parameter='Green'; String='DarkCyan' }

# Launchers
function open-spotify { Start-Process "shell:AppsFolder\SpotifyAB.SpotifyMusic_zpdnekdrzrea0!Spotify" }
Set-Alias -Name spotify -Value open-spotify

function open-brave { Start-Process "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" }
Set-Alias -Name brave -Value open-brave

function open-proton { Start-Process "C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe" }
Set-Alias -Name proton -Value open-proton

function Remove-TempFiles {
    param ([string]$outputFile,[string]$errorFile,[string[]]$processNames)
    foreach ($processName in $processNames) {
        while (Get-Process -Name $processName -ErrorAction SilentlyContinue) { Start-Sleep -Seconds 5 }
    }
    Write-Host "Processes have ended. Removing temporary files..." -ForegroundColor Yellow
    while ($true) {
        try { Remove-Item $outputFile, $errorFile -Force; Write-Host "Temporary files removed." -ForegroundColor Green; break }
        catch { Start-Sleep -Seconds 5 }
    }
}

function open-signal {
    $outputFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    $errorFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    Start-Process "C:\Users\$env:USERNAME\AppData\Local\Programs\signal-desktop\Signal.exe" -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
    Start-Job -ScriptBlock { param ($outputFile, $errorFile) Remove-TempFiles -outputFile $outputFile -errorFile $errorFile -processNames @("Signal") } -ArgumentList $outputFile, $errorFile | Out-Null
}
Set-Alias -Name signal -Value open-signal

function open-keepassxc { Start-Process "C:\Program Files\KeePassXC\KeePassXC.exe" }
Set-Alias -Name keepassxc -Value open-keepassxc

function open-battlenet { Start-Process "C:\Program Files (x86)\Battle.net\Battle.net Launcher.exe" }
Set-Alias -Name battlenet -Value open-battlenet

function open-gog { Start-Process "C:\Program Files (x86)\GOG Galaxy\GalaxyClient.exe" }
Set-Alias -Name gog -Value open-gog

function open-steam { Start-Process "C:\Program Files (x86)\Steam\Steam.exe" }
Set-Alias -Name steam -Value open-steam

function open-ubisoft { Start-Process "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\UbisoftConnect.exe" }
Set-Alias -Name ubisoft -Value open-ubisoft

function open-ea { Start-Process "C:\Program Files\Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe" }
Set-Alias -Name ea -Value open-ea

function open-epic { Start-Process "C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe" }
Set-Alias -Name epic -Value open-epic

function open-discord { Start-Process "C:\ProgramData\SquirrelMachineInstalls\Discord.exe" }
Set-Alias -Name discord -Value open-discord

function open-readme { code "$env:USERPROFILE\Documents\Powershell\readme.md" }
Set-Alias -Name openReadme -Value open-readme

function Show-Readme {
    $readmePath = "$env:USERPROFILE\Documents\Powershell\readme.md"
    if (Test-Path $readmePath) { Get-Content $readmePath | Out-Host } else { Write-Host "README file not found at path: $readmePath" -ForegroundColor Red }
}
Set-Alias -Name readme -Value Show-Readme

function openExplorerHere { Start-Process explorer.exe -ArgumentList $PWD }
Set-Alias -Name open-here -Value openExplorerHere

function open-explorer { Start-Process explorer.exe "C:\" }
Set-Alias -Name explorer -Value open-explorer

function open-turtl {
    $outputFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    $errorFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    Start-Process "C:\Program Files\Turtl\turtl.exe" -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile
    Start-Job -ScriptBlock { param ($outputFile, $errorFile) Remove-TempFiles -outputFile $outputFile -errorFile $errorFile -processNames @("Turtl") } -ArgumentList $outputFile, $errorFile | Out-Null
}
Set-Alias -Name turtl -Value open-turtl

function open-parsec { Start-Process "C:\Program Files\Parsec\parsecd.exe" }
Set-Alias -Name parsec -Value open-parsec

function open-notepad++ { Start-Process "C:\Program Files\Notepad++\notepad++.exe" }
Set-Alias -Name notepad -Value open-notepad++

function open-postman { Start-Process "C:\Users\$env:USERNAME\AppData\Local\Postman\Postman.exe" }
Set-Alias -Name postman -Value open-postman

# Home-only Tor path (desktop under current user)
function open-tor { Start-Process "$env:USERPROFILE\Desktop\Tor Browser\Browser\firefox.exe" }
Set-Alias -Name tor -Value open-tor

function open-kleopatra { Start-Process "C:\Program Files (x86)\Gpg4win\bin\kleopatra.exe" }
Set-Alias -Name kleo -Value open-kleopatra

function open-docker { Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" }
Set-Alias -Name docker -Value open-docker

function open-rider { Start-Process "C:\Users\an4rc\AppData\Local\Programs\Rider\bin\rider64.exe" }
Set-Alias -Name rider -Value open-rider

# Health & maintenance
function run-dism { Start-Process "dism.exe" "/online /cleanup-image /restorehealth" -NoNewWindow -Wait }
Set-Alias -Name dism -Value run-dism

function run-sfc { Start-Process "sfc.exe" "/scannow" -NoNewWindow -Wait }
Set-Alias -Name sfc -Value run-sfc

function run-chkdsk {
    $drive = "C:"
    $message = "chkdsk cannot run because the volume is in use by another process. Would you like to schedule this volume to be checked the next time the system restarts? (Y/N)"
    $scheduleChkDsk = Read-Host "$message"
    if ($scheduleChkDsk -match '^[Yy]$') { Start-Process "chkdsk.exe" "$drive /f /r" -NoNewWindow -Wait } else { Write-Host "Cancelled CHKDSK scheduling." }
}
Set-Alias -Name chkdsk -Value run-chkdsk

function run-cleanmgr { Start-Process "cleanmgr.exe" }
Set-Alias -Name cleanmgr -Value run-cleanmgr

function run-windowsupdate { Start-Process "powershell.exe" "-Command Get-WindowsUpdate -Install -AcceptAll -AutoReboot" }
Set-Alias -Name windowsupdate -Value run-windowsupdate

# Port helpers
function Get-ProcessByPort {
    param ([int]$Port)
    $netstatOutput = netstat -ano | Select-String ":$Port\s"
    if (-not $netstatOutput) { Write-Host "No process found using port $Port" -ForegroundColor Red; return }
    $processId = ($netstatOutput -split "\s+")[-1]
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process) {
        [PSCustomObject]@{ Port=$Port; PID=$processId; ProcessName=$process.Name } | Format-Table -AutoSize
    } else { Write-Host "No process found with PID $processId" -ForegroundColor Red }
}
Set-Alias -Name GetProcByPort -Value Get-ProcessByPort

function Kill-ProcessByPID {
    param ([int]$ProcessId)
    try { Stop-Process -Id $ProcessId -Force -Confirm; Write-Host "Process with PID $ProcessId has been terminated." -ForegroundColor Green }
    catch { Write-Host "Failed to terminate process with PID $ProcessId. Error: $_" -ForegroundColor Red }
}
Set-Alias -Name kill -Value Kill-ProcessByPID

function Get-AvailablePort {
    param ([int]$StartingPort = 1024, [int]$EndingPort = 65535)
    for ($port = $StartingPort; $port -le $EndingPort; $port++) {
        if (-not (netstat -an | Select-String -Pattern "TCP.*:$port\s")) { Write-Output $port; return }
    }
    Write-Error "No available ports found in the range $StartingPort to $EndingPort."
}
Set-Alias -Name GetAvailPort -Value Get-AvailablePort

# Session control
function shutdown-pc { shutdown.exe /s /f /t 0 }
Set-Alias -Name shutdown -Value shutdown-pc

function Test-IsAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function signout-shutdown {
    param ([int]$delayMinutes = 1)
    if (-not (Test-IsAdmin)) { Write-Host "This script must be run as an administrator. Please restart PowerShell with elevated privileges." -ForegroundColor Red; return }
    $shutdownTime = (Get-Date).AddMinutes($delayMinutes).ToString("HH:mm")
    $taskName = "ShutdownPC"
    schtasks /create /tn $taskName /tr "shutdown.exe /s /f /t 0" /sc once /st $shutdownTime /f
    shutdown.exe /l
}
Set-Alias -Name signoutshutdown -Value signout-shutdown

function signout-user { shutdown.exe /l }
Set-Alias -Name signout -Value signout-user

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
