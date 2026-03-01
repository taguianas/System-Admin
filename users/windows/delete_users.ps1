<#
.SYNOPSIS
    Cleanly disable and delete Windows user accounts.

.DESCRIPTION
    For each user, performs the following steps in order:
      1. Disable the account   (prevents new logins immediately)
      2. Sign out active sessions (query / logoff)
      3. Archive the user profile directory to <ArchiveDir>\<user>_<timestamp>.zip
      4. Remove scheduled tasks owned by the user
      5. Delete the account    (Remove-LocalUser or Remove-ADUser)

    Accepts a CSV file (same format as create_users.ps1) or a plain list
    of usernames as positional arguments.

.PARAMETER Users
    One or more usernames to delete. Mutually exclusive with -CsvFile.

.PARAMETER CsvFile
    Path to CSV file - only the 'username' column is used.
    Mutually exclusive with -Users.

.PARAMETER ArchiveDir
    Where to store profile archives. Default: C:\UserArchives

.PARAMETER LogDir
    Directory for log files. Default: ..\..\logs

.PARAMETER KeepProfile
    Switch. Skip profile archiving and deletion (disable/delete account only).

.PARAMETER UseAD
    Switch. Target Active Directory accounts instead of local accounts.

.PARAMETER DryRun
    Switch. Print what would be done without making any changes.

.EXAMPLE
    # Delete specific local users
    .\delete_users.ps1 -Users alice, bob

.EXAMPLE
    # Delete from CSV, dry-run first
    .\delete_users.ps1 -CsvFile .\offboarded.csv -DryRun

.EXAMPLE
    # AD accounts with custom archive location
    .\delete_users.ps1 -CsvFile .\offboarded.csv -UseAD -ArchiveDir D:\Archives

.NOTES
    Must be run as Administrator.
    Profile archiving requires access to C:\Users\<username>.
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = "ByName")]
param(
    [Parameter(ParameterSetName = "ByName", Position = 0, Mandatory)]
    [string[]]$Users,

    [Parameter(ParameterSetName = "ByCsv", Mandatory)]
    [string]$CsvFile,

    [string]$ArchiveDir = "C:\UserArchives",

    [string]$LogDir = (Join-Path $PSScriptRoot "..\..\logs"),

    [switch]$KeepProfile,

    [switch]$UseAD,

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
$script:LogFile = $null

function Initialize-Log {
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $script:LogFile = Join-Path $LogDir "delete_users.log"
    if (-not (Test-Path $script:LogFile)) {
        New-Item -ItemType File -Path $script:LogFile -Force | Out-Null
    }
}

function Get-LevelColor ([string]$Level) {
    if ($Level -eq "WARNING") { return "Yellow" }
    if ($Level -eq "ERROR")   { return "Red" }
    if ($Level -eq "DRY-RUN") { return "Magenta" }
    return "Cyan"
}

function Write-Log {
    param(
        [ValidateSet("INFO","WARNING","ERROR","DRY-RUN")]
        [string]$Level = "INFO",
        [string]$Message
    )
    $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$ts [$($Level.PadRight(7))] $Message"
    Write-Host $entry -ForegroundColor (Get-LevelColor $Level)
    Add-Content -Path $script:LogFile -Value $entry
}

# ---------------------------------------------------------------------------
# Input resolution
# ---------------------------------------------------------------------------
function Resolve-Usernames {
    if ($PSCmdlet.ParameterSetName -eq "ByCsv") {
        if (-not (Test-Path $CsvFile)) {
            Write-Log -Level ERROR -Message "CSV file not found: $CsvFile"
            exit 1
        }
        Write-Log -Level INFO -Message "Reading usernames from CSV: $CsvFile"
        $result = Import-Csv -Path $CsvFile |
                  Where-Object { -not [string]::IsNullOrWhiteSpace($_.username) -and -not $_.username.StartsWith('#') } |
                  ForEach-Object { $_.username.Trim() }
        return $result
    }
    return $Users
}

# ---------------------------------------------------------------------------
# Account existence checks
# ---------------------------------------------------------------------------
function Test-LocalUserExists ([string]$Username) {
    $found = $false
    try {
        Get-LocalUser -Name $Username -ErrorAction Stop | Out-Null
        $found = $true
    } catch { }
    return $found
}

function Test-ADUserExists ([string]$Username) {
    $found = $false
    try {
        Get-ADUser -Identity $Username -ErrorAction Stop | Out-Null
        $found = $true
    } catch { }
    return $found
}

function Get-ProfilePath ([string]$Username) {
    # Try registry first (most reliable across domain and local accounts)
    $profileList = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $found = $null
    Get-ChildItem $profileList | ForEach-Object {
        $prof = Get-ItemProperty $_.PSPath
        if ($prof.ProfileImagePath -match "[/\\]$Username`$") {
            $found = $prof.ProfileImagePath
        }
    }
    if ($found) { return $found }

    # Fall back to default profile location
    $default = Join-Path $env:SystemDrive "Users\$Username"
    if (Test-Path $default) { return $default }
    return $null
}

# ---------------------------------------------------------------------------
# Step 1 - Disable account
# ---------------------------------------------------------------------------
function Disable-UserAccount ([string]$Username) {
    if ($DryRun) {
        Write-Log -Level "DRY-RUN" -Message "Would disable account: $Username"
        return
    }
    if ($UseAD) {
        Disable-ADAccount -Identity $Username
    } else {
        Disable-LocalUser -Name $Username
    }
    Write-Log -Level INFO -Message "Disabled account: $Username"
}

# ---------------------------------------------------------------------------
# Step 2 - Sign out active sessions
# ---------------------------------------------------------------------------
function Remove-ActiveSessions ([string]$Username) {
    if (-not (Get-Command query.exe -ErrorAction SilentlyContinue)) {
        Write-Log -Level WARNING -Message "query.exe not found - skipping session logoff for $Username"
        return
    }

    $queryOutput = & query.exe session /server:localhost 2>$null
    $sessions    = $queryOutput | Where-Object { $_ -match "\s+$Username\s+" }

    if (-not $sessions) {
        Write-Log -Level INFO -Message "No active sessions for: $Username"
        return
    }

    foreach ($line in $sessions) {
        $sessionId = ($line -split '\s+' | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
        if ($sessionId) {
            if ($DryRun) {
                Write-Log -Level "DRY-RUN" -Message "Would logoff session $sessionId for: $Username"
            } else {
                & logoff.exe $sessionId /server:localhost 2>$null
                Write-Log -Level INFO -Message "Logged off session $sessionId for: $Username"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Step 3 - Archive profile directory
# ---------------------------------------------------------------------------
function Invoke-ProfileArchive ([string]$Username) {
    if ($KeepProfile) {
        Write-Log -Level INFO -Message "Skipping profile archive for '$Username' (-KeepProfile set)"
        return
    }

    $profilePath = Get-ProfilePath $Username
    if (-not $profilePath) {
        Write-Log -Level WARNING -Message "Profile directory not found for '$Username' - skipping archive"
        return
    }

    $ts          = Get-Date -Format "yyyyMMdd_HHmmss"
    $archiveName = "${Username}_${ts}.zip"
    $archivePath = Join-Path $ArchiveDir $archiveName

    if ($DryRun) {
        Write-Log -Level "DRY-RUN" -Message "Would archive: $profilePath to $archivePath"
        return
    }

    if (-not (Test-Path $ArchiveDir)) {
        New-Item -ItemType Directory -Path $ArchiveDir -Force | Out-Null

        # Restrict directory to Administrators only
        $acl = Get-Acl $ArchiveDir
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $adminSid  = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
        $adminRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $adminSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($adminRule)
        Set-Acl -Path $ArchiveDir -AclObject $acl
    }

    try {
        Compress-Archive -Path $profilePath -DestinationPath $archivePath -CompressionLevel Optimal
        $sizeMB = [math]::Round((Get-Item $archivePath).Length / 1MB, 2)
        Write-Log -Level INFO -Message "Archived profile: $archivePath ($sizeMB MB)"
    } catch {
        Write-Log -Level ERROR -Message "Failed to archive profile for '$Username': $($_.Exception.Message)"
        throw
    }
}

# ---------------------------------------------------------------------------
# Step 4 - Remove scheduled tasks
# ---------------------------------------------------------------------------
function Remove-UserScheduledTasks ([string]$Username) {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
             Where-Object {
                 $match = $false
                 try { $match = $_.Principal.UserId -like "*$Username*" } catch { }
                 $match
             }

    if (-not $tasks) {
        Write-Log -Level INFO -Message "No scheduled tasks found for: $Username"
        return
    }

    foreach ($task in $tasks) {
        $taskLabel = "$($task.TaskPath)$($task.TaskName)"
        if ($DryRun) {
            Write-Log -Level "DRY-RUN" -Message "Would remove scheduled task: $taskLabel"
        } else {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
            Write-Log -Level INFO -Message "Removed scheduled task: $taskLabel"
        }
    }
}

# ---------------------------------------------------------------------------
# Step 5 - Delete account
# ---------------------------------------------------------------------------
function Remove-UserAccount ([string]$Username) {
    if ($DryRun) {
        Write-Log -Level "DRY-RUN" -Message "Would delete account: $Username"
        return
    }
    if ($UseAD) {
        Remove-ADUser -Identity $Username -Confirm:$false
    } else {
        Remove-LocalUser -Name $Username
    }
    Write-Log -Level INFO -Message "Deleted account: $Username"
}

# ---------------------------------------------------------------------------
# Process one user through all steps
# ---------------------------------------------------------------------------
function Remove-SingleUser ([string]$Username) {
    $exists = if ($UseAD) { Test-ADUserExists $Username } else { Test-LocalUserExists $Username }
    if (-not $exists) {
        Write-Log -Level WARNING -Message "User '$Username' does not exist - skipping"
        return $false
    }

    Write-Log -Level INFO -Message "--- Processing: $Username ---"

    Disable-UserAccount       $Username
    Remove-ActiveSessions     $Username
    Invoke-ProfileArchive     $Username
    Remove-UserScheduledTasks $Username
    Remove-UserAccount        $Username

    return $true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Main {
    Initialize-Log

    Write-Log -Level INFO -Message "=== delete_users.ps1 started ==="
    $modeStr = if ($UseAD) { "Active Directory" } else { "Local" }
    Write-Log -Level INFO -Message "Mode        : $modeStr"
    Write-Log -Level INFO -Message "Archive dir : $ArchiveDir"
    Write-Log -Level INFO -Message "Keep profile: $KeepProfile"
    Write-Log -Level INFO -Message "Dry run     : $DryRun"

    if ($UseAD) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Log -Level ERROR -Message "ActiveDirectory module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory*"
            exit 1
        }
        Import-Module ActiveDirectory -ErrorAction Stop
    }

    $usernames = @(Resolve-Usernames)

    if ($usernames.Count -eq 0) {
        Write-Log -Level ERROR -Message "No usernames resolved from input."
        exit 1
    }

    $total   = $usernames.Count
    $deleted = 0
    $failed  = 0

    foreach ($username in $usernames) {
        try {
            if (Remove-SingleUser $username) { $deleted++ }
        } catch {
            Write-Log -Level ERROR -Message "Failed to process '$username': $($_.Exception.Message)"
            $failed++
        }
    }

    Write-Log -Level INFO -Message "=== Summary: $total total, $deleted deleted, $failed failed ==="

    if ($failed -gt 0) {
        Write-Log -Level WARNING -Message "Some deletions failed - check $($script:LogFile)"
        exit 1
    }
}

Main
