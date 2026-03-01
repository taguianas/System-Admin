<#
.SYNOPSIS
    Batch-create Windows user accounts from a CSV file.

.DESCRIPTION
    Reads a CSV file and creates local or Active Directory user accounts.
    Supports automatic password generation, group assignment, and forced
    password change at next logon.

    By default uses local accounts (New-LocalUser).
    Pass -UseAD to target Active Directory (requires RSAT ActiveDirectory module).

.PARAMETER CsvFile
    Path to the CSV file.
    Expected columns: username, group, shell, password
      - shell    : ignored on Windows (kept for cross-platform CSV compatibility)
      - password : plain text; leave blank to auto-generate a temporary password
      - group    : local group or AD group name; created if it does not exist

.PARAMETER LogDir
    Directory where log files are written. Default: ..\..\logs

.PARAMETER UseAD
    Switch. When present, creates AD accounts instead of local accounts.
    Requires the ActiveDirectory PowerShell module (RSAT).

.PARAMETER OUPath
    Distinguished Name of the target Organizational Unit for AD accounts.
    Example: "OU=Staff,DC=corp,DC=example,DC=com"
    Only used when -UseAD is specified.

.PARAMETER DryRun
    Switch. Print what would be done without making any changes.

.EXAMPLE
    # Local accounts
    .\create_users.ps1 -CsvFile .\sample_users.csv

.EXAMPLE
    # Preview actions only
    .\create_users.ps1 -CsvFile .\sample_users.csv -DryRun

.EXAMPLE
    # Active Directory
    .\create_users.ps1 -CsvFile .\sample_users.csv -UseAD -OUPath "OU=Staff,DC=corp,DC=example,DC=com"

.NOTES
    Must be run as Administrator.
    Tested on Windows 10/11 and Windows Server 2019/2022.
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$CsvFile,

    [string]$LogDir = (Join-Path $PSScriptRoot "..\..\logs"),

    [switch]$UseAD,

    [string]$OUPath = "",

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
    $script:LogFile = Join-Path $LogDir "create_users.log"
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
# Helpers
# ---------------------------------------------------------------------------

function New-RandomPassword {
    # Generates a 14-character password satisfying Windows complexity rules.
    $upper   = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = [char[]]'abcdefghjkmnpqrstuvwxyz'
    $digits  = [char[]]'23456789'
    $symbols = [char[]]'!@#$%^&*'
    $all     = $upper + $lower + $digits + $symbols

    # Guarantee at least one character from each class
    $pwd = @(
        ($upper   | Get-Random)
        ($lower   | Get-Random)
        ($digits  | Get-Random)
        ($symbols | Get-Random)
    )
    $pwd += 1..10 | ForEach-Object { $all | Get-Random }

    # Shuffle and return
    return -join ($pwd | Get-Random -Count $pwd.Count)
}

function ConvertTo-SecurePlain ([string]$Plain) {
    return ConvertTo-SecureString -String $Plain -AsPlainText -Force
}

function Test-LocalGroupExists ([string]$GroupName) {
    $found = $false
    try {
        Get-LocalGroup -Name $GroupName -ErrorAction Stop | Out-Null
        $found = $true
    } catch { }
    return $found
}

function Test-ADGroupExists ([string]$GroupName) {
    $found = $false
    try {
        Get-ADGroup -Identity $GroupName -ErrorAction Stop | Out-Null
        $found = $true
    } catch { }
    return $found
}

function Ensure-LocalGroup ([string]$GroupName) {
    if (Test-LocalGroupExists $GroupName) {
        Write-Log -Level INFO -Message "Group '$GroupName' already exists - skipping creation"
        return
    }
    if ($DryRun) {
        Write-Log -Level "DRY-RUN" -Message "Would create local group: $GroupName"
        return
    }
    New-LocalGroup -Name $GroupName -Description "Created by create_users.ps1" | Out-Null
    Write-Log -Level INFO -Message "Created local group: $GroupName"
}

function Ensure-ADGroup ([string]$GroupName) {
    if (Test-ADGroupExists $GroupName) {
        Write-Log -Level INFO -Message "AD group '$GroupName' already exists - skipping creation"
        return
    }
    if ($DryRun) {
        Write-Log -Level "DRY-RUN" -Message "Would create AD group: $GroupName"
        return
    }
    $params = @{
        Name          = $GroupName
        GroupScope    = "Global"
        GroupCategory = "Security"
    }
    if ($OUPath) { $params["Path"] = $OUPath }
    New-ADGroup @params
    Write-Log -Level INFO -Message "Created AD group: $GroupName"
}

# ---------------------------------------------------------------------------
# Credential file (admin-only, temporary passwords)
# ---------------------------------------------------------------------------
function Save-GeneratedCredential ([string]$Username, [string]$Password) {
    $credFile = Join-Path $LogDir "new_user_credentials.txt"

    if (-not (Test-Path $credFile)) {
        New-Item -ItemType File -Path $credFile -Force | Out-Null

        $acl = Get-Acl $credFile
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        $adminSid  = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
        $adminRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $adminSid, "FullControl", "Allow"
        )
        $acl.AddAccessRule($adminRule)
        Set-Acl -Path $credFile -AclObject $acl
    }

    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts  $($Username.PadRight(20))  $Password"
    Add-Content -Path $credFile -Value $line
    Write-Log -Level WARNING -Message "Auto-generated password for '$Username' written to: $credFile"
}

# ---------------------------------------------------------------------------
# Local user creation
# ---------------------------------------------------------------------------
function New-LocalUserAccount {
    param(
        [string]$Username,
        [string]$Group,
        [string]$PlainPassword,
        [bool]  $Generated
    )

    # Check if user already exists
    $alreadyExists = $false
    try {
        Get-LocalUser -Name $Username -ErrorAction Stop | Out-Null
        $alreadyExists = $true
    } catch { }

    if ($alreadyExists) {
        Write-Log -Level WARNING -Message "Local user '$Username' already exists - skipping"
        return $false
    }

    if ($DryRun) {
        Write-Log -Level "DRY-RUN" -Message "Would create local user: $Username (group=$Group)"
        if ($Generated) {
            Write-Log -Level "DRY-RUN" -Message "Would auto-generate password for: $Username"
        }
        Write-Log -Level "DRY-RUN" -Message "Would set PasswordChangeRequired for: $Username"
        return $true
    }

    $secPwd = ConvertTo-SecurePlain $PlainPassword

    $params = @{
        Name                     = $Username
        Password                 = $secPwd
        PasswordNeverExpires     = $false
        UserMayNotChangePassword = $false
        AccountNeverExpires      = $true
    }
    New-LocalUser @params | Out-Null
    Write-Log -Level INFO -Message "Created local user: $Username"

    # Add to group
    Ensure-LocalGroup $Group
    Add-LocalGroupMember -Group $Group -Member $Username
    Write-Log -Level INFO -Message "Added '$Username' to local group '$Group'"

    # Force password change at next logon (LocalAccounts module has no direct API)
    & net user $Username /logonpasswordchg:yes 2>&1 | Out-Null
    Write-Log -Level INFO -Message "Set password-change-at-next-logon for: $Username"

    if ($Generated) {
        Save-GeneratedCredential -Username $Username -Password $PlainPassword
    }

    return $true
}

# ---------------------------------------------------------------------------
# Active Directory user creation
# ---------------------------------------------------------------------------
function New-ADUserAccount {
    param(
        [string]$Username,
        [string]$Group,
        [string]$PlainPassword,
        [bool]  $Generated
    )

    # Check if user already exists
    $alreadyExists = $false
    try {
        Get-ADUser -Identity $Username -ErrorAction Stop | Out-Null
        $alreadyExists = $true
    } catch { }

    if ($alreadyExists) {
        Write-Log -Level WARNING -Message "AD user '$Username' already exists - skipping"
        return $false
    }

    if ($DryRun) {
        Write-Log -Level "DRY-RUN" -Message "Would create AD user: $Username (group=$Group, OU=$OUPath)"
        if ($Generated) {
            Write-Log -Level "DRY-RUN" -Message "Would auto-generate password for: $Username"
        }
        return $true
    }

    $secPwd = ConvertTo-SecurePlain $PlainPassword

    $params = @{
        SamAccountName        = $Username
        Name                  = $Username
        AccountPassword       = $secPwd
        Enabled               = $true
        ChangePasswordAtLogon = $true
        PasswordNeverExpires  = $false
    }
    if ($OUPath) { $params["Path"] = $OUPath }

    New-ADUser @params
    Write-Log -Level INFO -Message "Created AD user: $Username"

    Ensure-ADGroup $Group
    Add-ADGroupMember -Identity $Group -Members $Username
    Write-Log -Level INFO -Message "Added '$Username' to AD group '$Group'"

    if ($Generated) {
        Save-GeneratedCredential -Username $Username -Password $PlainPassword
    }

    return $true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
function Main {
    Initialize-Log

    Write-Log -Level INFO -Message "=== create_users.ps1 started ==="
    Write-Log -Level INFO -Message "CSV file : $CsvFile"
    $modeStr = if ($UseAD) { "Active Directory" } else { "Local" }
    Write-Log -Level INFO -Message "Mode     : $modeStr"
    Write-Log -Level INFO -Message "Dry run  : $DryRun"

    if (-not (Test-Path $CsvFile)) {
        Write-Log -Level ERROR -Message "CSV file not found: $CsvFile"
        exit 1
    }

    if ($UseAD) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Log -Level ERROR -Message "ActiveDirectory module not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory*"
            exit 1
        }
        Import-Module ActiveDirectory -ErrorAction Stop
    }

    $rows    = Import-Csv -Path $CsvFile
    $total   = 0
    $created = 0
    $skipped = 0
    $failed  = 0

    foreach ($row in $rows) {
        $total++

        $username = $row.username.Trim()
        $group    = $row.group.Trim()
        $password = ""
        if ($row.PSObject.Properties['password']) {
            $password = $row.password.Trim()
        }

        # Skip blank or comment rows
        if ([string]::IsNullOrWhiteSpace($username) -or $username.StartsWith('#')) {
            $total--
            continue
        }

        # Validate username (Windows SAM: 1-20 chars)
        if ($username -notmatch '^[A-Za-z0-9._-]{1,20}$') {
            Write-Log -Level ERROR -Message "Invalid username '$username' - skipping"
            $failed++
            continue
        }

        if ([string]::IsNullOrWhiteSpace($group)) { $group = $username }

        $generated = $false
        if ([string]::IsNullOrWhiteSpace($password)) {
            $password  = New-RandomPassword
            $generated = $true
        }

        try {
            $result = $false
            if ($UseAD) {
                $result = New-ADUserAccount    -Username $username -Group $group -PlainPassword $password -Generated $generated
            } else {
                $result = New-LocalUserAccount -Username $username -Group $group -PlainPassword $password -Generated $generated
            }
            if ($result) { $created++ } else { $skipped++ }
        } catch {
            Write-Log -Level ERROR -Message "Failed to create '$username': $($_.Exception.Message)"
            $failed++
        }
    }

    Write-Log -Level INFO -Message "=== Summary: $total total, $created created, $skipped skipped, $failed failed ==="

    if ($failed -gt 0) {
        Write-Log -Level WARNING -Message "Some users failed - check $($script:LogFile)"
        exit 1
    }
}

Main
