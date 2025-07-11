<#
.SYNOPSIS
    Sets up a complete Active Directory lab environment with intentional
    misconfigurations for BloodHound security analysis.

.DESCRIPTION
    This enhanced script automates the creation of users, groups, computers, and OUs,
    configures specific permissions and settings to create vulnerabilities detectable
    by BloodHound, and includes additional attack paths and cleanup functionality.

.NOTES
    Author: Gemini (Enhanced Version)
    Version: 3.0
    Features Added:
    - Automated GPO configuration
    - Random password generation
    - Additional attack paths
    - Comprehensive logging
    - Cleanup functionality
    - Shadow admin scenario
    - Excessive rights user
    - Inactive privileged account

    Instructions: 
    1. DELETE any existing "BloodHound_Lab" OU before running.
    2. Run this script from an elevated PowerShell window on your Domain Controller.
    3. Review the generated passwords in .\BH_Lab_Credentials.txt
    4. Run the SharpHound collector using: .\SharpHound.exe -c All
#>

#region Initialization
# --- Configuration ---
$domainPath = "DC=mylab,DC=local"
$domainNetBIOS = "MYLAB"
$labOU = "OU=BloodHound_Lab,$domainPath"
$logFile = ".\BH_Lab_Setup_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$credFile = ".\BH_Lab_Credentials.txt"

# Create secure password generator function
function New-RandomPassword {
    param([int]$Length = 16)
    $charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*"
    $password = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $charset[(Get-Random -Maximum $charset.Length)]
    }
    return $password
}

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage -ForegroundColor $Color
}

# Cleanup old files if they exist
if (Test-Path $credFile) { Remove-Item $credFile -Force }
if (Test-Path $logFile) { Remove-Item $logFile -Force }

Write-Log "Starting BloodHound Lab Setup" -Color Green
Write-Log "Log file: $logFile" -Color Cyan
Write-Log "Credentials will be saved to: $credFile" -Color Cyan

# Create credential header
Add-Content -Path $credFile -Value "BloodHound Lab Credentials"
Add-Content -Path $credFile -Value "Generated on: $(Get-Date)"
Add-Content -Path $credFile -Value "----------------------------------`n"
#endregion

#region Main Lab Setup
# --- Setup Main Lab OU ---
try {
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$labOU'" -ErrorAction SilentlyContinue) {
        Write-Log "[-] Lab OU already exists. Please delete it before running this script." -Color Red
        exit
    }
    
    New-ADOrganizationalUnit -Name "BloodHound_Lab" -Path $domainPath
    Write-Log "[+] Created main lab OU: BloodHound_Lab" -Color Green
}
catch {
    Write-Log "[!] ERROR creating main lab OU: $($_.Exception.Message)" -Color Red
    exit
}

# Create sub-OUs
$subOUs = @(
    "Vulnerable_Workstations",
    "Privileged_Accounts",
    "Service_Accounts",
    "Security_Groups"
)

foreach ($ou in $subOUs) {
    try {
        New-ADOrganizationalUnit -Name $ou -Path $labOU
        Write-Log "[+] Created sub-OU: $ou" -Color Green
    }
    catch {
        Write-Log "[!] ERROR creating sub-OU $ou: $($_.Exception.Message)" -Color Red
    }
}
#endregion

#region Test Case 1: Principals with DCSync Rights
Write-Log "`n--- [1] Creating user with DCSync rights ---" -Color Yellow
$dcsyncPass = New-RandomPassword
$dcsyncSecure = ConvertTo-SecureString $dcsyncPass -AsPlainText -Force

try {
    $user = New-ADUser -Name "user.dcsync" -SamAccountName "user.dcsync" -Path "OU=Privileged_Accounts,$labOU" `
        -AccountPassword $dcsyncSecure -Enabled $true -Description "This user can perform DCSync."
    
    $domainObject = Get-ADDomain
    $acl = Get-Acl "AD:$($domainObject.DistinguishedName)"
    # GUIDs for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
    $getChangesGuid = [System.Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    $getChangesAllGuid = [System.Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user.SID, "ExtendedRight", "Allow", $getChangesGuid))
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $user.SID, "ExtendedRight", "Allow", $getChangesAllGuid))
    Set-Acl -AclObject $acl "AD:$($domainObject.DistinguishedName)"
    
    Add-Content -Path $credFile -Value "DCSync User:"
    Add-Content -Path $credFile -Value "Username: user.dcsync"
    Add-Content -Path $credFile -Value "Password: $dcsyncPass`n"
    
    Write-Log "[+] Created 'user.dcsync' and granted DCSync rights." -Color Green
}
catch {
    Write-Log "[!] ERROR setting up DCSync user: $($_.Exception.Message)" -Color Red
}
#endregion

#region Test Case 2 & 3: Kerberos Vulnerabilities
Write-Log "`n--- [2 & 3] Creating Kerberoastable and AS-REP Roastable users ---" -Color Yellow

# Kerberoastable user
$kerberoastPass = New-RandomPassword
$kerberoastSecure = ConvertTo-SecureString $kerberoastPass -AsPlainText -Force

try {
    New-ADUser -Name "user.kerberoastable" -SamAccountName "user.kerberoastable" -Path "OU=Service_Accounts,$labOU" `
        -AccountPassword $kerberoastSecure -Enabled $true -ServicePrincipalNames @{Add="MSSQLSvc/db.mylab.local:1433"} `
        -Description "This user has an SPN and is Kerberoastable."
    
    Add-Content -Path $credFile -Value "Kerberoastable User:"
    Add-Content -Path $credFile -Value "Username: user.kerberoastable"
    Add-Content -Path $credFile -Value "Password: $kerberoastPass`n"
    
    Write-Log "[+] Created Kerberoastable user 'user.kerberoastable'." -Color Green
}
catch {
    Write-Log "[!] ERROR creating Kerberoastable user: $($_.Exception.Message)" -Color Red
}

# AS-REP Roastable user
$asrepPass = New-RandomPassword
$asrepSecure = ConvertTo-SecureString $asrepPass -AsPlainText -Force

try {
    New-ADUser -Name "user.asreproast" -SamAccountName "user.asreproast" -Path "OU=Service_Accounts,$labOU" `
        -AccountPassword $asrepSecure -Enabled $true -DoesNotRequirePreAuth $true `
        -Description "This user does not require Kerberos pre-authentication."
    
    Add-Content -Path $credFile -Value "AS-REP Roastable User:"
    Add-Content -Path $credFile -Value "Username: user.asreproast"
    Add-Content -Path $credFile -Value "Password: $asrepPass`n"
    
    Write-Log "[+] Created AS-REP Roastable user 'user.asreproast'." -Color Green
}
catch {
    Write-Log "[!] ERROR creating AS-REP Roastable user: $($_.Exception.Message)" -Color Red
}
#endregion

#region Test Case 4: Attack Path to Domain Admins
Write-Log "`n--- [4] Creating privilege escalation path to Domain Admins ---" -Color Yellow

$lowprivPass = New-RandomPassword
$lowprivSecure = ConvertTo-SecureString $lowprivPass -AsPlainText -Force

try {
    # Create low privilege user
    New-ADUser -Name "user.lowpriv" -SamAccountName "user.lowpriv" -Path "OU=Privileged_Accounts,$labOU" `
        -AccountPassword $lowprivSecure -Enabled $true -Description "Low privilege user that can escalate to Domain Admin"
    
    Add-Content -Path $credFile -Value "Low Privilege User:"
    Add-Content -Path $credFile -Value "Username: user.lowpriv"
    Add-Content -Path $credFile -Value "Password: $lowprivPass`n"
    
    # Create HelpDesk group and add user
    $helpDeskGroup = New-ADGroup -Name "GRP_HelpDesk" -SamAccountName "GRP_HelpDesk" `
        -GroupCategory Security -GroupScope Global -Path "OU=Security_Groups,$labOU" `
        -Description "HelpDesk group with excessive privileges"
    
    Add-ADGroupMember -Identity $helpDeskGroup -Members "user.lowpriv"
    
    Write-Log "[+] Created user 'user.lowpriv' and group 'GRP_HelpDesk'." -Color Green
}
catch {
    Write-Log "[!] ERROR setting up attack path objects: $($_.Exception.Message)" -Color Red
}
#endregion

#region Test Case 5, 6, & 7: GPO-based Vulnerabilities
Write-Log "`n--- [5, 6, 7] Creating vulnerable computer OU and GPO ---" -Color Yellow

try {
    # Create vulnerable workstation
    if (-not(Get-ADComputer -Identity "VULN-WS01" -ErrorAction SilentlyContinue)) {
        New-ADComputer -Name "VULN-WS01" -SamAccountName "VULN-WS01$" -Path "OU=Vulnerable_Workstations,$labOU" -Enabled $true
        Write-Log "[+] Created computer 'VULN-WS01' in Vulnerable_Workstations OU." -Color Green
    }

    # Create GPO with vulnerable settings
    if (-not(Get-GPO -Name "GPO_Vulnerable_Settings" -ErrorAction SilentlyContinue)) {
        $gpo = New-GPO -Name "GPO_Vulnerable_Settings" -Comment "Makes specific groups local admins and RDP users on linked computers."
        New-GPLink -Name $gpo.DisplayName -Target "OU=Vulnerable_Workstations,$labOU"
        
        # Configure Local Admin rights via GPO
        $gpoGuid = $gpo.Id.ToString()
        $gpoDomain = $domainNetBIOS
        $gpoPath = "\\$($domainNetBIOS.ToLower())\sysvol\$($domainNetBIOS.ToLower())\Policies\{$gpoGuid}\Machine\Preferences\Groups\Groups.xml"
        
        $groupsXML = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" uid="{6FC97F8E-ED31-4E36-BD3F-1C016D9E2979}">
        <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
            <Members>
                <Member name="$($domainNetBIOS)\Domain Users" action="ADD" sid="" />
                <Member name="$($domainNetBIOS)\GRP_HelpDesk" action="ADD" sid="" />
                <Member name="$($domainNetBIOS)\Domain Admins" action="ADD" sid="" />
            </Members>
        </Properties>
    </Group>
    <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Remote Desktop Users (built-in)" image="2" changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" uid="{7D0D35A0-7F2D-4E9E-8C6F-C7D6B5E8C9D3}">
        <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-555" groupName="Remote Desktop Users (built-in)">
            <Members>
                <Member name="$($domainNetBIOS)\Domain Users" action="ADD" sid="" />
            </Members>
        </Properties>
    </Group>
</Groups>
"@

        # Create directory structure if it doesn't exist
        $gpoDir = Split-Path $gpoPath
        if (-not (Test-Path $gpoDir)) {
            New-Item -ItemType Directory -Path $gpoDir -Force | Out-Null
        }
        
        # Save the XML file
        $groupsXML | Out-File -FilePath $gpoPath -Encoding utf8 -Force
        
        Write-Log "[+] Created and configured GPO 'GPO_Vulnerable_Settings' with:" -Color Green
        Write-Log "    - Domain Users as Local Admins" -Color Green
        Write-Log "    - GRP_HelpDesk as Local Admins" -Color Green
        Write-Log "    - Domain Users as RDP Users" -Color Green
    }
    else {
        Write-Log "[*] GPO 'GPO_Vulnerable_Settings' already exists. Skipping." -Color Cyan
    }
}
catch {
    Write-Log "[!] ERROR setting up GPO scenario: $($_.Exception.Message)" -Color Red
}
#endregion

#region Additional Test Cases
Write-Log "`n--- [8] Creating additional attack paths and scenarios ---" -Color Yellow

# Test Case 8a: Shadow Admin
try {
    $shadowPass = New-RandomPassword
    $shadowSecure = ConvertTo-SecureString $shadowPass -AsPlainText -Force
    
    New-ADUser -Name "user.shadowadmin" -SamAccountName "user.shadowadmin" -Path "OU=Privileged_Accounts,$labOU" `
        -AccountPassword $shadowSecure -Enabled $true -Description "Shadow admin with indirect privileges"
    
    # Grant Account Operator rights (hidden admin)
    Add-ADGroupMember -Identity "Account Operators" -Members "user.shadowadmin"
    
    Add-Content -Path $credFile -Value "Shadow Admin User:"
    Add-Content -Path $credFile -Value "Username: user.shadowadmin"
    Add-Content -Path $credFile -Value "Password: $shadowPass`n"
    
    Write-Log "[+] Created shadow admin 'user.shadowadmin' (Account Operators)" -Color Green
}
catch {
    Write-Log "[!] ERROR creating shadow admin: $($_.Exception.Message)" -Color Red
}

# Test Case 8b: Excessive Rights User
try {
    $excessivePass = New-RandomPassword
    $excessiveSecure = ConvertTo-SecureString $excessivePass -AsPlainText -Force
    
    New-ADUser -Name "user.excessive" -SamAccountName "user.excessive" -Path "OU=Privileged_Accounts,$labOU" `
        -AccountPassword $excessiveSecure -Enabled $true -Description "User with excessive GPO modification rights"
    
    # Grant rights to modify all GPOs
    $gpoContainer = "CN=Policies,CN=System,$domainPath"
    $acl = Get-Acl "AD:$gpoContainer"
    $acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule "user.excessive", "GenericAll", "Allow"))
    Set-Acl -AclObject $acl "AD:$gpoContainer"
    
    Add-Content -Path $credFile -Value "Excessive Rights User:"
    Add-Content -Path $credFile -Value "Username: user.excessive"
    Add-Content -Path $credFile -Value "Password: $excessivePass`n"
    
    Write-Log "[+] Created user 'user.excessive' with GPO modification rights" -Color Green
}
catch {
    Write-Log "[!] ERROR creating excessive rights user: $($_.Exception.Message)" -Color Red
}

# Test Case 8c: Inactive Privileged Account
try {
    $inactivePass = New-RandomPassword
    $inactiveSecure = ConvertTo-SecureString $inactivePass -AsPlainText -Force
    
    New-ADUser -Name "user.inactiveadmin" -SamAccountName "user.inactiveadmin" -Path "OU=Privileged_Accounts,$labOU" `
        -AccountPassword $inactiveSecure -Enabled $false -Description "Disabled admin account that still has privileges"
    
    # Add to Domain Admins (even though disabled)
    Add-ADGroupMember -Identity "Domain Admins" -Members "user.inactiveadmin"
    
    Add-Content -Path $credFile -Value "Inactive Admin User:"
    Add-Content -Path $credFile -Value "Username: user.inactiveadmin"
    Add-Content -Path $credFile -Value "Password: $inactivePass`n"
    
    Write-Log "[+] Created inactive admin 'user.inactiveadmin' (in Domain Admins but disabled)" -Color Green
}
catch {
    Write-Log "[!] ERROR creating inactive admin: $($_.Exception.Message)" -Color Red
}
#endregion

#region Final Output
Write-Log "`n`n--- SCRIPT COMPLETE ---" -Color White
Write-Log "Active Directory structure successfully configured with:" -Color White
Write-Log "- DCSync user (user.dcsync)" -Color White
Write-Log "- Kerberoastable and AS-REP roastable users" -Color White
Write-Log "- Privilege escalation path to Domain Admins" -Color White
Write-Log "- GPO-based vulnerabilities (local admin and RDP rights)" -Color White
Write-Log "- Shadow admin scenario" -Color White
Write-Log "- Excessive rights user" -Color White
Write-Log "- Inactive privileged account" -Color White

Write-Log "`nAll credentials have been saved to: $credFile" -Color Yellow
Write-Log "Full setup log available at: $logFile" -Color Yellow

Write-Log "`nNext Steps:" -Color Cyan
Write-Log "1. Join a test workstation to the domain and move its computer object to the 'Vulnerable_Workstations' OU" -Color Cyan
Write-Log "2. Run 'gpupdate /force' on the test workstation" -Color Cyan
Write-Log "3. Run the SharpHound collector: .\SharpHound.exe -c All" -Color Cyan
Write-Log "4. Import the collected data into BloodHound and explore the attack paths" -Color Cyan

# Open credential file in Notepad
try {
    Start-Process notepad.exe $credFile
}
catch {
    Write-Log "[*] Could not automatically open credential file. Please open it manually." -Color Yellow
}
#endregion