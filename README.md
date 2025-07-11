# BloodHound-Lab Active Directory Vulnerable Lab Setup

## Overview
This project provides a PowerShell script (`BloodHoundLab.ps1`) to automate the setup of a vulnerable Active Directory (AD) lab environment. The lab is intentionally misconfigured to expose common AD attack paths and vulnerabilities detectable by BloodHound, a popular AD enumeration tool.

## Features
- Automated creation of users, groups, computers, and OUs
- Assigns DCSync rights to a user
- Creates Kerberoastable and AS-REP roastable users
- Sets up privilege escalation paths via group memberships
- Prepares a vulnerable workstation and GPO for local admin and RDP access
- Step-by-step manual instructions for GPO configuration

## Prerequisites
- **Domain Controller** running Windows Server with the Active Directory module for PowerShell
- **Domain Name**: The script assumes `mylab.local` (edit `$domainPath` and `$domainNetBIOS` in the script if different)
- **Permissions**: Run as a Domain Admin in an elevated PowerShell window
- **BloodHound** and **SharpHound** binaries for post-setup enumeration

## Usage
1. **Preparation**
   - Delete any existing `BloodHound_Lab` OU from your domain before running the script.
   - Place `BloodHoundLab.ps1` on your Domain Controller.

2. **Run the Script**
   - Open PowerShell as Administrator.
   - Execute the script:
     ```powershell
     .\BloodHoundLab.ps1
     ```

3. **Manual GPO Configuration**
   - After the script completes, follow the printed instructions to:
     - Configure a GPO to add specific groups to the local Administrators and Remote Desktop Users groups on the vulnerable workstation.
     - Update group policy on the client machine if applicable.

4. **Collect Data with SharpHound**
   - On the Domain Controller, run:
     ```powershell
     .\SharpHound.exe -c All
     ```
   - Import the collected data into BloodHound for analysis.

## Manual Steps (Summary)
1. **Configure GPO for Local Admin Rights**
   - Add `Domain Users`, `GRP_HelpDesk`, and `Domain Admins` to the local Administrators group via GPO.
2. **Configure GPO for RDP Access**
   - Add `Domain Users` to the local Remote Desktop Users group via GPO.
3. **Update Policy on Client Machine**
   - Move the client computer to the `Vulnerable_Workstations` OU and run `gpupdate /force`.
4. **Run BloodHound Collector**
   - Use SharpHound to collect and analyze AD data.

## Notes
- The script is idempotent: it checks for existing objects before creating them.
- For a different domain, update the `$domainPath` and `$domainNetBIOS` variables at the top of the script.
- For more details, see the comments and instructions within `BloodHoundLab.ps1`.

## Author
- HITMAN949

## Version
- 2.1 

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 