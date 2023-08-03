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
