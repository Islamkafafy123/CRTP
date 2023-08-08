# Domain Enumeration – User Hunting
- Find all machines on the current domain where the current user has local admin access
```
Find-LocalAdminAccess –Verbose
```
- This function queries the DC of the current or provided domain for a list of computers
```
Get-NetComputer
```
- then use multi-threaded on each machine
```
Invoke-CheckLocalAdminAccess 
```
- This can also be done with the help of remote administration tools like WMI and PowerShell remoting. Pretty useful in cases ports (RPC and SMB) used by Find-LocalAdminAccess are blocked
```
Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1
```
- Find computers where a domain admin (or specified user/group) has sessions
```
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "RDPUsers"
```
- queries the DC of the current or provided domain for members of the given group (Domain Admins by default)
```
Get-DomainGroupMember
```
- gets a list of computers
```
Get-DomainComputer
```
- list sessions and logged on users from each machine
```
Get-NetSession/Get-NetLoggedon
```
- Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess)
```
Find-DomainUserLocation -CheckAccess
```
- Find computers (File Servers and Distributed File servers) where a domain admin session is available
```
Find-DomainUserLocation –Stealth
```
# Privilege Escalation
- various ways of locally escalating privileges on Windows box
  - Missing patches
  - Automated deployment and AutoLogon passwords in clear text
  - AlwaysInstallElevated (Any user can run MSI as SYSTEM)
  - Misconfigured Services
  - DLL Hijacking and more
  - NTLM Relaying a.k.a. Won't Fix
