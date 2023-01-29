---
title: Domain Enumeration cheatsheet
subtitle: Domain enumeration is the process of extracting information from the Active Directory like enumerating the users, groups, and other interesting fields and resources.

# Summary for listings and search engines
summary: Domain enumeration is the process of extracting information from the Active Directory like enumerating the users, groups, and other interesting fields and resources.

# Link this post with a project
projects: []

# Date published
date: '2022-07-17T00:00:00Z'

# Date updated
lastmod: '2022-07-17T00:00:00Z'

# Is this an unpublished draft?
draft: false

# Show this page in the Featured widget?
featured: false

# Featured image
# Place an image named `featured.jpg/png` in this page's folder and customize its options here.
image:
  caption: 'Image credit: [**Giovanni Pecoraro**](https://unsplash.com/photos/CpkOjOcXdUY)'
  focal_point: ''
  placement: 2
  preview_only: false

authors:
  - admin

tags:
  - Cheatsheet
  - Red Teaming
  - Windows
  - Active Directory
  - Enumeration

categories:
  - Cyber Security
  
---

## Module Import

Load the PowerView module:

```powershell
powershell -ep bypass
. .\PowerView.ps1
```

or the ActiveDirectory module (to use ActiveDirectory module without installing RSAT, we can use `Import-Module` for the valid Active Directory module DLL):

```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```

It works also in case of ConstrainedLanguage Mode:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

## Basic Enumeration

Get current domain or trusted domain objects:

```powershell
# PowerView
Get-NetDomain
Get-NetDomain -Domain "cyberlab.cybercorp.local"
Get-NetDomain -Domain "cybercorp.local"

## Test it via getting domain NetBios name
(gwmi Win32_NTDomain).DomainName

# ActiveDirectory Module
Get-ADDomain
Get-ADDomain -Identiy "cyberlab.cybercorp.local"
Get-ADDomain -Identiy "cybercorp.local"
```

Get domain SID for the current domain:

```powershell
# PowerView
Get-DomainSID

# ActiveDirectory Module
(Get-ADDomain).DomainSID
```

Get domain policy for the current domain or for a trusted domain:

```powershell
# PowerView
Get-DomainPolicy
(Get-DomainPolicy)."System Access"
(Get-DomainPolicy)."Kerberos Policy"
(Get-DomainPolicy -Domain "cybercorp.local")."System Access"
(Get-DomainPolicy -Domain "cybercorp.local")."Kerberos Policy"
```

Get Domain Controllers for the current or for a trusted domain:

```powershell
# PowerView
Get-NetDomainController						
Get-NetDomainController	-Domain "cybercorp.local"

# ActiveDirectory Module
Get-ADDomainController						
Get-ADDomainController -DomainName "cybercorp.local" -Discover
```

Get the list of users in the current domain:

```powershell
# PowerView
Get-NetUser
Get-NetUser | select -ExpandProperty samaccountname
Get-NetUser | select samaccountname,title,description,logoncount,pwdlastset
Get-NetUser -Domain "cybercorp.local" | select -ExpandProperty samaccountname
Get-NetUser -UserName "STUDENT1"

# ActiveDirectory Module
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity "STUDENT1" -Properties *
```
```batch
::cmd.exe
net user /domain
net user "STUDENT1" /domain
```

Get list of all properties for users in the current domain:

```powershell
# PowerView
Get-UserProperty					# All properties
Get-UserProperty -Properties "pwdlastset"		# Only pwdlastset property

# ActiveDirectory Module
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity "STUDENT1" -Properties *
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}	
```

Search for a particular string in a users' attribute:

```powershell
# PowerView
Find-UserField -Verbose
Find-UserField -SearchField "Description" -SearchTerm "built"

# ActiveDirectory Module
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select Name,Description
```

Get a list of computers in the current domain:

```powershell
# PowerView
Get-NetComputer 
Get-NetComputer -OperatingSystem "*Server 2016*" 
Get-NetComputer -Ping 
Get-NetComputer -FullData

## Get computer IPs
Get-NetComputer | % {$name=$_; $ip=[System.Net.Dns]::GetHostAddresses($name).IPAddressToString; Write-Host $name "`t : " $ip }

# ActiveDirectory Module
Get-ADComputer -Filter * | select Name 
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem 
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName} 	
Get-ADComputer -Filter * -Properties * 
```

Search for a particular string in a computer attribute:

```powershell
# PowerView
Find-ComputerField -SearchField "OperatingSystem" -SearchTerm "windows"	

# ActiveDirectory Module
Get-ADComputer -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

Get groups in the current domain:

```powershell
# PowerView
Get-NetGroup
Get-NetGroup -GroupName "Domain Admins" -FullData
Get-NetGroup -GroupName "Enterprise Admins" -FullData
Get-NetGroup -GroupName "*admin*"

# ActiveDirectory Module
Get-ADGroup -Filter *
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```
```batch
::cmd.exe
net group /domain 
net group "Domain Admins" /domain 
```

Get all the members of a group:

```powershell
# PowerView
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-NetGroupMember -GroupName "Enterprise Admins" -Recurse

# ActiveDirectory Module
Get-ADGroupMember -Identity "Domain Admins" -Recursive	
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive	
```

Get the group membership for a user:

```powershell
# PowerView
Get-NetGroup -UserName "STUDENT1"	

# ActiveDirectory Module
Get-ADPrincipalGroupMembership -Identity "STUDENT1"
```

Get local groups on localhost or an specified computer (need local admin rights on the target):

```powershell
# PowerView
Get-NetLocalGroup
Get-NetLocalGroup -ComputerName "COMPUTER1"
Get-NetLocalGroup -ComputerName "COMPUTER1" -ListGroups	

Get-NetLocalGroup -ComputerName "COMPUTER1" -GroupName "Remote Desktop Users"	
```

```batch
:: cmd.exe
net localgroup
```

Get all effective local/domain users/groups that can access the machine with local administrative privileges:

```powershell
# PowerView
Get-NetLocalGroup -ComputerName "COMPUTER1" -Recurse	
```

Get currently logged users on a computer (need local admin rights on the target):

```powershell
# PowerView
Get-NetLoggedon -ComputerName "COMPUTER1"
```

Get active sessions on the host:

```powershell
# PowerView
Get-NetSession -ComputerName "COMPUTER1"
```

Get currently locally logged users  on a computer (need remote registry - default in server OS):

```powershell
# PowerView
Get-LoggedOnLocal
Get-LoggedOnLocal -ComputerName "COMPUTER1"
```

Get the last logged user on a computer (need local admin rights on the target):

```powershell
# PowerView
Get-LastLoggedOn -ComputerName "COMPUTER1"
```

List RDP sessions inside a computer (need local admin rights on the target):

```powershell
# PowerView
Get-NetRDPSession -ComputerName "COMPUTER1"
```

Find shares on host in current domain:

```powershell
# PowerView
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose

## Check if the share is accessible
Invoke-ShareFinder -CheckShareAccess -Verbose
```

Find senstive files on computers in the domain:

```powershell
# PowerView
Invoke-FileFinder -Verbose
```

Get all fileservers of the domain:

```powershell
# PowerView
Get-NetFileServer	
```

Get list of GPO in current domain:

```powershell
# PowerView
Get-NetGPO
Get-NetGPO | select displayname,name,whencreated
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B83E8F4EF8081}"
Get-NetGPO -ComputerName "COMPUTER1"
```

GPO files are stored in the SYSVOL path: 

```powershell
cd "\\cyberlab.local\sysvol\cyberlab.local\Policies\{603ABE02-C554-49B1-A462-2FF89BC61CB2}"
```

and can be easily analized by using the tool *Registry.Pol Reader*. It is necessary to copy the folder to the local machine and then open the file *registry.pol* in the aforementioned tool. In case it is possible to install such tool on a machine in the analyzed domain, it can automatically capture and show all the policies.

Get GPO(s) which use Restricted Groups or groups.xml for interesting users:

```powershell
# PowerView
Get-NetGPOGroup
```

Get users/groups which are in a local group of a machine using GPO correlation (this command analyzes the GPO applied to the OU to which the computer belongs):

```powershell
# PowerView
Find-GPOComputerAdmin -ComputerName "COMPUTER1.cyberlab.local"	# Default group: Local Administrators
Find-GPOComputerAdmin -ComputerName "COMPUTER1.cyberlab.local" -LocalGroup "Remote Desktop Users"
Find-GPOComputerAdmin -ComputerName "COMPUTER1.cyberlab.local" -Recurse | select ComputerName,ObjectName,GPODisplayName,isGroup | ft
Find-GPOComputerAdmin -ComputerName "COMPUTER1.cyberlab.local" -Recurse | ?{$_.IsGroup -ne $true}
Find-GPOComputerAdmin -ComputerName "COMPUTER1.cyberlab.local" -Recurse | ?{$_.IsGroup -ne $true} | select ComputerName,ObjectName,GPODisplayName | ft
```

Get machines where the given user is member of a specific group using GPO correlation:

```powershell
# PowerView
Find-GPOLocation -UserName "STUDENT1" -Domain "cyberlab.local" -Verbose	# Default group: Local administrators
Find-GPOLocation -UserName "STUDENT1" -Domain "cyberlab.local" -LocalGroup "Remote Desktop Users" -Verbose
Find-GPOLocation -UserName "STUDENT1"  -Domain "cyberlab.local" | select ComputerName	
```

Get OUs in a domain:

```powershell
# PowerView
Get-NetOU -FullData
Get-NetOU -FullData | select Name,gplink

## List all the computers in all OUs
Get-NetOU | %{echo $_; Get-NetComputer -ADSPath $_; echo "---"}

## List all the computers in an OU
Get-NetOU "*student*" | %{Get-NetComputer -ADSPath $_}

## Enumerate all GPOs applied to an OU
Get-NetOU *student* | %{Get-NetComputer -ADSPath $_}
Get-NetGPO -ADSpath 'LDAP://cn={5BA02DB5-FC5E-4A57-A310-0B1600456CC7},cn=policies,cn=system,DC=cyberlab,DC=local'

# ActiveDirectory Module
Get-ADOrganizationalUnit -Filter * -Properties *	
```

## Access Control Lists (ACL)

**ACL Entities**

| Name | Description |
| ---- | ---- |
| SID  | Security IDentifier | 
| DACL | Discretionary Access Control List | 
| ACE  | Access Control Entry (contained in DACL) | 
| SACL | Security Access Control List (LOGS) | 

---

**ACE Structure**

| Name | Description|
| ---- | ---- |
| IdentityReference	| Subject | 
| ActiveDirectoryRights	| Privileges assigned to IdentityReference in relation to ObjectDN |
| ObjectDN | Target Object | 

**IdentityReference** can **ActiveDirectoryRights** on **ObjectDN**

----

**ActiveDirectoryRights**

| Name | Value | Description |
| ---- | ---- | ---- |
| AccessSystemSecurity 	| 16777216 	|  The right to get or set the SACL in the object security descriptor. |
| CreateChild 		| 1 		|  The right to create children of the object. |
| Delete			| 65536 	|  The right to delete the object. |
| DeleteChild 		| 2 		|  The right to delete children of the object. |
| DeleteTree 		| 64 		|  The right to delete all children of this object, regardless of the permissions of the children. |
| ExtendedRight 		| 256 		|  A customized control access right. For a list of possible extended rights, see the topic "Extended Rights" in the MSDN Library at http://msdn.microsoft.com. For more information about extended rights, see the topic "Control Access Rights" in the MSDN Library at http://msdn.microsoft.com. [AllExtendedRights - ability to add user to a group or reset password] |
| ForceChangePassword 	|   		|  Ability to change user's password |
| GenericAll 		| 983551 	|  The right to create or delete children, delete a subtree, read and write properties, examine children and the object itself, add and remove the object from the directory, and read or write with an extended right. [full rights to the object (add users to a group or reset user's password)] |
| GenericExecute 		| 131076 	|  The right to read permissions on, and list the contents of, a container object. |
| GenericRead 		| 131220	|  The right to read permissions on this object, read all the properties on this object, list this object name when the parent container is listed, and list the contents of this object if it is a container. |
| GenericWrite 		| 131112 	|  The right to read permissions on this object, write all the properties on this object, and perform all validated writes to this object. [update object's attributes (i.e logon script)] |
| ListChildren 		| 4 		|  The right to list children of this object. For more information about this right, see the topic "Controlling Object Visibility" in the MSDN Library http://msdn.microsoft.com/library. |
| ListObject 		| 128 		|  The right to list a particular object. For more information about this right, see the topic "Controlling Object Visibility" in the MSDN Library at http://msdn.microsoft.com/library. |
| ReadControl 		| 131072 	|  The right to read data from the security descriptor of the object, not including the data in the SACL. |
| ReadProperty 		| 16 		|  The right to read properties of the object. |
| Self 			| 8 		|  The right to perform an operation that is controlled by a validated write access right. [ability to add yourself to a group] |
| Synchronize 		| 1048576 	|  The right to use the object for synchronization. This right enables a thread to wait until that object is in the signaled state. |
| WriteDacl 		| 262144 	|  The right to modify the DACL in the object security descriptor. [modify object's ACEs and give attacker full control right over the object] |
| WriteOwner 		| 524288 	|  The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the ownership to other users. [change object owner to attacker controlled user take over the object] |
| WriteProperty 		| 32 		|  The right to write properties of the object. |


Get the ACLs associated with the specified SamAccountName (ObjectDN - Target object):

```powershell
# PowerView					
Get-ObjectAcl -SamAccountName "STUDENT1" -ResolveGUIDs
Get-ObjectAcl -SamAccountName "STUDENT1" -ResolveGUIDs | select IdentityReference,ActiveDirectoryRights
Get-ObjectAcl -SamAccountName "STUDENT1" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}	

Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs
```

Get the ACLs associated with the specified target AD prefix or path  (ObjectDN - Target object):

```powershell
# PowerView	
Get-ObjectAcl -ADSprefix "CN=Administrator,CN=Users" -Verbose
Get-ObjectAcl -ADSprefix "CN=FirstName LastName,CN=Users" -Verbose
Get-ObjectAcl -ADSpath "CN=FirstName LastName,CN=Users,DC=cyberlab,DC=cybercorp,DC=local" -Verbose

# ActiveDirectory Module
(Get-Acl "AD:\CN=Administrator,CN=Users,DC=cyberlab,DC=cybercorp,DC=local").Access	
```

Get the ACLs associated with the specified target LDAP path (ObjectDN - Target object):

```powershell
# PowerView
Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=cyberlab,DC=cybercorp,DC=local" -ResolveGUIDs -Verbose
```

Get the ACLs associated to all the GPOs:

```powershell
# PowerView
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}

## Enumerate those GPOs where a particular user has interesting permissions
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ?{$_.IdentityReference -match "STUDENT1"}
```

Search for interesting ACEs:

```powershell
# PowerView
Invoke-ACLScanner -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs | ft
Invoke-ACLScanner -ResolveGUIDs | select IdentityReference,ActiveDirectoryRights,ObjectDN | ft
Invoke-ACLScanner -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select IdentityReference,ActiveDirectoryRights,ObjectDN | ft

## Check if a particular user has interesting permissions
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "STUDENT1"}
```

Get the ACLs associated with the specified file path:

```powershell
# PowerView
Get-PathAcl -Path "\\cyberlab-dc.cyberlab.cybercorp.local\SYSVOL"
Get-PathAcl -Path "\\COMPUTER1.cyberlab.cybercorp.local\C$"
```

## Trusts and Forests

**Trust directions**

| Direction	 | Description |
| ---- | ---- |
| Bidirectional  | Two-way     | 
| Unidirectional | One-way     |

---

**Trust transitivity**

| Transitivity | Description |
| ---- | ---- |
| Transitive	 | Can be extended to other domains in the forest     | 
| Nontransititve | Cannot be extended to other domains in the forest  |

---

**Trust Type**

| Name | Type | Description |
| ---- | ---- | ---- |
| Parent-child   | Automatic | Automatically created between the new domain and the domain that precedes it in the namespace hierarchy whenever a new domain is added to a tree (always two-way transitive) | 
| Tree-root	 | Automatic | Automatically created whenever a new domain tree is added to a forest root (always two-way transitive) |
| External	 | Established | Two domains in different forests when forests do not have a trust relationship (one-way or two-way and nontransitive) |
| Shortcut 	 | Established | Used to reduce access times in complex trust scenarios (one-way or two-way) |
| Forest	 | Established | Between forest root domains (one-way or two-way and transitive, if specified, or nontransitive) |

---

Get a list of all domain trusts for the current or a trusted domain:

```powershell
# PowerView
Get-NetDomainTrust
Get-NetDomainTrust -Domain "cybercorp.local"

# ActiveDirectory Module
Get-ADTrust
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
Get-ADTrust -Identity "cybercorp.local" 
```

Get detail about the current or a trusted forest:

```powershell
# PowerView
Get-NetForest
Get-NetForest -Forest "evilcorp.local"

# ActiveDirectory Module
Get-ADForest
Get-ADForest -Identity "evilcorp.local"
```
Get all domains in the current or in a trusted forest:

```powershell
# PowerView
Get-NetForestDomain
Get-NetForestDomain -Forest "evilcorp.local"

# ActiveDirectory Module
(Get-ADForest).Domains
```

Get all global catalogs for the current or a trusted forest:

```powershell
# PowerView
Get-NetForestCatalog
Get-NetForestCatalog -Forest "evilcorp.local"

# ActiveDirectory Module
Get-ADForest | select -ExpandProperty GlobalCatalogs	
```

Map trusts of a forest:

```powershell
# PowerView
Get-NetForestTrust
Get-NetForestTrust -Forest "evilcorp.local"

# ActiveDirectory Module
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'	
```

Map all the trusts of the domains in the current or in a trusted forest:

```powershell
# PowerView
Get-NetForestDomain -Verbose | Get-NetDomainTrust
Get-NetForestDomain -Forest "evilcorp.local" -Verbose | Get-NetDomainTrust

## List only external trusts
Get-NetForestDomain -Verbose | Get-NetDomainTrust | ?{$_.TrustType -eq 'External'}

## List all trusts of a trusting forest
Get-NetForestDomain -Forest "evilcorp.local" -Verbose | GetNetDomainTrust
```

Try to build a relational mapping of all domain trusts:

```powershell
# PowerView
Invoke-MapDomainTrust
```

## User Hunting

Find all machines on the current/trusted domain where the current user has local admin access:

```powershell
# PowerView
Find-LocalAdminAccess -Verbose
Find-LocalAdminAccess -Verbose -NoPing
Find-LocalAdminAccess -Domain "cybercorp.local" -Verbose

# Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess -Verbose

Get-NetComputer -Domain cyberlab.local > .\targets.txt
Find-WMILocalAdminAccess -ComputerFile .\targets.txt

# Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Verbose

Get-NetComputer -Domain cyberlab.local > .\targets.txt
Find-PSRemotingLocalAdminAccess -ComputerFile .\targets.txt

# Find-PSRemotingLocalAdminAccessCreds.ps1
Find-PSRemotingLocalAdminAccessCreds -Username "STUDENT01" -Password "Password123." -Verbose
```

Find local admins on all machines of the domain (needs administrator privs on non-dc machines):

```powershell
# PowerView
Invoke-EnumerateLocalAdmin -Verbose
Invoke-EnumerateLocalAdmin -Verbose -NoPing
Invoke-EnumerateLocalAdmin | select ComputerName,AccountName,IsGroup | ft
```

Find computers where a domain admin (or specific user/group) has sessions: 

```powershell
# PowerView
Invoke-UserHunter 	# Domain Admins
invoke-UserHunter  | select UserDomain,UserName,ComputerName,SessionFromName | ft
Invoke-UserHunter -GroupName "Remote Desktop Users"	# Specific group
Invoke-UserHunter -Domain "cyberlab.local" -UserName "STUDENT1" # Specific user

Invoke-UserHunter -ComputerName "COMPUTER01" -Poll 100 -UserName "Administrator" -Delay 5 -Verbose
```

Find computers where a domain admin is logged into and checks if the local user has local administrator access:

```powershell
# PowerView
Invoke-UserHunter -CheckAccess	
```

Find computers where a domain admin is logged-in without sending queries to DCs:

```powershell
# PowerView
Invoke-UserHunter -Stealth	
```

## Bloodhound

Commands to be run on a Linux machine to run Bloodhound analyzer:

```bash
apt-get install bloodhound
neo4j console
bloodhound
```

Commands to be run on a domain machine to analyze the domain:

```powershell
.  .\SharpHound.ps1

## Gather data and information about the current domain
Invoke-BloodHound -CollectionMethod All -Verbose -JSONFolder "c:\experiments\bloodhound"
Invoke-BloodHound -CollectionMethod All -ExcludeDC -Verbose -JSONFolder "c:\experiments\bloodhound"

## Gather information about established sessions
InvokeBloodHound -CollectionMethod LoggedOn -Verbose
```

## Full Enumeration Sequence

```powershell
. .\PowerView.ps1
Get-NetDomain
Get-DomainSid
Get-NetForest
Get-NetForestDomain
Get-NetForestDomain | Get-NetDomainTrust
Get-NetForestTrust
Invoke-MapDomainTrust

# Execute domain analysis for all domain of interest
Get-NetDomain
(gwmi Win32_NTDomain).DomainName
Get-DomainSid
Get-NetDomainController
Get-NetComputer
Get-NetComputer -FullData | select name,operatingsystem,description
Get-NetComputer | % {$name=$_; $ip=[System.Net.Dns]::GetHostAddresses($name).IPAddressToString; Write-Host $name "`t : " $ip }
Get-NetOU
Get-NetOU | %{echo $_; Get-NetComputer -ADSPath $_; echo "---"}
Get-NetUser | select name,samaccountname,description
Get-NetUser | where {$_.mail}
Find-UserField -Verbose
Find-ComputerField -SearchField "OperatingSystem" -SearchTerm "windows"	
Get-NetGroup -GroupName "Domain Admins" -FullData
Get-NetGroupMember -GroupName "Domain Admins"
Get-NetGroup -GroupName "Enterprise Admins" -FullData
Get-NetGroupMember -GroupName "Enterprise Admins"
Get-NetGPO
Get-NetGPOGroup
Get-NetFileServer
Invoke-ShareFinder -ExcludeStandard -ExcludeIPC -ExcludePrint -CheckShareAccess
Invoke-ACLScanner -ResolveGUIDs | select IdentityReference,ActiveDirectoryRights,ObjectDN | ft

# Start to move laterally/escalate privileges
Find-LocalAdminAccess -Verbose -NoPing
Find-WMILocalAdminAccess -Verbose
Find-PSRemotingLocalAdminAccess -Verbose
Find-PSRemotingLocalAdminAccessCreds -Username "STUDENT01" -Password "Password123." -Verbose

# User Hunting (default: Domain Admins)
Invoke-UserHunter
Invoke-UserHunter -CheckAccess

# Port Scanning (PowerSploit)
Invoke-Portscan -Hosts @(Get-NetComputer) -TopPorts 100 | %{echo $_.Hostname; echo "--- OPEN ---"; echo $_.openPorts; echo "------------"; echo ""}

# Privilege Escalation
Get-NetUser -SPN # Kerberoasting
Get-NetComputer -Unconstrained # Unconstrained delegation
Get-DomainUser -PreauthNotRequired -Verbose # ASREPRoasting (PowerView_dev)
Get-DomainUser -TrustedToAuth # Constrained delegation (user)
Get-DomainComputer -TrustedToAuth # Constrained delegation (computer)

# Look for interesting MSSQL instance
Import-Module .\PowerUpSQL.psd1
Get-SQLInstanceDomain
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
Get-SQLInstanceDomain | Get-SQLServerInfoThreaded -Verbose
Invoke-SQLAudit -Verbose -Instance "SQLServer1\Instance1"
Invoke-SQLEscalatePriv -Verbose -Instance "SQLServer1\Instance1"
```
---