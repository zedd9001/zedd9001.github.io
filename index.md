# Hey, I’m Zack

## About me
```
$ whoami
zedd9001
$ cat README.md
Hey! I'm Zack
I'm still in school but I am very passionate about 
computer science and cyber! 
$ cat projects.md
user-finder.py/user-finder.py 
-  A tool that scans a given username across multiple social media domains 
More to come! 
```

## Latest Writeups
Check out my most recent posts below:
### - [HTB: Outbound](posts/htb-outbound.md)
Outbound is an easy rated linux assumed-breached machine which with the starting credentials, we get access to the Roundcube webmail interface. From there, we enumerate the Roundcube version and find out that it is vulnerable to `CVE-2025–49113`, a post-authenticated PHP object deserialization vulnerability effectively giving us RCE. After getting a shell on the target. We find database credentials in the config file for the web server. Connecting to the `mysql` database and enumerating it, we find a session that belongs to Jacob user that when base64 decoded, we find an encrypted password. Using the `decrypt.sh` file in the webserver, we can decode it and get access to her Roundcube mail. From there, we get a mail containing credentials for jacob's account.  
  
Getting SSH access as jacob, and a bit of enumeration, we find out that we can run the `below` monitoring utility with root privileges. That utility is vulnerable to `CVE-2025-27591` which then we can escalate our privileges to a new user with a root-level UID
# Box info
### - [HMV: Friendly](posts/hmv-friendly1.md)
Friendly is an easy linux box made for beginners which starts with exploiting FTP to uploading a reverse shell on FTP which also has the webserver in it. Then we get root by exploiting vim and rooting this boot2root machine
### - [HTB: Artificial](posts/htb-artificial.md)
Artificial is an easy rated linux box that starts with a web app upload RCE. We find the app, grab the Dockerfile/requirements, build a malicious .h5 model inside Docker using a TensorFlow RCE PoC, upload it, and get a reverse shell as app. From there we dump instance/users.db, crack an MD5 hash to get gael’s password, SSH in as gael, find a Backrest service and a base64’d bcrypt secret, decode + crack it, log into Backrest, restore /root/.ssh/id_rsa, and then SSH in as root
### - [HTB: Cap](posts/htb-cap.md)  
Cap is an easy rated straight forward linux HackTheBox machine which starts off with an IDOR which allows us to analyze other users .pcap files, changing the value which is vulnerable to IDOR to 0 and then analyzing the file we find credentials and then log into SSH, there we find that an exploitable capability is there and is in GTFOBins and then we root the box
### - [THM: Lo-Fi](posts/thm-lofi.md)
Lo-Fi is a very simple THM challenge where we exploit LFI to read the flag  

---
Socials  
- GitHub: [@zedd9001](https://github.com/zedd9001)
- Discord: zedd9001
- HackTheBox: [zedd9001](https://app.hackthebox.com/users/2732230) 
- TryHackMe: [zedd9001](https://tryhackme.com/p/zedd9001)
