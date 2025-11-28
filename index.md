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
   - A tool that scans a given username across multiple social media domains 
More to come! 
```

## Latest Writeups
Check out my most recent posts below:
### - [VL: Retro](posts/vl-retro.md)
Retro is a easy active directory box where we enumerate a share, find out that the `trainee` user has a weak password, enumerate users, and then make a users.txt and pass the pass the password as the usernames from the user.txt and find out that one did indeed work and from there, we enumerate another share and exploit "Pre Created Computer Accounts" which was really fun. And then we exploit AD CS ESC1 and get Administrator

### - [HTB: Outbound](posts/htb-outbound.md)
Outbound is an easy linux assumed-breached box. With the starting creds, we log into the Roundcube webmail panel and quickly see it’s running a vulnerable version affected by `CVE-2025-49113`, a post-auth PHP object deserialization bug that gives us RCE. After popping a shell, we grab the database creds from the web config and go into MySQL. There, we find a session for the `jacob` user; base64-decoding it reveals an encrypted password. Using the `decrypt.sh` script on the box, we can decrypt it and access Jacob’s Roundcube mailbox, where we find valid login credentials.

With SSH access as jacob, some quick enumeration shows we can run the `below` monitoring utility as root. That tool is vulnerable to `CVE-2025-27591`, letting us escalate to a new user with a root-level UID.

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
