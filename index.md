# Hey, I’m Zack

Welcome to my personal writeup site  
[About me](/about.md)

## Latest Writeups
Check out my most recent posts below:
### - [HMV: Friendly](posts/hmv-friendly1.md)
Friendly is an easy linux box made for beginners which starts with exploiting FTP to uploading a reverse shell on FTP which also has the webserver in it. Then we get root by exploiting vim and rooting this boot2root machine
### - [HTB: Artificial](posts/htb-artificial.md)
Artificial is an easy rated box that starts with a web app upload RCE. We find the app, grab the Dockerfile/requirements, build a malicious .h5 model inside Docker using a TensorFlow RCE PoC, upload it, and get a reverse shell as app. From there we dump instance/users.db, crack an MD5 hash to get gael’s password, SSH in as gael, find a Backrest service and a base64’d bcrypt secret, decode + crack it, log into Backrest, restore /root/.ssh/id_rsa, and then SSH in as root
### - [HTB: Cap](posts/htb-cap.md)  
Cap is an easy rated straight forward HackTheBox machine which starts off with an IDOR which allows us to analyze other users .pcap files, changing the value which is vulnerable to IDOR to 0 and then analyzing the file we find credentials and then log into SSH, there we find that an exploitable capability is there and is in GTFOBins and then we root the box
### - [THM: Lo-Fi](posts/thm-lofi.md)
Lo-Fi is a very simple THM challenge where we exploit LFI to read the flag  

---
Socials  
- GitHub: [@zedd9001](https://github.com/zedd9001)
- Discord: zedd9001
- HackTheBox: [zedd9001](https://app.hackthebox.com/users/2732230) 
- TryHackMe: [zedd9001](https://tryhackme.com/p/zedd9001)
