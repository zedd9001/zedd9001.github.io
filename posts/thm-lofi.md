# Lo-Fi - TryHackMe
# Info about the CTF
**Name**: Lo-Fi  
**Challenge author**: cmnatic  
**Writeup author**: [zedd9001](https://tryhackme.com/p/zedd9001)
# Intro 
Lo-Fi is a very simple THM challenge where we exploit LFI to read the flag
# Recon
## Doing some enumeration
This website is about listening to Lo-Fi. Sweet    
![alt text](/assets/img/thm/lofi/lofi.png)  
Visiting one of the `Discography` sections, we can see something interesting in the URL    
![alt text](/assets/img/thm/lofi/Discography.png)

## Potential LFI
The `page` parameter looks like it’s used to include server-side PHP files, If the app doesn’t validate that input, it can be abused for Local File Inclusion (LFI) That means an attacker might read local files (or, in worse setups, turn that into RCE)  
```
http://10.201.124.223/?page=relax.php 
```
Learn more about `LFI` here:

- [Acunetix's blog on LFI](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/) 
- [BrightSec's blog on LFI](https://brightsec.com/blog/local-file-inclusion-lfi/)

## Confirmed LFI vulnerability
A common file to read on linux when you have LFI is `/etc/passwd`, so let's attempt to read it with LFI!  
Changing the parameter to `../.././../etc/passwd`, gives us the output of `/etc/passwd`
```
http://10.201.124.223/?page=../../../../etc/passwd
```
![alt text](/assets/img/thm/lofi/lfi.png)
## Getting the flag
The flag is in the root directory, so we can get it by: 
```
http://10.201.124.223/?page=../.././../flag.txt
```
I unfortunately can't show the continents of the flag because I want you to do this by yourself so that you can learn
# Thoughts
This was a really simple and nice machine and a good way to learn LFI. Would recommend this one to a beginner
