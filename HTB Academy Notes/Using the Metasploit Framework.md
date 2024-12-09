
25-11-2024 12:22 pm

Tags: [[Metasploit]] 

References: https://academy.hackthebox.com/module/39/section/381


# Using the Metasploit Framework
- the Metasploit framework can be used to test security vulnerabilities, enumerate networks, execute attacks, and evade detection
![[S02_SS01.webp]]

**IMPORTANT**
Metasploit modules are in `/usr/share/metasploit-framework/modules`!!!

![[S04_SS03.png]]
## MSF Components
### Modules
- each module looks like this:
```shell-session
<No.> <type>/<os>/<service>/<name>
```
Example:
```shell-session
794   exploit/windows/ftp/scriptftp_list
```

|**Type**|**Description**|
|---|---|
|`Auxiliary`|Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality.|
|`Encoders`|Ensure that payloads are intact to their destination.|
|`Exploits`|Defined as modules that exploit a vulnerability that will allow for the payload delivery.|
|`NOPs`|(No Operation code) Keep the payload sizes consistent across exploit attempts.|
|`Payloads`|Code runs remotely and calls back to the attacker machine to establish a connection (or shell).|
|`Plugins`|Additional scripts can be integrated within an assessment with `msfconsole` and coexist.|
|`Post`|Wide array of modules to gather information, pivot deeper, etc.|

How to search:
```shell-session
msf6 > search eternalromance

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms17_010_psexec   2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   1  auxiliary/admin/smb/ms17_010_command  2017-03-14       normal  No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution

msf6 > search eternalromance type:exploit

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms17_010_psexec   2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```
==Note: We can also make our search a bit more coarse and reduce it to one category of services. For example, for the CVE, we could specify the year (`cve:<year>`), the platform Windows (`platform:<os>`), the type of module we want to find (`type:<auxiliary/exploit/post>`), the reliability rank (`rank:<rank>`), and the search name (`<pattern>`). This would reduce our results to only those that match all of the above.==
```shell-session
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/windows/http/exchange_proxylogon_rce    2021-03-02       excellent  Yes    Microsoft Exchange ProxyLogon RCE
   1  exploit/windows/http/exchange_proxyshell_rce    2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE
   2  exploit/windows/http/sharepoint_unsafe_control  2021-05-11       excellent  Yes    Microsoft SharePoint Unsafe Control and ViewState RCE
```
==Note: There is the option `setg`, which specifies options selected by us as permanent until the program is restarted. Therefore, if we are working on a particular target host, we can use this command to set the IP address once and not change it again until we change our focus to a different IP address.==
### Targets
- `show targets`
- don't forget to use `info` to see a module's details
```shell-session
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   Automatic
   1   IE 7 on Windows XP SP3
   2   IE 8 on Windows XP SP3
   3   IE 7 on Windows Vista
   4   IE 8 on Windows Vista
   5   IE 8 on Windows 7
   6   IE 9 on Windows 7


msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6

target => 6
```
### Payloads
- payloads help us return a shell after a successful exploitation
- there are 3 types of payload modules in Metasploit: **singles, stagers and stages**
- for example, `windows/shell_bind_tcp` is a single payload with no stage, whereas `windows/shell/bind_tcp` consists of a stager (`bind_tcp`) and a stage (`shell`)
- **single payloads** have the exploit and the shell code all in one which makes them more stable but are larger
- **stagers** are used to establish a network connection between the attacker and the victim
- **stages** are payload components downloaded by stager's modules
- **staged payloads** executes exploitation in different stages (step by step); this makes it less visible to the AV and the IPS

How to see all payloads available:
```shell-session
msf6 > show payloads
```

- the **Meterpreter** payload uses **DLL injection** to ensure the connection to the victim is stable, hard to detect and also persistent

**IMPORTANT**
**Meterpreter functionalities** include: keystroke capture, password hash collection, microphone tapping, and screenshotting to impersonating process security tokens.

- [GentilKiwi's Mimikatz Plugin](https://github.com/gentilkiwi/mimikatz) can add more useful plugins to msfconsole

- if we want to search for Meterpreter payloads only we can use `grep`:
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads
```
- for a more in-depth search we can use:
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads
```

After carefully picking the payload we need to set it:
```shell-session
msf6 > set payload <number>
```
Then we have to set the options:
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
```
Set options that are required (for example LHOST, LPORT, RHOST, RPORT, etc.).
Then `run` or `exploit`.

A list of payload types:

|**Payload**|**Description**|
|---|---|
|`generic/custom`|Generic listener, multi-use|
|`generic/shell_bind_tcp`|Generic listener, multi-use, normal shell, TCP connection binding|
|`generic/shell_reverse_tcp`|Generic listener, multi-use, normal shell, reverse TCP connection|
|`windows/x64/exec`|Executes an arbitrary command (Windows x64)|
|`windows/x64/loadlibrary`|Loads an arbitrary x64 library path|
|`windows/x64/messagebox`|Spawns a dialog via MessageBox using a customizable title, text & icon|
|`windows/x64/shell_reverse_tcp`|Normal shell, single payload, reverse TCP connection|
|`windows/x64/shell/reverse_tcp`|Normal shell, stager + stage, reverse TCP connection|
|`windows/x64/shell/bind_ipv6_tcp`|Normal shell, stager + stage, IPv6 Bind TCP stager|
|`windows/x64/meterpreter/$`|Meterpreter payload + varieties above|
|`windows/x64/powershell/$`|Interactive PowerShell sessions + varieties above|
|`windows/x64/vncinject/$`|VNC Server (Reflective Injection) + varieties above|












# Useful Links:

