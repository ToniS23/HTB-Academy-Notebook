
29-07-2024 17:58 pm

Tags: [[Windows]] [[Operating Systems]] [[Services and Processes]]

References: https://academy.hackthebox.com/module/49/section/454


# Windows Fundamentals

## Introduction

Useful Get-WmiObject commands in PowerShell:
- Get-WmiObject Win32_OperatingSystem
- Get-WmiObject Win32_Process
- Get-WmiObject Win32_Service
- Get-WmiObject Win32_Bios (note: a bios is the firmware installed on a computer's motherboard that controls the basic functions such as power management, io interfaces and system configuration)

Remote Access Concepts:
- Virtual Private Networks (VPN)
- Secure Shell (SSH)
- File Transfer Protocol (FTP)
- Virtual Network Computing (VNC)
- Windows Remote Management (or PowerShell Remoting) (WinRM)
- Remote Desktop Protocol (RDP)

Note: In windows we have remote desktop connection and in linux we have xfreerdp.

==xfreerdp basic syntax==: xfreerdp /v:{ip} /u:{user} /p:{password}
## Core of the Operating System

### Operating System Structure

Note: The root directory is C usually.

| **Directory**              | **Function**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Perflogs                   | Can hold Windows performance logs but is empty by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Program Files              | On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here.                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Program Files (x86)        | 32-bit and 16-bit programs are installed here on 64-bit editions of Windows.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ProgramData                | This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it.                                                                                                                                                                                                                                                                                                                                                                                  |
| Users                      | This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Default                    | This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile.                                                                                                                                                                                                                                                                                                                                                                                                    |
| Public                     | This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access.                                                                                                                                                                                                                                                                                                                                                         |
| AppData                    | Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode. |
| Windows                    | The majority of the files required for the Windows operating system are contained here.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| System, System32, SysWOW64 | Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path.                                                                                                                                                                                                                                                                                                                                                        |
| WinSxS                     | The Windows Component Store contains a copy of all Windows components, updates, and service packs.                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

Useful Windows Commands:
- dir = shows directories
- tree = graphical interface of directories structures

## Integrity Control Access Control List (icacls)

Used to see NTFS permissions or modify them in Windows systems.

- icacls C:\\Users\\{user} to view permissions
- icacls C:\\Users\\ /grant {user}:{type_of_access} to grant access to a user
- icacls C:\\Users\\ /remove {user}:{type_of_access} to remove access from a user

## Creating a Network Share

1. On the Windows target system, create a folder and share it using advanced sharing.
2. Check the security tab to see permissions.
3. Permissions need to be set in the windows defender firewall (or just disable it) in order to send outbound packets to the Windows system.
4. We can either connect to the shared folder with smbclient or just mount the shared folder on our machine.

==smbclient syntax==: 
```
smbclient -L {ip} -U {user} OR smbclient '\\\\{ip}\\{path_to_shared_folder}' -U {user}
```

==mounting syntax==: 
```
sudo mount -t cifs -o username={user},password={password} //{target_ip}/{path_to_shared_folder} {path_to_LOCAL_folder}
```
-t refers to file type system, in our case cifs (Common Internet File System);
-o refers to the options, username and password;

Note: ==net share== command inputted in PowerShell is used to see all the shares or just see them in the Computer Management tool (also has event viewer; important for audits).

## Windows Services and Processes

Get-Service command in PowerShell to see all the services and their statuses or just use the Services app from Windows.

| **Tab**         | **Description**                                                                                                                                                                                                                                                  |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Processes tab   | Shows a list of running applications and background processes along with the CPU, memory, disk, network, and power usage for each.                                                                                                                               |
| Performance tab | Shows graphs and data such as CPU utilization, system uptime, memory usage, disk and, networking, and GPU usage. We can also open the `Resource Monitor`, which gives us a much more in-depth view of the current CPU, Memory, Disk, and Network resource usage. |
## Service Permissions

- Windows services can be used as an attack vector
- A user should have access only to what they absolutely need (principle of least pivilege)

Note: We can create new accounts just for running certain services.

```cmd-session
C:\Users\htb-student>sc qc wuauserv
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: wuauserv
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\WINDOWS\system32\svchost.exe -k netsvcs -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Windows Update
        DEPENDENCIES       : rpcss
        SERVICE_START_NAME : LocalSystem
```

- sc qc {service_name} is used to query a service
- we can also stop services with sc stop {service_name}

We can get details for a service in ps with Get-ACL:
```powershell-session
PS C:\Users\htb-student> Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wuauserv
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Users Allow  -2147483648
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -2147483648
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow
         ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow
         -2147483648
Audit  :
Sddl   : O:SYG:SYD:AI(A;ID;KR;;;BU)(A;CIIOID;GR;;;BU)(A;ID;KA;;;BA)(A;CIIOID;GA;;;BA)(A;ID;KA;;;SY)(A;CIIOID;GA;;;SY)(A
         ;CIIOID;GA;;;CO)(A;ID;KR;;;AC)(A;CIIOID;GR;;;AC)(A;ID;KR;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654
         721687-432734479-3232135806-4053264122-3456934681)(A;CIIOID;GR;;;S-1-15-3-1024-1065365936-1281604716-351173842
         8-1654721687-432734479-3232135806-4053264122-3456934681)
```

## Windows Sessions

There are two types:
- interactive (local logon session)
- non-interactive

Non-interactive accounts:

| **Account**             | **Description**                                                                                                                                                                                                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Local System Account    | Also known as the `NT AUTHORITY\SYSTEM` account, this is the most powerful account in Windows systems. It is used for a variety of OS-related tasks, such as starting Windows services. This account is more powerful than accounts in the local administrators group. |
| Local Service Account   | Known as the `NT AUTHORITY\LocalService` account, this is a less privileged version of the SYSTEM account and has similar privileges to a local user account. It is granted limited functionality and can start some services.                                         |
| Network Service Account | This is known as the `NT AUTHORITY\NetworkService` account and is similar to a standard domain user account. It has similar privileges to the Local Service Account on the local machine. It can establish authenticated sessions for certain network services.        |

## Interacting with Windows

In powershell we can fin different information with cmdlets:
- get-alias -List or certain program to get the alias
- scripts can be run with ./name
- get-module to list all the modules
- get-executionpolicy -List to see the execution policy list

## Windows Management Instrumentation (WMI)

- it's a subsystem of powershell
- it's goal is to consolidate device and application management in a corporation's network

| **Component Name** | **Description**                                                                                                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WMI service        | The Windows Management Instrumentation process, which runs automatically at boot and acts as an intermediary between WMI providers, the WMI repository, and managing applications. |
| Managed objects    | Any logical or physical components that can be managed by WMI.                                                                                                                     |
| WMI providers      | Objects that monitor events/data related to a specific object.                                                                                                                     |
| Classes            | These are used by the WMI providers to pass data to the WMI service.                                                                                                               |
| Methods            | These are attached to classes and allow actions to be performed. For example, methods can be used to start/stop processes on remote machines.                                      |
| WMI repository     | A database that stores all static data related to WMI.                                                                                                                             |
| CIM Object Manager | The system that requests data from WMI providers and returns it to the application requesting it.                                                                                  |
| WMI API            | Enables applications to access the WMI infrastructure.                                                                                                                             |
| WMI Consumer       | Sends queries to objects via the CIM Object Manager.                                                                                                                               |

Some of the uses for WMI are:
- Status information for local/remote systems
- Configuring security settings on remote machines/applications
- Setting and changing user and group permissions
- Setting/modifying system properties
- Code execution
- Scheduling processes
- Setting up logging

Note: ==WMI== can be accessed in the CMD by typing ==wmic==.

```cmd-session
C:\htb> wmic os list brief

BuildNumber  Organization  RegisteredUser  SerialNumber             SystemDirectory      Version
19041                      Owner           00123-00123-00123-AAOEM  C:\Windows\system32  10.0.19041
```

## Microsoft Management Console (MMC)

- snap-ins (tools) can be created or added in order to manage a system
- it can be configured to make changes locally or on another pc

## Windows Security

### Security Identifier (SID)

- Windows follows certain security principles, each of them having a corresponding SID
- SIDs are basically string values stored in a db which are added to the user's token to identify the actions that the user is authorized to take

example:
```powershell-session
PS C:\htb> whoami /user

USER INFORMATION
----------------

User Name           SID
=================== =============================================
ws01\bob S-1-5-21-674899381-4069889467-2080702030-1002
```

- the SID is broken into this pattern:`(SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)`

| **Number**                      | **Meaning**          | **Description**                                                                                                                                                                                    |
| ------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S                               | SID                  | Identifies the string as a SID.                                                                                                                                                                    |
| 1                               | Revision Level       | To date, this has never changed and has always been `1`.                                                                                                                                           |
| 5                               | Identifier-authority | A 48-bit string that identifies the authority (the computer or network) that created the SID.                                                                                                      |
| 21                              | Subauthority1        | This is a variable number that identifies the user's relation or group described by the SID to the authority that created it. It tells us in what order this authority created the user's account. |
| 674899381-4069889467-2080702030 | Subauthority2        | Tells us which computer (or domain) created the number                                                                                                                                             |
| 1002                            | Subauthority3        | The RID that distinguishes one account from another. Tells us whether this user is a normal user, a guest, an administrator, or part of some other group                                           |

## Security Accounts Manager (SAM) and Access Control Entries (ACE)

- SAM grants access to a network to execute specific processes
- the access rights are managed by ACE in ACL(Access Control Lists)
- the ACL contain info on which users or groups have access to certain files or processes
- for every thread and process the LSA (local security authority) needs to validate the token associated with it

## User Account Control (UAC)

- pops up when we try to run something as administrator
- prevents malware or system changes from running without our knowledge

![[How-to-Enable-or-Disable-User-Account-Control-in-Windows-11.webp]]

## Registry

- it basically stores low-level Windows settings in a db

![[regedit.webp]]

- the tree structure consists of root keys (main folders) and subkey (subfolders), each subkey with it's value
- there are 11 types of values that can be entered:

|**Value**|**Type**|
|---|---|
|REG_BINARY|Binary data in any form.|
|REG_DWORD|A 32-bit number.|
|REG_DWORD_LITTLE_ENDIAN|A 32-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_DWORD in the Windows header files.|
|REG_DWORD_BIG_ENDIAN|A 32-bit number in big-endian format. Some UNIX systems support big-endian architectures.|
|REG_EXPAND_SZ|A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%"). It will be a Unicode or ANSI string depending on whether you use the Unicode or ANSI functions. To expand the environment variable references, use the [**ExpandEnvironmentStrings**](https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsa) function.|
|REG_LINK|A null-terminated Unicode string containing the target path of a symbolic link created by calling the [**RegCreateKeyEx**](https://docs.microsoft.com/en-us/windows/desktop/api/Winreg/nf-winreg-regcreatekeyexa) function with REG_OPTION_CREATE_LINK.|
|REG_MULTI_SZ|A sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: _String1_\0_String2_\0_String3_\0_LastString_\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string.|
|REG_NONE|No defined value type.|
|REG_QWORD|A 64-bit number.|
|REG_QWORD_LITTLE_ENDIAN|A 64-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_QWORD in the Windows header files.|
|REG_SZ|A null-terminated string. This will be either a Unicode or an ANSI string, depending on whether you use the Unicode or ANSI functions.|
Note: All ==root keys== start with ==HKEY==.

example of apps running while logged in as a certain user:
```powershell-session
PS C:\Users\Tony> reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    Steam    REG_SZ    "C:\Program Files (x86)\Steam\steam.exe" -silent
    Discord    REG_SZ    "C:\Users\Tony\AppData\Local\Discord\Update.exe" --processStart Discord.exe
    MicrosoftEdgeAutoLaunch_DB1D9E99788CE78B8AE8540767A26685    REG_SZ    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start
```

## Application Whitelisting and Blacklisting

- whitelisting means that all apps are deemed bad except those specifically allowed
- blacklisting prohibits all apps that are in the blacklist and are deemed malicious
- ==AppLocker== is Microsoft's solution for ==Whitelisting==




# Useful Links:

https://ss64.com/ps/get-wmiobject.html // cmdlets
https://adamtheautomator.com/get-wmiobject/ // cmdlets
https://ss64.com/nt/icacls.html // icacls
https://www.cloudflare.com/learning/access-management/principle-of-least-privilege/ // concept of least privilege access
https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf // windows command reference
https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic // wmi cli