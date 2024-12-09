
12-07-2024 14:45 pm

Tags: [[Networking]] 

References: https://academy.hackthebox.com/module/34/section/297


# Introduction To Networking

## Overview

==Subnetting== = the process of dividing a network in two or more parts

==Subnet Mask== = number of bits used for a certain portion of the network in order to mask the ip address

==Gateway== = access point to another network (ex.:192.168.1.1)

==CIDR (classless inter-domain routing /24 or /25 or other)== = indicates the subnet mask, meaning the number of bits used for that portion of the network

Most networks use ==/24== subnet which allows computers with the first three octets to talk to each other (192.168.1.xxx). The subnet mask for ==/24== is ==255.255.255.0== . The first 24 bits are used and the remaining 8 are for ip addresses (32 bits in total, 2^8 => 254 usable ip addresses on that subnet because 2 of them are used by default).

For a ==/25== subnet we have 2^7 usable ip addresses (128-2 by default). The subnet mask is ==255.255.255.128== .

For example, for a /28 bit subnet, the last digits in binary for the mask would be 11110000 which is 240 in decimal => 255.255.255.240 in decimal.

# Networking Structure
## Network Types

| **Network Type**                   | **Definition**                               |
| ---------------------------------- | -------------------------------------------- |
| Wide Area Network (WAN)            | Internet                                     |
| Local Area Network (LAN)           | Internal Networks (Ex: Home or Office)       |
| Wireless Local Area Network (WLAN) | Internal Networks accessible over Wi-Fi      |
| Virtual Private Network (VPN)      | Connects multiple network sites to one `LAN` |
==Note== : WAN is just a bunch of LANs put together.

==Book Terms== :

| **Network Type**                      | **Definition**                   |
| ------------------------------------- | -------------------------------- |
| Global Area Network (GAN)             | Global network (the Internet)    |
| Metropolitan Area Network (MAN)       | Regional network (multiple LANs) |
| Wireless Personal Area Network (WPAN) | Personal network (Bluetooth)     |

## Network Topologies

= logical and physical connection of a network

==Types of Connections== :

| **Wired connections** | **Wireless connections** |
| --------------------- | ------------------------ |
| Coaxial cabling       | Wi-Fi                    |
| Glass fiber cabling   | Cellular                 |
| Twisted-pair cabling  | Satellite                |
| and others            | and others               |
==Network Interface Controller(NIC)== :

The transmission medium.

|              |          |           |          |
| ------------ | -------- | --------- | -------- |
| Repeaters    | Hubs     | Bridges   | Switches |
| Router/Modem | Gateways | Firewalls |          |

## Proxies

= middleman between computer and the internet

==Types== :
- `Dedicated Proxy` / `Forward Proxy`
- `Reverse Proxy`
- `Transparent Proxy`

# Networking Workflow

## Networking models

![[Pasted image 20240716140634.png]]

|**Layer**|**Function**|
|---|---|
|`7.Application`|Among other things, this layer controls the input and output of data and provides the application functions.|
|`6.Presentation`|The presentation layer's task is to transfer the system-dependent presentation of data into a form independent of the application.|
|`5.Session`|The session layer controls the logical connection between two systems and prevents, for example, connection breakdowns or other problems.|
|`4.Transport`|Layer 4 is used for end-to-end control of the transferred data. The Transport Layer can detect and avoid congestion situations and segment data streams.|
|`3.Network`|On the networking layer, connections are established in circuit-switched networks, and data packets are forwarded in packet-switched networks. Data is transmitted over the entire network from the sender to the receiver.|
|`2.Data Link`|The central task of layer 2 is to enable reliable and error-free transmissions on the respective medium. For this purpose, the bitstreams from layer 1 are divided into blocks or frames.|
|`1.Physical`|The transmission techniques used are, for example, electrical signals, optical signals, or electromagnetic waves. Through layer 1, the transmission takes place on wired or wireless transmission lines.|
![[Pasted image 20240716145258.png]]
![[Pasted image 20240716145708.png]]

# Addressing

## Network Layer

= responsible for ip addresses

## IPv4 Addresses

==MAC== = Media Access Control

==IPv4 STRUCTURE== :

= unique address for a device; can be PUBLIC(on WAN) or PRIVATE(on LAN)

It CAN look like this:

| **Notation** | **Presentation**                        |
| ------------ | --------------------------------------- |
| Binary       | 0111 1111.0000 0000.0000 0000.0000 0001 |
| Decimal      | 127.0.0.1                               |

## Subnetting

= network segmentation

ex.:
- IPv4 Address: `192.168.12.160`
- Subnet Mask: `255.255.255.192`
- CIDR: `192.168.12.160/26`

Subnets can only be divided bases on the binary system:

|**Exponent**|**Value**|
|---|---|
|2`^0`|= 1|
|2`^1`|= 2|
|2`^2`|= 4|
|2`^3`|= 8|
|2`^4`|= 16|
|2`^5`|= 32|
|2`^6`|= 64|
|2`^7`|= 128|
|2`^8`|= 256|
In order to subnet you need to add 2 additional bits to the mask (ex.: from /27 to /29)

2^(32-/x) to determine how many addresses.

2^(32-29) = 2^3 = 8 addresses

## MAC Addresses

= physical address for a network interface

Standards:
- Ethernet (IEEE 802.3)
- Bluetooth (IEEE 802.15)
- WLAN (IEEE 802.11)

MAC address example:
- `DE:AD:BE:EF:13:37`
- `DE-AD-BE-EF-13-37`
- `DEAD.BEEF.1337`

First half is the ==Organization Unique Identifier (OUI)== and the second half is the ==Network Interface Controller (NIC)==.

Note: In the first octet, the last bit determines if it's a ==Unicast (0)== or ==Multicast (1)==. That shows if the packets are sent to one host (unicast) or multiple (multicast).

==ARP (Address Resolution Protocol) = used to map the IP to it's corresponding MAC address on LAN==

	-ARP Request (when the SENDER does not know the MAC of an IP) -> MAC on LAN
	-MAC on LAN -> ARP Response/Reply
	-ARP Request SENDER stores the mapping in an ARP Cache
	
MAC Addresses

```shell-session
1   0.000000 10.129.12.100 -> 10.129.12.255 ARP 60  Who has 10.129.12.101?  Tell 10.129.12.100
2   0.000015 10.129.12.101 -> 10.129.12.100 ARP 60  10.129.12.101 is at AA:AA:AA:AA:AA:AA

3   0.000030 10.129.12.102 -> 10.129.12.255 ARP 60  Who has 10.129.12.103?  Tell 10.129.12.102
4   0.000045 10.129.12.103 -> 10.129.12.102 ARP 60  10.129.12.103 is at BB:BB:BB:BB:BB:BB
```

==DHCP (Dynamic Host Configuration Protocol) = a protocol that assigns IP addresses and other configurations to devices on a LAN==

	-Device connects and sends DHCP Discover to the DHCP Server on LAN
	-DHCP Server sends back a DHCP Offer with available IP and other configurations
	-Device sends back a DHCP Request
	-DHCP Server sends to the device a DHCP Acknowledge

Note: The second last bit in the first octet identifies whether it is a ==global OUI==, defined by the IEEE, or a ==locally administrated== MAC address.

## IPv6 Addresses

An IPv6 (128 bits) address consists of two parts:

- `Network Prefix` (network part)
- `Interface Identifier` also called `Suffix` (host part)

# Networking Key Terminology

|**Protocol**|**Acronym**|**Description**|
|---|---|---|
|Wired Equivalent Privacy|`WEP`|WEP is a type of security protocol that was commonly used to secure wireless networks.|
|Secure Shell|`SSH`|A secure network protocol used to log into and execute commands on a remote system|
|File Transfer Protocol|`FTP`|A network protocol used to transfer files from one system to another|
|Simple Mail Transfer Protocol|`SMTP`|A protocol used to send and receive emails|
|Hypertext Transfer Protocol|`HTTP`|A client-server protocol used to send and receive data over the internet|
|Server Message Block|`SMB`|A protocol used to share files, printers, and other resources in a network|
|Network File System|`NFS`|A protocol used to access files over a network|
|Simple Network Management Protocol|`SNMP`|A protocol used to manage network devices|
|Wi-Fi Protected Access|`WPA`|WPA is a wireless security protocol that uses a password to protect wireless networks from unauthorized access.|
|Temporal Key Integrity Protocol|`TKIP`|TKIP is also a security protocol used in wireless networks but less secure.|
|Network Time Protocol|`NTP`|It is used to synchronize the timing of computers on a network.|
|Virtual Local Area Network|`VLAN`|It is a way to segment a network into multiple logical networks.|
|VLAN Trunking Protocol|`VTP`|VTP is a Layer 2 protocol that is used to establish and maintain a virtual LAN (VLAN) spanning multiple switches.|
|Routing Information Protocol|`RIP`|RIP is a distance-vector routing protocol used in local area networks (LANs) and wide area networks (WANs).|
|Open Shortest Path First|`OSPF`|It is an interior gateway protocol (IGP) for routing traffic within a single Autonomous System (AS) in an Internet Protocol (IP) network.|
|Interior Gateway Routing Protocol|`IGRP`|IGRP is a Cisco proprietary interior gateway protocol designed for routing within autonomous systems.|
|Enhanced Interior Gateway Routing Protocol|`EIGRP`|It is an advanced distance-vector routing protocol that is used to route IP traffic within a network.|
|Pretty Good Privacy|`PGP`|PGP is an encryption program that is used to secure emails, files, and other types of data.|
|Network News Transfer Protocol|`NNTP`|NNTP is a protocol used for distributing and retrieving messages in newsgroups across the internet.|
|Cisco Discovery Protocol|`CDP`|It is a proprietary protocol developed by Cisco Systems that allows network administrators to discover and manage Cisco devices connected to the network.|
|Hot Standby Router Protocol|`HSRP`|HSRP is a protocol used in Cisco routers to provide redundancy in the event of a router or other network device failure.|
|Virtual Router Redundancy Protocol|`VRRP`|It is a protocol used to provide automatic assignment of available Internet Protocol (IP) routers to participating hosts.|
|Spanning Tree Protocol|`STP`|STP is a network protocol used to ensure a loop-free topology in Layer 2 Ethernet networks.|
|Terminal Access Controller Access-Control System|`TACACS`|TACACS is a protocol that provides centralized authentication, authorization, and accounting for network access.|
|Session Initiation Protocol|`SIP`|It is a signaling protocol used for establishing and terminating real-time voice, video and multimedia sessions over an IP network.|
|Voice Over IP|`VOIP`|VOIP is a technology that allows for telephone calls to be made over the internet.|
|Extensible Authentication Protocol|`EAP`|EAP is a framework for authentication that supports multiple authentication methods, such as passwords, digital certificates, one-time passwords, and public-key authentication.|
|Lightweight Extensible Authentication Protocol|`LEAP`|LEAP is a proprietary wireless authentication protocol developed by Cisco Systems. It is based on the Extensible Authentication Protocol (EAP) used in the Point-to-Point Protocol (PPP).|
|Protected Extensible Authentication Protocol|`PEAP`|PEAP is a security protocol that provides an encrypted tunnel for wireless networks and other types of networks.|
|Systems Management Server|`SMS`|SMS is a systems management solution that helps organizations manage their networks, systems, and mobile devices.|
|Microsoft Baseline Security Analyzer|`MBSA`|It is a free security tool from Microsoft that is used to detect potential security vulnerabilities in Windows computers, networks, and systems.|
|Supervisory Control and Data Acquisition|`SCADA`|It is a type of industrial control system that is used to monitor and control industrial processes, such as those in manufacturing, power generation, and water and waste treatment.|
|Virtual Private Network|`VPN`|VPN is a technology that allows users to create a secure, encrypted connection to another network over the internet.|
|Internet Protocol Security|`IPsec`|IPsec is a protocol used to provide secure, encrypted communication over a network. It is commonly used in VPNs, or Virtual Private Networks, to create a secure tunnel between two devices.|
|Point-to-Point Tunneling Protocol|`PPTP`|It is a protocol used to create a secure, encrypted tunnel for remote access.|
|Network Address Translation|`NAT`|NAT is a technology that allows multiple devices on a private network to connect to the internet using a single public IP address. NAT works by translating the private IP addresses of devices on the network into a single public IP address, which is then used to connect to the internet.|
|Carriage Return Line Feed|`CRLF`|Combines two control characters to indicate the end of a line and a start of a new one for certain text file formats.|
|Asynchronous JavaScript and XML|`AJAX`|Web development technique that allows creating dynamic web pages using JavaScript and XML/JSON.|
|Internet Server Application Programming Interface|`ISAPI`|Allows to create performance-oriented web extensions for web servers using a set of APIs.|
|Uniform Resource Identifier|`URI`|It is a syntax used to identify a resource on the Internet.|
|Uniform Resource Locator|`URL`|Subset of URI that identifies a web page or another resource on the Internet, including the protocol and the domain name.|
|Internet Key Exchange|`IKE`|IKE is a protocol used to set up a secure connection between two computers. It is used in virtual private networks (VPNs) to provide authentication and encryption for data transmission, protecting the data from outside eavesdropping and tampering.|
|Generic Routing Encapsulation|`GRE`|This protocol is used to encapsulate the data being transmitted within the VPN tunnel.|
|Remote Shell|`RSH`|It is a program under Unix that allows executing commands and programs on a remote computer.|

## Common Protocols

- TCP (Transmission Control Protocol)
- UDP (User Datagram Protocol)
- ICMP (Internet Control Message Protocol)
- VoIP (Voice Over IP)

==Common TCP Ports==:

|**Protocol**|**Acronym**|**Port**|**Description**|
|---|---|---|---|
|Telnet|`Telnet`|`23`|Remote login service|
|Secure Shell|`SSH`|`22`|Secure remote login service|
|Simple Network Management Protocol|`SNMP`|`161-162`|Manage network devices|
|Hyper Text Transfer Protocol|`HTTP`|`80`|Used to transfer webpages|
|Hyper Text Transfer Protocol Secure|`HTTPS`|`443`|Used to transfer secure webpages|
|Domain Name System|`DNS`|`53`|Lookup domain names|
|File Transfer Protocol|`FTP`|`20-21`|Used to transfer files|
|Trivial File Transfer Protocol|`TFTP`|`69`|Used to transfer files|
|Network Time Protocol|`NTP`|`123`|Synchronize computer clocks|
|Simple Mail Transfer Protocol|`SMTP`|`25`|Used for email transfer|
|Post Office Protocol|`POP3`|`110`|Used to retrieve emails|
|Internet Message Access Protocol|`IMAP`|`143`|Used to access emails|
|Server Message Block|`SMB`|`445`|Used to transfer files|
|Network File System|`NFS`|`111`, `2049`|Used to mount remote systems|
|Bootstrap Protocol|`BOOTP`|`67`, `68`|Used to bootstrap computers|
|Kerberos|`Kerberos`|`88`|Used for authentication and authorization|
|Lightweight Directory Access Protocol|`LDAP`|`389`|Used for directory services|
|Remote Authentication Dial-In User Service|`RADIUS`|`1812`, `1813`|Used for authentication and authorization|
|Dynamic Host Configuration Protocol|`DHCP`|`67`, `68`|Used to configure IP addresses|
|Remote Desktop Protocol|`RDP`|`3389`|Used for remote desktop access|
|Network News Transfer Protocol|`NNTP`|`119`|Used to access newsgroups|
|Remote Procedure Call|`RPC`|`135`, `137-139`|Used to call remote procedures|
|Identification Protocol|`Ident`|`113`|Used to identify user processes|
|Internet Control Message Protocol|`ICMP`|`0-255`|Used to troubleshoot network issues|
|Internet Group Management Protocol|`IGMP`|`0-255`|Used for multicasting|
|Oracle DB (Default/Alternative) Listener|`oracle-tns`|`1521`/`1526`|The Oracle database default/alternative listener is a service that runs on the database host and receives requests from Oracle clients.|
|Ingres Lock|`ingreslock`|`1524`|Ingres database is commonly used for large commercial applications and as a backdoor that can execute commands remotely via RPC.|
|Squid Web Proxy|`http-proxy`|`3128`|Squid web proxy is a caching and forwarding HTTP web proxy used to speed up a web server by caching repeated requests.|
|Secure Copy Protocol|`SCP`|`22`|Securely copy files between systems|
|Session Initiation Protocol|`SIP`|`5060`|Used for VoIP sessions|
|Simple Object Access Protocol|`SOAP`|`80`, `443`|Used for web services|
|Secure Socket Layer|`SSL`|`443`|Securely transfer files|
|TCP Wrappers|`TCPW`|`113`|Used for access control|
|Internet Security Association and Key Management Protocol|`ISAKMP`|`500`|Used for VPN connections|
|Microsoft SQL Server|`ms-sql-s`|`1433`|Used for client connections to the Microsoft SQL Server.|
|Kerberized Internet Negotiation of Keys|`KINK`|`892`|Used for authentication and authorization|
|Open Shortest Path First|`OSPF`|`89`|Used for routing|
|Point-to-Point Tunneling Protocol|`PPTP`|`1723`|Is used to create VPNs|
|Remote Execution|`REXEC`|`512`|This protocol is used to execute commands on remote computers and send the output of commands back to the local computer.|
|Remote Login|`RLOGIN`|`513`|This protocol starts an interactive shell session on a remote computer.|
|X Window System|`X11`|`6000`|It is a computer software system and network protocol that provides a graphical user interface (GUI) for networked computers.|
|Relational Database Management System|`DB2`|`50000`|RDBMS is designed to store, retrieve and manage data in a structured format for enterprise applications such as financial systems, customer relationship management (CRM) systems.

==Common UDP Ports==:

|**Protocol**|**Acronym**|**Port**|**Description**|
|---|---|---|---|
|Domain Name System|`DNS`|`53`|It is a protocol to resolve domain names to IP addresses.|
|Trivial File Transfer Protocol|`TFTP`|`69`|It is used to transfer files between systems.|
|Network Time Protocol|`NTP`|`123`|It synchronizes computer clocks in a network.|
|Simple Network Management Protocol|`SNMP`|`161`|It monitors and manages network devices remotely.|
|Routing Information Protocol|`RIP`|`520`|It is used to exchange routing information between routers.|
|Internet Key Exchange|`IKE`|`500`|Internet Key Exchange|
|Bootstrap Protocol|`BOOTP`|`68`|It is used to bootstrap hosts in a network.|
|Dynamic Host Configuration Protocol|`DHCP`|`67`|It is used to assign IP addresses to devices in a network dynamically.|
|Telnet|`TELNET`|`23`|It is a text-based remote access communication protocol.|
|MySQL|`MySQL`|`3306`|It is an open-source database management system.|
|Terminal Server|`TS`|`3389`|It is a remote access protocol used for Microsoft Windows Terminal Services by default.|
|NetBIOS Name|`netbios-ns`|`137`|It is used in Windows operating systems to resolve NetBIOS names to IP addresses on a LAN.|
|Microsoft SQL Server|`ms-sql-m`|`1434`|Used for the Microsoft SQL Server Browser service.|
|Universal Plug and Play|`UPnP`|`1900`|It is a protocol for devices to discover each other on the network and communicate.|
|PostgreSQL|`PGSQL`|`5432`|It is an object-relational database management system.|
|Virtual Network Computing|`VNC`|`5900`|It is a graphical desktop sharing system.|
|X Window System|`X11`|`6000-6063`|It is a computer software system and network protocol that provides GUI on Unix-like systems.|
|Syslog|`SYSLOG`|`514`|It is a standard protocol to collect and store log messages on a computer system.|
|Internet Relay Chat|`IRC`|`194`|It is a real-time Internet text messaging (chat) or synchronous communication protocol.|
|OpenPGP|`OpenPGP`|`11371`|It is a protocol for encrypting and signing data and communications.|
|Internet Protocol Security|`IPsec`|`500`|IPsec is also a protocol that provides secure, encrypted communication. It is commonly used in VPNs to create a secure tunnel between two devices.|
|Internet Key Exchange|`IKE`|`11371`|It is a protocol for encrypting and signing data and communications.|
|X Display Manager Control Protocol|`XDMCP`|`177`|XDMCP is a network protocol that allows a user to remotely log in to a computer running the X11.|

# Wireless Networks

= data is converted into RF (radio frequency)

Note: Communication occurs over 2.5 GHz or 5 GHz bands.

==WAP (Wireless Access Point) = a device that allows other devices to transmit data over Internet==

## WiFi Connection

==SSID (Service Set IDentifier) = WiFi name==

Note: IEEE 802.11 protocol is used to make the connection between devices and WiFi

The device sends a connection request with the following to the WiFi:

| **Name**                       | **Description**                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------- |
| `MAC address`                  | A unique identifier for the device's wireless adapter.                                       |
| `SSID`                         | The network name, also known as the `Service Set Identifier` of the WiFi network.            |
| `Supported data rates`         | A list of the data rates the device can communicate.                                         |
| `Supported channels`           | A list of the `channels` (frequencies) on which the device can communicate.                  |
| `Supported security protocols` | A list of the security protocols that the device is capable of using, such as `WPA2`/`WPA3`. |

Security features: Encryption, Firewall, Access Control, etc.

==Common ENCRYPTION Algorithms==: WEP, WPA2 and WPA3

### Authentication Protocols

	-LEAP = Lightweight Extensible Authentification Protocol
	-PEAP = Protected Extensible Authentification Protocol

Note: They are used in combination with WPA.

## Disassociation (Deauthentification) Attack

= the attacker sends deauthentification frames to the WAP and keeps disconnecting the user

Note: used in combination with evil twin

# Virtual Private Networks

= allows a secure and encrypted connection to a network

Note: It creates a ==tunneling protocol== (TCP/1723 point-to-point tunneling protocol).

Key VPN components:

|**Requirement**|**Description**|
|---|---|
|`VPN Client`|This is installed on the remote device and is used to establish and maintain a VPN connection with the VPN server. For example, this could be an OpenVPN client.|
|`VPN Server`|This is a computer or network device responsible for accepting VPN connections from VPN clients and routing traffic between the VPN clients and the private network.|
|`Encryption`|VPN connections are encrypted using a variety of encryption algorithms and protocols, such as AES and IPsec, to secure the connection and protect the transmitted data.|
|`Authentication`|The VPN server and client must authenticate each other using a shared secret, certificate, or another authentication method to establish a secure connection.|

## IPsec

= Internet Protocol Security; provides security and encryption for internet communications

Note: It adds an ==Authentication Header (AH)== protocol that verifies the integrity and authenticity of the packet.

Note: It also adds an ==Encapsulating Security Payload (ESP)== protocol for extra encryption.

# Connection Establishment

## Key Exchange Mechanisms

= methods used in order to exchange cryptographic keys

Diffie-Hellman -> vulnerable to MITM (mitm can generate and pass to the users a key)

RSA -> protects data in traffic through SSL and TLS protocols

ECDH -> past communications cannot be revealed even if the keys are compromised

ECDSA -> can generate digital signatures

|**Algorithm**|**Acronym**|**Security**|
|---|---|---|
|`Diffie-Hellman`|`DH`|Relatively secure and computationally efficient|
|`Rivest–Shamir–Adleman`|`RSA`|Widely used and considered secure, but computationally intensive|
|`Elliptic Curve Diffie-Hellman`|`ECDH`|Provides enhanced security compared to traditional Diffie-Hellman|
|`Elliptic Curve Digital Signature Algorithm`|`ECDSA`|Provides enhanced security and efficiency for digital signature generation|

==IKE (Internet Key Exchange)== = protocol that allows secure key exchange and session communication over the internet; it's a key component to many VPNs

## Authentication Protocols

|**Protocol**|**Description**|
|---|---|
|`Kerberos`|Key Distribution Center (KDC) based authentication protocol that uses tickets in domain environments.|
|`SRP`|This is a password-based authentication protocol that uses cryptography to protect against eavesdropping and man-in-the-middle attacks.|
|`SSL`|A cryptographic protocol used for secure communication over a computer network.|
|`TLS`|TLS is a cryptographic protocol that provides communication security over the internet. It is the successor to SSL.|
|`OAuth`|An open standard for authorization that allows users to grant third-party access to their web resources without sharing their passwords.|
|`OpenID`|OpenID is a decentralized authentication protocol that allows users to use a single identity to sign in to multiple websites.|
|`SAML`|Security Assertion Markup Language is an XML-based standard for securely exchanging authentication and authorization data between parties.|
|`2FA`|An authentication method that uses a combination of two different factors to verify a user's identity.|
|`FIDO`|The Fast IDentity Online Alliance is a consortium of companies working to develop open standards for strong authentication.|
|`PKI`|PKI is a system for securely exchanging information based on the use of public and private keys for encryption and digital signatures.|
|`SSO`|An authentication method that allows a user to use a single set of credentials to access multiple applications.|
|`MFA`|MFA is an authentication method that uses multiple factors, such as something the user knows (a password), something the user has (a phone), or something the user is (biometric data), to verify their identity.|
|`PAP`|A simple authentication protocol that sends a user's password in clear text over the network.|
|`CHAP`|An authentication protocol that uses a three-way handshake to verify a user's identity.|
|`EAP`|A framework for supporting multiple authentication methods, allowing for the use of various technologies to verify a user's identity.|
|`SSH`|This is a network protocol for secure communication between a client and a server. We can use it for remote command-line access and remote command execution, as well as for secure file transfer. SSH uses encryption to protect against eavesdropping and other attacks and can also be used for authentication.|
|`HTTPS`|This is a secure version of the HTTP protocol used for communication on the internet. HTTPS uses SSL/TLS to encrypt communication and provide authentication, ensuring that third parties cannot intercept and read the transmitted data. It is widely used for secure communication over the internet, particularly for web browsing.|
|`LEAP`|LEAP is a wireless authentication protocol developed by Cisco. It uses EAP to provide mutual authentication between a wireless client and a server and uses the RC4 encryption algorithm to encrypt communication between the two. Unfortunately, LEAP is vulnerable to dictionary attacks and other security vulnerabilities and has been largely replaced by more secure protocols such as EAP-TLS and PEAP.|
|`PEAP`|PEAP on the other hand is a secure tunneling protocol used for wireless and wired networks. It is based on EAP and uses TLS to encrypt communication between a client and a server. PEAP uses a server-side certificate to authenticate the server and can also be used to authenticate the client using various methods, such as passwords, certificates, or biometric data. PEAP is widely used in enterprise networks for secure authentication.|

## TCP and UDP Connections

TCP (segments) -> usually transmits important data such as web pages or emails

UDP (datagrams = small data packets) -> usually transmits real-time data such as streaming or online gaming

Payload = the actual data that is being transmitted

# Cryptography

= encryption is used in order to safely transmit data over the internet

Digital keys -> symmetric/asymmetric

==Symmetric Encryption== (secret key encryption) = uses the same key to encrypt and decrypt data (AES and DES = encryption standards)

==Asymmetric Encryption== (public key encryption) = uses two different keys, public and private (RSA, PGP, ECC = encryption methods)
examples: E-Signatures, SSH, SSL/TLS, VPNs, Cloud, PKI, etc.

## Cypher Modes

= how a block cipher algorithm encrypts plaintext messages

|**Cipher Mode**|**Description**|
|---|---|
|[Electronic Code Book](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) (`ECB`) mode|ECB mode is generally not recommended for use due to its susceptibility to certain types of attacks. Furthermore, it does not hide data patterns efficiently. As a result, statistical analysis can reveal elements of clear-text messages, for example, in web applications.|
|[Cipher Block Chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC) (`CBC`) mode|CBC mode is generally used to encrypt messages like disk encryption and e-mail communication. This is the default mode for AES and is also used in software like TrueCrypt, VeraCrypt, TLS, and SSL.|
|[Cipher Feedback](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)) (`CFB`) mode|CFB mode is well suited for real-time encryption of a data stream, e.g., network communication encryption or encryption/decryption of files in transit like Public-Key Cryptography Standards (PKCS) and Microsoft's BitLocker.|
|[Output Feedback](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#OFB) (`OFB`) mode|OFB mode is also used to encrypt a data stream, e.g., to encrypt real-time communication. However, this mode is considered better for the data stream because of how the key stream is generated. We can find this mode in PKCS but also in the SSH protocol.|
|[Counter](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR) (`CTR`) mode|CTR mode encrypts real-time data streams AES uses, e.g., network communication, disk encryption, and other real-time scenarios where data is processed. An example of this would be IPsec or Microsoft's BitLocker.|
|[Galois/Counter](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (`GCM`) mode|GCM is used in cases where confidentiality and integrity need to be protected together, such as wireless communications, VPNs, and other secure communication protocols.|





# Useful Links:

https://owasp.org/www-project-modsecurity-core-rule-set/
https://en.wikipedia.org/wiki/ARP_spoofing
https://www.imperva.com/learn/performance/time-to-live-ttl/
https://www.makeuseof.com/what-are-disassociation-attacks/