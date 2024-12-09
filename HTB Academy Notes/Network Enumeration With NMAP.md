
05-07-2024 13:05 pm

Tags: [[NMAP]] [[Recon]] [[Firewall and IDS IPS Evasion]] [[Enumeration]] [[Networking]] 

References:

https://academy.hackthebox.com/module/19/section/99
https://nmap.org/


# Network Enumeration With NMAP


==Enumeration== is the first part of an attack where recon takes part in order to see what can be attacked. THE MORE INFORMATION THE BETTER!!

==NMAP== = Network MAPper (C, C++, Python and Lua)

==Use Cases== :
- Pentesting
- Identify firewall/IDS settings
- Vulnerability assessment
- Find Open ports
- NETWORK MAPPING


==General Techniques== : 
- Host discovery
- Port scanning
- OS detection
- Services discovery and enumeration
- Scriptable interactions in Lua

==Basic Syntax== :
```
nmap <target ip> <port/s> <options> <scan technique>
```

==SCAN TECHNIQUES== :
```
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
  -sV performs service scans
```

==TCP(transmission control protocol) HANDSHAKE==

![[Pasted image 20240711213138.png]]

RST => CLOSED

==OPTIONS== :
```
-sn disables port scanning
-oA <any_name> stores the results in <any_name.lst> and other formats
-PE for ICMP echo requests
--packet-trace for packet tracing
--reason for aditional explainations or -vv
--disable-arp-ping for disabling arp pings
-p <port/ports> scans specified port/ports
-p- scans all 65535 ports
-F scans top 100 most common ports
-n disables DNS resolution(process of converting domain names to ips)
-Pn disable ICMP echo requests
--stats-every=5s shows results every 5 seconds

```

==Saving Results== :
```
- Normal output (`-oN`) with the `.nmap` file extension
- Grepable output (`-oG`) with the `.gnmap` file extension
- XML output (`-oX`) with the `.xml` file extension (xsltproc <name>.xml -o <name>.html)
```

==Nmap Scripting== :

| **Category** | **Description**                                                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`       | Determination of authentication credentials.                                                                                            |
| `broadcast`  | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brute`      | Executes scripts that try to log in to the respective service by brute-forcing with credentials.                                        |
| `default`    | Default scripts executed by using the `-sC` option.                                                                                     |
| `discovery`  | Evaluation of accessible services.                                                                                                      |
| `dos`        | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.              |
| `exploit`    | This category of scripts tries to exploit known vulnerabilities for the scanned port.                                                   |
| `external`   | Scripts that use external services for further processing.                                                                              |
| `fuzzer`     | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.     |
| `intrusive`  | Intrusive scripts that could negatively affect the target system.                                                                       |
| `malware`    | Checks if some malware infects the target system.                                                                                       |
| `safe`       | Defensive scripts that do not perform intrusive and destructive access.                                                                 |
| `version`    | Extension for service detection.                                                                                                        |
| `vuln`       | Identification of specific vulnerabilities.                                                                                             |
==Syntax==:
```
sudo nmap \<ip> --script \<category>
```

==Note== : Nmap has a very useful script for grabbing banners (--script banner)

==Performance== :

Timeouts (RTT - round trip timeouts) = the time it takes for the port to respond

```
--initial-rtt-timeout 50ms
--max-rtt-timeout 100ms
--max-retries <number> to set the retry rate of the sent packets (default=10)
--min-rate <number of packets> sets the minimum rate of packets/second
```

Timing of scans(aggressiveness):
- `-T 0` / `-T paranoid`
- `-T 1` / `-T sneaky`
- `-T 2` / `-T polite`
- `-T 3` / `-T normal`
- `-T 4` / `-T aggressive`
- `-T 5` / `-T insane`

==Firewall and IDS/IPS Evasion== : decoys, packet fragmentation, etc.
	- the firewall sees the incoming connections
	- IDS detects network traffic
	- IPS takes measures and prevents certain connection attempts

```
-sA TCP ACK is harder to detect because it only sends ACK packages; the firewall does NOT know if the connection was made from inside or outside
```

==Note== : If no packets are RCVD then they were DROPPED (firewall)

==DECOYS== :
```
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

-D for decoys
RND:5 generates 5 decoys
```

==SCAN by using different IP== :
```
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

-S specify source IP
-e specify interface
-O os detection
```

==DNS Proxying== (port 53) :
```
--dns-server <ns> to specify the dns server (usually company/host domain)
--source-port <port(53)> to specify source port

EXAMPLE: sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```
These are both options for the scans in order to bypass the firewall through the DMZ(demilitarized zone)


# Useful Links:

https://nmap.org/book/host-discovery-strategies.html
https://nmap.org/book/scan-methods-connect-scan.html
https://www.geeksforgeeks.org/tcp-3-way-handshake-process/