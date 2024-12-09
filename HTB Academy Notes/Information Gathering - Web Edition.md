
20-09-2024 18:32 pm

Tags: [[WHOIS]] [[DNS (53)|DNS (53)]] [[Fingerprinting]] [[Crawling]] [[Search Engine Discovery]] [[Web Archives]] [[Recon|Recon]] 

References: https://academy.hackthebox.com/module/144/section/1247


# Information Gathering - Web Edition

- it involves collecting information about a target's website or web application
![[PT-process.webp]]
The primary goals of web reconnaissance include:
- **Identifying Assets**: Uncovering all publicly accessible components of the target, such as web pages, subdomains, IP addresses, and technologies used. This step provides a comprehensive overview of the target's online presence.
- **Discovering Hidden Information**: Locating sensitive information that might be inadvertently exposed, including backup files, configuration files, or internal documentation. These findings can reveal valuable insights and potential entry points for attacks.
- **Analyzing the Attack Surface**: Examining the target's attack surface to identify potential vulnerabilities and weaknesses. This involves assessing the technologies used, configurations, and possible entry points for exploitation.
- **Gathering Intelligence**: Collecting information that can be leveraged for further exploitation or social engineering attacks. This includes identifying key personnel, email addresses, or patterns of behaviour that could be exploited.
## Active Reconnaissance
- direct interaction with the target system

| Technique                  | Description                                                                                   | Example                                                                                                                               | Tools                                                      | Risk of Detection                                                                                                  |
| -------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Port Scanning**          | Identifying open ports and services running on the target.                                    | Using Nmap to scan a web server for open ports like 80 (HTTP) and 443 (HTTPS).                                                        | Nmap, Masscan, Unicornscan                                 | High: Direct interaction with the target can trigger intrusion detection systems (IDS) and firewalls.              |
| **Vulnerability Scanning** | Probing the target for known vulnerabilities, such as outdated software or misconfigurations. | Running Nessus against a web application to check for SQL injection flaws or cross-site scripting (XSS) vulnerabilities.              | Nessus, OpenVAS, Nikto                                     | High: Vulnerability scanners send exploit payloads that security solutions can detect.                             |
| **Network Mapping**        | Mapping the target's network topology, including connected devices and their relationships.   | Using traceroute to determine the path packets take to reach the target server, revealing potential network hops and infrastructure.  | Traceroute, Nmap                                           | Medium to High: Excessive or unusual network traffic can raise suspicion.                                          |
| **Banner Grabbing**        | Retrieving information from banners displayed by services running on the target.              | Connecting to a web server on port 80 and examining the HTTP banner to identify the web server software and version.                  | Netcat, curl                                               | Low: Banner grabbing typically involves minimal interaction but can still be logged.                               |
| **OS Fingerprinting**      | Identifying the operating system running on the target.                                       | Using Nmap's OS detection capabilities (`-O`) to determine if the target is running Windows, Linux, or another OS.                    | Nmap, Xprobe2                                              | Low: OS fingerprinting is usually passive, but some advanced techniques can be detected.                           |
| **Service Enumeration**    | Determining the specific versions of services running on open ports.                          | Using Nmap's service version detection (`-sV`) to determine if a web server is running Apache 2.4.50 or Nginx 1.18.0.                 | Nmap                                                       | Low: Similar to banner grabbing, service enumeration can be logged but is less likely to trigger alerts.           |
| **Web Spidering**          | Crawling the target website to identify web pages, directories, and files.                    | Running a web crawler like Burp Suite Spider or OWASP ZAP Spider to map out the structure of a website and discover hidden resources. | Burp Suite Spider, OWASP ZAP Spider, Scrapy (customisable) | Low to Medium: Can be detected if the crawler's behaviour is not carefully configured to mimic legitimate traffic. |
## Passive Reconnaissance
- gathering information without interacting with the target

| **Technique**             | **Description**                                                                                                                 | **Example**                                                                                                                                       | **Tools**                                                                   | **Risk of Detection**                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| **Search Engine Queries** | Utilising search engines to uncover information about the target, including websites, social media profiles, and news articles. | Searching Google for "`[Target Name] employees`" to find employee information or social media profiles.                                           | Google, DuckDuckGo, Bing, and specialized search engines (e.g., ==Shodan==) | Very Low: Search engine queries are normal internet activity and unlikely to trigger alerts.           |
| **WHOIS Lookups**         | Querying WHOIS databases to retrieve domain registration details.                                                               | Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers.                                | whois command-line tool, online WHOIS lookup services                       | Very Low: WHOIS queries are legitimate and do not raise suspicion.                                     |
| **DNS**                   | Analysing DNS records to identify subdomains, mail servers, and other infrastructure.                                           | Using `dig` to enumerate subdomains of a target domain.                                                                                           | dig, nslookup, host, dnsenum, fierce, dnsrecon                              | Very Low: DNS queries are essential for internet browsing and are not typically flagged as suspicious. |
| **Web Archive Analysis**  | Examining historical snapshots of the target's website to identify changes, vulnerabilities, or hidden information.             | Using the Wayback Machine to view past versions of a target website to see how it has changed over time.                                          | Wayback Machine                                                             | Very Low: Accessing archived versions of websites is a normal activity.                                |
| **Social Media Analysis** | Gathering information from social media platforms like LinkedIn, Twitter, or Facebook.                                          | Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets. | LinkedIn, Twitter, Facebook, specialised OSINT tools                        | Very Low: Accessing public social media profiles is not considered intrusive.                          |
| **Code Repositories**     | Analysing publicly accessible code repositories like GitHub for exposed credentials or vulnerabilities.                         | Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities.        | GitHub, GitLab                                                              | Very Low: Code repositories are meant for public access, and searching them is not suspicious.         |
## WHOIS (giant phonebook for the internet)
- query and response protocol designed to access databases that store information about registered internet resources

What is it used for in cybersecurity?
- **Phishing Investigation**: We can detect suspicious activity by looking at the registration date (example: few days ago), registrant (example: private) or name servers (example: servers associated with a known malicious provider).
- **Malware Analysis**: When malware communicates with an external server.
- **Threat Intelligence Report**: Again, we look for suspicious data to write in our report.
## DNS and Subdomains
- DNS is like GPS, it translates site names into IP addresses

How does DNS work?
1. **Your Computer Asks for Directions (DNS Query)**: When you enter the domain name, your computer first checks its memory (cache) to see if it remembers the IP address from a previous visit. If not, it reaches out to a DNS resolver, usually provided by your internet service provider (ISP).
2. **The DNS Resolver Checks its Map (Recursive Lookup)**: The resolver also has a cache, and if it doesn't find the IP address there, it starts a journey through the DNS hierarchy. It begins by asking a root name server, which is like the librarian of the internet.
3. **Root Name Server Points the Way**: The root server doesn't know the exact address but knows who does – the Top-Level Domain (TLD) name server responsible for the domain's ending (e.g., .com, .org). It points the resolver in the right direction.
4. **TLD Name Server Narrows It Down**: The TLD name server is like a regional map. It knows which authoritative name server is responsible for the specific domain you're looking for (e.g., `example.com`) and sends the resolver there.
5. **Authoritative Name Server Delivers the Address**: The authoritative name server is the final stop. It's like the street address of the website you want. It holds the correct IP address and sends it back to the resolver.
6. **The DNS Resolver Returns the Information**: The resolver receives the IP address and gives it to your computer. It also remembers it for a while (caches it), in case you want to revisit the website soon.
7. **Your Computer Connects**: Now that your computer knows the IP address, it can connect directly to the web server hosting the website, and you can start browsing.

==IMPORTANT==
Hosts File = a file that allows hostname to IP mapping (`/etc/hosts` on Linux and MacOS and `C:\Windows\System32\drivers\etc\hosts`)

Mapping example:
```txt
127.0.0.1       localhost
192.168.1.10    devserver.local
```
```txt
127.0.0.1       myapp.local // for testing local apps
```
```txt
0.0.0.0       unwanted-site.com // for blocking sites
```
## Key DNS Concepts

**Zone** = distinct part of domain namespace that an admin manages (example: example.com and it's subdomains like mail.example.com or blog.example.com are all in the same ZONE)
- the **zone** has a **zone file** that is on the DNS server

Example of a zone file for example.com:
```dns-zone
$TTL 3600 ; Default Time-To-Live (1 hour)
@       IN SOA   ns1.example.com. admin.example.com. (
                2024060401 ; Serial number (YYYYMMDDNN)
                3600       ; Refresh interval
                900        ; Retry interval
                604800     ; Expire time
                86400 )    ; Minimum TTL

@       IN NS    ns1.example.com.
@       IN NS    ns2.example.com.
@       IN MX 10 mail.example.com.
www     IN A     192.0.2.1
mail    IN A     198.51.100.1
ftp     IN CNAME www.example.com.
```
- here we can see the authoritative name servers (**NS**), mail servers (**MX**) and IP addresses (**A**) for various hosts within example.com domain

| DNS Concept                   | Description                                                                      | Example                                                                                                                                 |
| ----------------------------- | -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Domain Name**               | A human-readable label for a website or other internet resource.                 | `www.example.com`                                                                                                                       |
| **IP Address**                | A unique numerical identifier assigned to each device connected to the internet. | `192.0.2.1`                                                                                                                             |
| **DNS Resolver**              | A server that translates domain names into IP addresses.                         | Your ISP's DNS server or public resolvers like Google DNS (`8.8.8.8`)                                                                   |
| **Root Name Server**          | The top-level servers in the DNS hierarchy.                                      | There are 13 root servers worldwide, named A-M: `a.root-servers.net`                                                                    |
| **TLD Name Server**           | Servers responsible for specific top-level domains (e.g., .com, .org).           | [Verisign](https://en.wikipedia.org/wiki/Verisign) for `.com`, [PIR](https://en.wikipedia.org/wiki/Public_Interest_Registry) for `.org` |
| **Authoritative Name Server** | The server that holds the actual IP address for a domain.                        | Often managed by hosting providers or domain registrars.                                                                                |
| **DNS Record Types**          | Different types of information stored in DNS.                                    | A, AAAA, CNAME, MX, NS, TXT, etc.                                                                                                       |

| Record Type | Full Name                 | Description                                                                                                                                 | Zone File Example                                                                              |
| ----------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **A**       | Address Record            | Maps a hostname to its IPv4 address.                                                                                                        | `www.example.com.` IN A `192.0.2.1`                                                            |
| **AAAA**    | IPv6 Address Record       | Maps a hostname to its IPv6 address.                                                                                                        | `www.example.com.` IN AAAA `2001:db8:85a3::8a2e:370:7334`                                      |
| **CNAME**   | Canonical Name Record     | Creates an alias for a hostname, pointing it to another hostname.                                                                           | `blog.example.com.` IN CNAME `webserver.example.net.`                                          |
| **MX**      | Mail Exchange Record      | Specifies the mail server(s) responsible for handling email for the domain.                                                                 | `example.com.` IN MX 10 `mail.example.com.`                                                    |
| **NS**      | Name Server Record        | Delegates a DNS zone to a specific authoritative name server.                                                                               | `example.com.` IN NS `ns1.example.com.`                                                        |
| **TXT**     | Text Record               | Stores arbitrary text information, often used for domain verification or security policies.                                                 | `example.com.` IN TXT `"v=spf1 mx -all"` (SPF record)                                          |
| **SOA**     | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
| **SRV**     | Service Record            | Defines the hostname and port number for specific services.                                                                                 | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.`                             |
| **PTR**     | Pointer Record            | Used for reverse DNS lookups, mapping an IP address to a hostname.                                                                          | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.`                                            |
## Digging DNS
### DNS Tools
| Tool                       | Key Features                                                                                            | Use Cases                                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `dig`                      | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.                      |
| `nslookup`                 | Simpler DNS lookup tool, primarily for A, AAAA, and MX records.                                         | Basic DNS queries, quick checks of domain resolution and mail server records.                                                           |
| `host`                     | Streamlined DNS lookup tool with concise output.                                                        | Quick checks of A, AAAA, and MX records.                                                                                                |
| `dnsenum`                  | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).         | Discovering subdomains and gathering DNS information efficiently.                                                                       |
| `fierce`                   | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.         | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.                                           |
| `dnsrecon`                 | Combines multiple DNS reconnaissance techniques and supports various output formats.                    | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.                                  |
| `theHarvester`             | OSINT tool that gathers information from various sources, including DNS records (email addresses).      | Collecting email addresses, employee information, and other data associated with a domain from multiple sources.                        |
| Online DNS Lookup Services | User-friendly interfaces for performing DNS lookups.                                                    | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information |
### Common `dig` commands
|Command|Description|
|---|---|
|`dig domain.com`|Performs a default A record lookup for the domain.|
|`dig domain.com A`|Retrieves the IPv4 address (A record) associated with the domain.|
|`dig domain.com AAAA`|Retrieves the IPv6 address (AAAA record) associated with the domain.|
|`dig domain.com MX`|Finds the mail servers (MX records) responsible for the domain.|
|`dig domain.com NS`|Identifies the authoritative name servers for the domain.|
|`dig domain.com TXT`|Retrieves any TXT records associated with the domain.|
|`dig domain.com CNAME`|Retrieves the canonical name (CNAME) record for the domain.|
|`dig domain.com SOA`|Retrieves the start of authority (SOA) record for the domain.|
|`dig @1.1.1.1 domain.com`|Specifies a specific name server to query; in this case 1.1.1.1|
|`dig +trace domain.com`|Shows the full path of DNS resolution.|
|`dig -x 192.168.1.1`|Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.|
|`dig +short domain.com`|Provides a short, concise answer to the query.|
|`dig +noall +answer domain.com`|Displays only the answer section of the query output.|
|`dig domain.com ANY`|Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)).|
## Subdomains
- they are extensions of the main domain

Example: For `example.com` we might have `blog.example.com` or `shop.example.com` or others.
### Enumeration
1) **Active Enumeration**
	- attempting DNS zone transfer (rarely works)
	- brute-force enumeration (==gobuster==(the best), ffuf or dnsenum) with wordlists
2) **Passive Enumeration**
	- Certificate Transparency (CT) logs (public repos of SSL/TLS certs) ==https://crt.sh    ==
	- using search engines
### Brute-forcing
- active subdomain discovery

**Process**:
1) Wordlist Selection
2) Iteration and Querying
3) DNS Lookup
4) Filtering and Validation

| Tool                                                    | Description                                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [dnsenum](https://github.com/fwaeytens/dnsenum)         | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.                 |
| [fierce](https://github.com/mschwager/fierce)           | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.                |
| [dnsrecon](https://github.com/darkoperator/dnsrecon)    | Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.                     |
| [amass](https://github.com/owasp-amass/amass)           | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.               |
| [puredns](https://github.com/d3mondev/puredns)          | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.                           |
```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```
- `-r` flag tells dnsenum to recursively enumerate that subdomain for subdomains
==Note==: `dnsenum` works best with a wordlist and with the flag `-r`.
## DNS Zone Transfers
![[pako_eNqNkc9qwzAMxl9F-JSx7gV8KISWXcY2aHYYwxdjK39obGWKvBFK333ukg5aGNQnW9b3Q_q-g3LkUWk14mfC6HDb2YZtMBHyGdFR9JanCvkL-WG9vh-4C38FDeX74w52J-0oUHxQRHhjG8ca-W5mXAgy4YqpoXotM8EReygqsSxANZRJWuJOpoXSEw0gC3ku3QTfvlQLfBZh9DeO.svg]]
1. `Zone Transfer Request (AXFR)`: The secondary DNS server initiates the process by sending a zone transfer request to the primary server. This request typically uses the AXFR (Full Zone Transfer) type.
2. `SOA Record Transfer`: Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record. The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.
3. `DNS Records Transmission`: The primary server then transfers all the DNS records in the zone to the secondary server, one by one. This includes records like A, AAAA, MX, CNAME, NS, and others that define the domain's subdomains, mail servers, name servers, and other configurations.
4. `Zone Transfer Complete`: Once all records have been transmitted, the primary server signals the end of the zone transfer. This notification informs the secondary server that it has received a complete copy of the zone data.
5. `Acknowledgement (ACK)`: The secondary server sends an acknowledgement message to the primary server, confirming the successful receipt and processing of the zone data. This completes the zone transfer process.
### Vulnerability
- authorizing DNS zone transfers to everyone makes all the DNS records visible
What is visible?
- `Subdomains`: A complete list of subdomains, many of which might not be linked from the main website or easily discoverable through other means. These hidden subdomains could host development servers, staging environments, administrative panels, or other sensitive resources.
- `IP Addresses`: The IP addresses associated with each subdomain, providing potential targets for further reconnaissance or attacks.
- `Name Server Records`: Details about the authoritative name servers for the domain, revealing the hosting provider and potential misconfigurations.

==Mitigation==: DNS can be configured to allow only trusted secondary servers to perform zone transfers.

Example for testing the vulnerability with `dig`:
```shell-session
dig axfr @nsztm1.digi.ninja zonetransfer.me
```
- this performs a zone transfer for `zonetransfer.me` from the DNS server at (@) `nsztm1.digi.ninja`
## Virtual Hosts
- web servers like Apache, Nginx or IIS are designed to host multiple websites on a single server through `virtual hosting`
- this allows them to differentiate between domains, subdomains or even separate websites with distinct content
- basically, multiple websites with their subdomains can be hosted on a single IP address

==VHost fuzzing==: Method of discovering public and non-public subdomains and VHosts by testing various hostnames against an IP address.

![[pako_eNqNUsFuwjAM_ZUop00CPqAHDhubuCBNBW2XXrzUtNFap3McOoT496WUVUA3aTkltp_f84sP2rgcdaI9fgYkgwsLBUOdkYqnARZrbAMk6oFd65HHiTd8XyPvfku9WpYA1dJ5eXS0tcW4ZOFMqJEkdU4y6vNnqul8PvRO1HKzeVFpp9KLumvbdmapAsItoy1KmRlX3_fwAXTd4OkL.svg]]
1. `Browser Requests a Website`: When you enter a domain name (e.g., `www.inlanefreight.com`) into your browser, it initiates an HTTP request to the web server associated with that domain's IP address.
2. `Host Header Reveals the Domain`: The browser includes the domain name in the request's `Host` header, which acts as a label to inform the web server which website is being requested.
3. `Web Server Determines the Virtual Host`: The web server receives the request, examines the `Host` header, and consults its virtual host configuration to find a matching entry for the requested domain name.
4. `Serving the Right Content`: Upon identifying the correct virtual host configuration, the web server retrieves the corresponding files and resources associated with that website from its document root and sends them back to the browser as the HTTP response.
### Types of Virtual Hosting
1) **Name Based**: It relies on ==HTTP Host Header== to distinguish between websites on the same IP address. (great for scalability and cheap because it requires one IP address)
2) **IP-Based**: This assigns different unique IPs to each website; does NOT rely on the HTTP Host Header. (expensive and less scalable)
3) **Port-Based**: It uses ports to host different websites on the same IP address (example: 80, 8080, others). (less user friendly but works)

### Virtual Host Discovery Tools
|Tool|Description|Features|
|---|---|---|
|[gobuster](https://github.com/OJ/gobuster)|A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery.|Fast, supports multiple HTTP methods, can use custom wordlists.|
|[Feroxbuster](https://github.com/epi052/feroxbuster)|Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.|Supports recursion, wildcard discovery, and various filters.|
|[ffuf](https://github.com/ffuf/ffuf)|Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header.|Customizable wordlist input and filtering options.|
==Very useful `gobuster` command:==
```shell-session
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```
There are a couple of other arguments that are worth knowing:
- Consider using the `-t` flag to increase the number of threads for faster scanning.
- The `-k` flag can ignore SSL/TLS certificate errors.
- You can use the `-o` flag to save the output to a file for later analysis.
## Certificate Transparency Logs (global registry of certificates)
- data between a browser and a website is encrypted with **Secure Socket Layer/Transport Layer Security(SSL/TLS)** protocol
- the **SSL/TLS** has a certificate that verifies a website's integrity and secures communication
- **Certificate Transparency Logs** are public ledgers that record what SSL/TLS certificates have been issued for certain websites
![[pako_eNqFkk1LxDAQhv9KmIMo7Afb9lRlwdWDFy_qzXjINtMmbNqUbGqRZf-7-TDQlYXmMjPJPPO-kDlBpTlCCY1hvSC7j3vaEXee0NjNJwUfyeZhb9bb23EcV7JTrMPaoGyEXVW6vaPwRZbLLXlhR-EJHxMRcl2TOIXcxCTzzEQnSzpZpPZKN3NCEzxPeB5xjt8zdJZsZlds5slm8c9m.svg]]
(Merkle Tree Structure)
- for example if we need to verify cert 2 for `blog.inlanefreight.com` we verify first cert 2, then hash 1 and then the root hash

==Note==: CT logs might reveal subdomains with expired certificates which can be exploited.

| Tool                                | Key Features                                                                                                     | Use Cases                                                                                                 | Pros                                              | Cons                                         |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------- |
| [crt.sh](https://crt.sh/)           | User-friendly web interface, simple search by domain, displays certificate details, SAN entries.                 | Quick and easy searches, identifying subdomains, checking certificate issuance history.                   | Free, easy to use, no registration required.      | Limited filtering and analysis options.      |
| [Censys](https://search.censys.io/) | Powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes. | In-depth analysis of certificates, identifying misconfigurations, finding related certificates and hosts. | Extensive data and filtering options, API access. | Requires registration (free tier available). |

==IMPORTANT DISCOVERY.... CENSYS IS REALLY PONT!==
## Fingerprinting
- it means extracting technical details about a website or web application
- fingerprinting helps us target our attacks, identify misconfigurations, prioritize targets and build a comprehensive profile of the target's infrastructure
### Techniques
1) **Banner Grabbing**: They usually tell server software, version and other details.
2) **Analyzing HTTP Headers**: Also reveals server software, technologies and others.
3) **Probing for Specific Responses**: It involves analyzing errors from specifically crafted requests.
4) **Analyzing Page Content**: Structure, scripts and others may offer some information.

| Tool           | Description                                                                                                           | Features                                                                                            |
| -------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| **Wappalyzer** | Browser extension and online service for website technology profiling.                                                | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| **BuiltWith**  | Web technology profiler that provides detailed reports on a website's technology stack.                               | Offers both free and paid plans with varying levels of detail.                                      |
| **WhatWeb**    | Command-line tool for website fingerprinting.                                                                         | Uses a vast database of signatures to identify various web technologies.                            |
| **Nmap**       | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting.                          |
| **Netcraft**   | Offers a range of web security services, including website fingerprinting and security reporting.                     | Provides detailed reports on a website's technology, hosting provider, and security posture.        |
| **wafw00f**    | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs).                             | Helps determine if a WAF is present and, if so, its type and configuration.                         |
| **Nikto**      | Powerful open-source web server scanner.                                                                              | Vulnerability assessment and fingerprinting.                                                        |
How to see ONLY page header with `curl`:
```shell-session
curl -I inlanefreight.com
```

==IMPORTANT==: Always search for a WAF(Web Application Firewall) before pentesting!!

How to install `Wafw00f`:
```shell-session
pip3 install git+https://github.com/EnableSecurity/wafw00f
```
Basic syntax:
```shell-session
wafw00f inlanefreight.com
```

How to install `Nikto`:
```shell-session
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```
Basic syntax for fingerprinting:
```shell-session
nikto -h inlanefreight.com -Tuning b 
```
- the flag `-Tuning b` tells it to only run software identification modules
## Crawling (spidering)
- it's a process for systematically browsing the World Wide Web
- a web crawler is a bot that uses algorithms to discover and index web pages

How do these bots work?
1) They start with a seed which is a URL (the initial web page to crawl).
2) The crawler extracts all the links from the page and adds them to a list for future crawling.
3) It continues crawling.
![[pako_eNo90D0PgjAQBuC_0twsg98Jgwkf6oKJgThZhkpPIEohpR0M4b970shNd09uuHsHKFqJ4EOpRVexJOWqtw83ZIiS3dKEK0YV3K-iRLbMuUIluQqY5x1Y6HSV_yFysCYIJ4gdbGY4OtgSRBOcHOxmODvYE8ACGtSNqCXdOPwu4WAqbJCDT60U-sWBq5H2hDVt9lEF-EZbXIBubVmB.svg]]
(Breadth-First Crawling -> prioritizes a website's width before going deeper)
![[pako_eNo9zz0PgjAQBuC_0twsg18LgwlfGyYG4uQ5VHoC0RZS2sEQ_rsnTezU98mlvXeGZlAEMbRWjp0oKzSTf4RQEylxrUo0gk9yu8iWxPaOhoxCk4goOok06I41XSELsGfIVsgDHBjyFYoAR4YivCEEGtiAJqtlr3iZ-fclgutIE0LMVyXtCwHNwnPSu6H-mAZiZz1twA6-7SB-yvfE.svg]]
(Depth-First Crawling -> prioritizes a website's depth over breadth)
## robots.txt
- it tells internet bot crawlers what they are allowed and not allowed to access on the website
- it's placed in the root directory of a website

Example:
```txt
User-agent: *
Disallow: /private/
```
- `User-agent` -> this specifies what bots should abide the rules
- `Directives` -> these lines tell the bots what they are allowed or disallowed to access (example: `Disallow: /private/`)

| Directive       | Description                                                                                                        | Example                                                      |
| --------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| **Disallow**    | Specifies paths or patterns that the bot should not crawl.                                                         | `Disallow: /admin/` (disallow access to the admin directory) |
| **Allow**       | Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader `Disallow` rule. | `Allow: /public/` (allow access to the public directory)     |
| **Crawl-delay** | Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server.                | `Crawl-delay: 10` (10-second delay between requests)         |
| **Sitemap**     | Provides the URL to an XML sitemap for more efficient crawling.                                                    | `Sitemap: https://www.example.com/sitemap.xml`               |
Another example:
```txt
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```
## .Well-Known URIs
- standardized directory within a website's root domain
- accessed via `/.well-known/` (`https://example.com/.well-known/`)
- it centralizes a website's critical metadata

| URI Suffix                       | Description                                                                                           | Status      | Reference                                                                               |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------- | --------------------------------------------------------------------------------------- |
| **security.txt**                 | Contains contact information for security researchers to report vulnerabilities.                      | Permanent   | RFC 9116                                                                                |
| **/.well-known/change-password** | Provides a standard URL for directing users to a password change page.                                | Provisional | https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri |
| **openid-configuration**         | Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol. | Permanent   | http://openid.net/specs/openid-connect-discovery-1_0.html                               |
| **assetlinks.json**              | Used for verifying ownership of digital assets (e.g., apps) associated with a domain.                 | Permanent   | https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md     |
| **mta-sts.txt**                  | Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.      | Permanent   | RFC 8461                                                                                |
## Creepy Crawlies
### Popular Web Crawlers
1. **Burp Suite Spider**: Burp Suite, a widely used web application testing platform, includes a powerful active crawler called Spider. Spider excels at mapping out web applications, identifying hidden content, and uncovering potential vulnerabilities.
2. **OWASP ZAP (Zed Attack Proxy)**: ZAP is a free, open-source web application security scanner. It can be used in automated and manual modes and includes a spider component to crawl web applications and identify potential vulnerabilities.
3. **Scrapy (Python Framework)**: Scrapy is a versatile and scalable Python framework for building custom web crawlers. It provides rich features for extracting structured data from websites, handling complex crawling scenarios, and automating data processing. Its flexibility makes it ideal for tailored reconnaissance tasks.
4. **Apache Nutch (Scalable Crawler)**: Nutch is a highly extensible and scalable open-source web crawler written in Java. It's designed to handle massive crawls across the entire web or focus on specific domains. While it requires more technical expertise to set up and configure, its power and flexibility make it a valuable asset for large-scale reconnaissance projects.
### Scrapy
Installation:
```shell-session
pip3 install scrapy
```
`ReconSpider` download:
```shell-session
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip

unzip ReconSpider.zip
```
Run `Reconspider`:
```shell-session
python3 ReconSpider.py http://inlanefreight.com
```
- the result will be stored in a `.json` file
Example:
```json
{
    "emails": [
        "lily.floid@inlanefreight.com",
        "cvs@inlanefreight.com",
        ...
    ],
    "links": [
        "https://www.themeansar.com",
        "https://www.inlanefreight.com/index.php/offices/",
        ...
    ],
    "external_files": [
        "https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf",
        ...
    ],
    "js_files": [
        "https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2",
        ...
    ],
    "form_fields": [],
    "images": [
        "https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01-1024x810.png",
        ...
    ],
    "videos": [],
    "audio": [],
    "comments": [
        "<!-- #masthead -->",
        ...
    ]
}
```
## Search Engine Discovery
- basically, OSINT (Open Source Intelligence)
- using search engines to discover publicly available data
### Search Operators

| Operator                   | Operator Description                                         | Example                                             | Example Description                                                                     |
| :------------------------- | :----------------------------------------------------------- | :-------------------------------------------------- | :-------------------------------------------------------------------------------------- |
| **site:**                  | Limits results to a specific website or domain.              | `site:example.com`                                  | Find all publicly accessible pages on example.com.                                      |
| **inurl:**                 | Finds pages with a specific term in the URL.                 | `inurl:login`                                       | Search for login pages on any website.                                                  |
| **filetype:**              | Searches for files of a particular type.                     | `filetype:pdf`                                      | Find downloadable PDF documents.                                                        |
| **intitle:**               | Finds pages with a specific term in the title.               | `intitle:"confidential report"`                     | Look for documents titled "confidential report" or similar variations.                  |
| **intext:** or **inbody:** | Searches for a term within the body text of pages.           | `intext:"password reset"`                           | Identify webpages containing the term “password reset”.                                 |
| **cache:**                 | Displays the cached version of a webpage (if available).     | `cache:example.com`                                 | View the cached version of example.com to see its previous content.                     |
| **link:**                  | Finds pages that link to a specific webpage.                 | `link:example.com`                                  | Identify websites linking to example.com.                                               |
| **related:**               | Finds websites related to a specific webpage.                | `related:example.com`                               | Discover websites similar to example.com.                                               |
| **info:**                  | Provides a summary of information about a webpage.           | `info:example.com`                                  | Get basic details about example.com, such as its title and description.                 |
| **define:**                | Provides definitions of a word or phrase.                    | `define:phishing`                                   | Get a definition of "phishing" from various sources.                                    |
| **numrange:**              | Searches for numbers within a specific range.                | `site:example.com numrange:1000-2000`               | Find pages on example.com containing numbers between 1000 and 2000.                     |
| **allintext:**             | Finds pages containing all specified words in the body text. | `allintext:admin password reset`                    | Search for pages containing both "admin" and "password reset" in the body text.         |
| **allinurl:**              | Finds pages containing all specified words in the URL.       | `allinurl:admin panel`                              | Look for pages with "admin" and "panel" in the URL.                                     |
| **allintitle:**            | Finds pages containing all specified words in the title.     | `allintitle:confidential report 2023`               | Search for pages with "confidential," "report," and "2023" in the title.                |
| **AND**                    | Narrows results by requiring all terms to be present.        | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com.                                  |
| **OR**                     | Broadens results by including pages with any of the terms.   | `"linux" OR "ubuntu" OR "debian"`                   | Search for webpages mentioning Linux, Ubuntu, or Debian.                                |
| **NOT**                    | Excludes results containing the specified term.              | `site:bank.com NOT inurl:login`                     | Find pages on bank.com excluding login pages.                                           |
| `*` (wildcard)             | Represents any character or word.                            | `site:socialnetwork.com filetype:pdf user* manual`  | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| **..** (range search)      | Finds results within a specified numerical range.            | `site:ecommerce.com "price" 100..500`               | Look for products priced between 100 and 500 on an e-commerce website.                  |
| **" "** (quotation marks)  | Searches for exact phrases.                                  | `"information security policy"`                     | Find documents mentioning the exact phrase "information security policy".               |
| **-** (minus sign)         | Excludes terms from the search results.                      | `site:news.com -inurl:sports`                       | Search for news articles on news.com excluding sports-related content.                  |
### Other Google Dorking Examples
- Finding Login Pages:
    - `site:example.com inurl:login`
    - `site:example.com (inurl:login OR inurl:admin)`
- Identifying Exposed Files:
    - `site:example.com filetype:pdf`
    - `site:example.com (filetype:xls OR filetype:docx)`
- Uncovering Configuration Files:
    - `site:example.com inurl:config.php`
    - `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)
- Locating Database Backups:
    - `site:example.com inurl:backup`
    - `site:example.com filetype:sql`
## Web Archives (Wayback Machine)
- Wayback Machine is a digital archive of the World Wide Web
- it has been archiving websites since 1996
- it works by using web crawlers that capture snapshots of websites regularly
### Usage
1. **Uncovering Hidden Assets and Vulnerabilities**: The Wayback Machine allows you to discover old web pages, directories, files, or subdomains that might not be accessible on the current website, potentially exposing sensitive information or security flaws.
2. **Tracking Changes and Identifying Patterns**: By comparing historical snapshots, you can observe how the website has evolved, revealing changes in structure, content, technologies, and potential vulnerabilities.
3. **Gathering Intelligence**: Archived content can be a valuable source of OSINT, providing insights into the target's past activities, marketing strategies, employees, and technology choices.
4. **Stealthy Reconnaissance**: Accessing archived snapshots is a passive activity that doesn't directly interact with the target's infrastructure, making it a less detectable way to gather information.
## Automating Recon
- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon): A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs.
- [Recon-ng](https://github.com/lanmaster53/recon-ng): A powerful framework written in Python that offers a modular structure with various modules for different reconnaissance tasks. It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities.
- [theHarvester](https://github.com/laramies/theHarvester): Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database. It is a command-line tool written in Python.
- [SpiderFoot](https://github.com/smicallef/spiderfoot): An open-source intelligence automation tool that integrates with various data sources to collect information about a target, including IP addresses, domain names, email addresses, and social media profiles. It can perform DNS lookups, web crawling, port scanning, and more.
- [OSINT Framework](https://osintframework.com/): A collection of various tools and resources for open-source intelligence gathering. It covers a wide range of information sources, including social media, search engines, public records, and more.
## Tips and Tricks
- always look for vhosts on a web application
- use gobuster and dirbuster
- use crawlers (`Reconspider.py`)



# Useful Links:

https://www.shodan.io/
https://search.censys.io/ //REALLY REALLY CT LOGS PONT :D