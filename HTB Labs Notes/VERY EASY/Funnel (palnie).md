
27-09-2024 11:35 am

Tags: [[FTP (21)|FTP (21)]] [[PostgreSQL]] [[Recon|Recon]] [[Tunneling]] [[Password Spraying]] [[Port Forwarding]] [[Anon or Guest Access|Anon or Guest Access]] [[Clear Text Credentials]] [[SSH (22)]] [[SOCKS5]]

References: https://app.hackthebox.com/starting-point


# Funnel (palnie)

- scan with NMAP
- found TCP 21 and 22
- 21 is vsFTPd 3.0.3
- has anonymous access enabled
- get default password and check for each user (this can also be done with `hydra` - syntax : `hydra -L usernames.txt -p 'funnel123#!#' {target_IP} ssh`)
- Christine hasn't changed her password on SSH
- I have access to SSH
- now I learn about tunneling:
```
In computer networks, a tunneling protocol is a communication protocol which allows for
the movement of data from one network to another, by exploiting encapsulation. It
involves allowing private network communications to be sent across a public network
(such as the Internet) through a process called encapsulation.
[...]
The tunneling protocol works by using the data portion of a packet (the payload) to
carry the packets that actually provide the service. Tunneling uses a layered protocol
model such as those of the OSI or TCP/IP protocol suite, but usually violates the
layering when using the payload to carry a service not normally provided by the
network. Typically, the delivery protocol operates at an equal or higher level in the
layered model than the payload protocol
```
- so SSH offers various types of tunneling
- the first type of tunneling is called **Local Port Forwarding** (this forwards traffic from the client's machine to the remote server - basically SSH allocates a socket on the remote server side)
- the second type of tunneling is called **Remote Port Forwarding** or **Reverse Tunneling** (basically the reverse of local port forwarding - the remote server sends data to the client)
- the third type is **Dynamic Port Forwarding** (local and remote port forwarding have to be defined prior to the creation of the tunnel and this is a PROBLEM - dynamic tunneling allows the user to specify one port that will forward the incoming traffic from the client to the server dynamically - SOCKS5 protocol)
- `ss -tuln` to see connections (`-l`: Display only listening sockets. `-t`: Display TCP sockets. `-n`: Do not try to resolve service names.)
- now comes the tunneling part - I will use local port forwarding (`ssh -L 1234:localhost:22 user@remote.example.com` - `-L` specifies local port forwarding, `1234` is the client's local port, `22` is the remote server's port `@remote.example.com`)
![[Pasted image 20240927121451.png]]
- I then install `psql` locally and connect by using `psql -U christine -h localhost -p 1234`
- I'm in B^)
- Input some postgresql commands and get the flag (`\l` - list existing databases; `\c <database>` - connect to a specified database; `\dt` - list all the data in the database; `SELECT * FROM flag;` - to get the flag)

- How to do it dynamically?
- `ssh -D 1234 christine@{target_IP}` (`-f` and `-N` flags so we do NOT SSH into the box)
- I need to use `proxychains`
- set a proxy chain in `/etc/proxychains4.conf` like this:
```
<SNIP>
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 127.0.0.1 9050
socks5 127.0.0.1 1234
```
- then `proxychains psql -U christine -h localhost -p 5432 "sslmode=disable"`
- gg I'm in B^)


==IMPORTANT - DO NOT FORGET==
- use `ss -tlnp` or `ss -tuln` to see active connections
- use `"sslmode=disable"` to not check for SSL so you don't get errors



# Useful Links:

