
14-09-2024 18:55 pm

Tags: [[NodeJS]] [[Recon|Recon]] [[Remote Code Execution]] [[Server Side Template Injection (SSTI)]] 

References: https://app.hackthebox.com/starting-point?tier=1


# Bike

- enumeration shows ports 22 and 80 open
![[Pasted image 20240914185717.png]]
- we see that we have a website on port 80
![[Pasted image 20240914190305.png]]
- the site dynamically returns a message after input
- check website with Wappalyzer
![[Pasted image 20240914190404.png]]
- check for SSTI with some payloads:
```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```
- the payload `{{7*7}}` shows an error message which tells us the root directory of the webpage is `/root/Backend` and it is using the `Handlebars` template engine
- then we use `Burpsuite` to capture the `POST` request:
	1) Go to `Proxy` tab
	2) Hit `Intercept if off`
	3) Post a request on the site in the input field
	4) Catch the request
	5) Hit `Ctrl + R` to send the request to the `Repeater` tab
	6) Use the `Decoder` tab to encode the payload from `HackTricks` from plain to URL
	7) Go back to the `Repeater` and after `email=` paste the encoded URL and `Send`
	8) We get an error saying that `require is not defined` in our code
	9) After changing the `require` part of the payload we see that we can inject commands
	10) Get the `flag.txt`

![[Pasted image 20240914191149.png]]
Result:
![[Pasted image 20240914191213.png]]










# Useful Links:

https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#handlebars-nodejs