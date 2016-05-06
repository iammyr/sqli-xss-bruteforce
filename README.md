# sqli-xss-bruteforce
SQL Injection (SQLi) or Cross-Site Scripting (XSS) Bruteforce

The attack.sh script automates the submission of a series of requests to a Web application which attempt to exploit SQLi or XSS vulnerabilities, depending on the set of attack vectors you decide to use (see sqli-payloads and xss-payloads folders). 

The script requires the following input parameters:
* URL of the Web application to attack
* File that contains a list of suffix that have to be appended to the base URL provided before in order to address different services of the application
* Folder containing lists of payloads within files all ending with the ".pay" extension
If you want you can use the malicious payloads provided here under the "payloads" folder.

Instructions are echoed as you run the script with no arguments.

Example: 
```bash
$ echo -e "index\npage1\npage2" > suffix.txt
$ ./attack.sh http://localhost:8080/myapp suffix.txt payloads/
```
This bruteforce attack is modeled around the OWASP Benchmark web application as a target. For instance, it inserts malicious input as value of the parameter named "vector", most of the times. Please, change the PARAMETER constant in the script as appropriate to match the parameter name that your web application of interest is expecting.
