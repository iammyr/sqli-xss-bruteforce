# sqli-bruteforce
SQL Injection Bruteforce

The attack.sh script automates the submission of a series of requests to a Web application which attempt to exploit SQL Injection vulnerabilities through several malicious payloads and attack vectors. 

The script requires the following input parameters:
* URL of the Web application to attack
* Full absolute path of the file that contains a list of suffix that have to be appended to the base URL provided before in order to address different services of the application
* Full absolute path of the folder containing lists of payloads within files all ending with the ".pay" extension
If you want you can use the malicious payloads provided here under the "payloads" folder.

Instructions are echoed as you run the script with no arguments.

This bruteforce attack is based on the OWASP Benchmark web application but can be applied to any other application as well.
