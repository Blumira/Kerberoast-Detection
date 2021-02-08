
Automation for creating a Kerberos service account Honey credential:

Threat actors can abuse the kerberos protocol to recover passwords related to service accounts using a tactic called Kerberoasting

In Kerberoasting threat actors abuse valid Kerberos ticket granting tickets to make a request for a ticket granting service from any 
valid service principal name (SPN) within your Microsoft Active-Directory domain, such ticket granting services are vulnerable to 
offline password cracking which can allow a threat actor to recover the plaintext password of the associated service account mapped by 
the SPN.

In order to avoid false positive detections you can create a service account honeypot to detect Kerberoasting:

Requirements:

		- Generate SPN artifacts for the purpose of detecting kerberoasting in otherwise noisy enviroments
    
		- This powershell script should be executed by a user account with privledges for creating Active directory accounts and SPN's
    
		- Auditing of Kerberos Service Ticket Operations must be enabled
    
		- An alerting mechanism (like Blumira clould SIEM) that will generate alerts related to matches of the following
    
		- Event ID: 4769
    
		- Encryption type: 0x17
    
		- Ticket options: 0x40810000
    
		- SPN Name: <Name of your honeycred / SPN name>

Usage:
	
  From an administrative powershell command prompt > .\DOGEMIRA.ps1

 Version: 1.0
 
 Author: Bill Reyor, Blumira
 
 https://www.blumira.com
 
 Twitter: @blumirasec
