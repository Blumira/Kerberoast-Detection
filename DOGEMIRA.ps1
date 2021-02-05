
#_ .-') _                              ('-.  _   .-')            _  .-')     ('-.     
#( (  OO) )                           _(  OO)( '.( OO )_         ( \( -O )   ( OO ).-. 
# \     .'_  .-'),-----.   ,----.    (,------.,--.   ,--.) ,-.-') ,------.   / . --. / 
# ,`'--..._)( OO'  .-.  ' '  .-./-')  |  .---'|   `.'   |  |  |OO)|   /`. '  | \-.  \  
# |  |  \  '/   |  | |  | |  |_( O- ) |  |    |         |  |  |  \|  /  | |.-'-'  |  | 
# |  |   ' |\_) |  |\|  | |  | .--, \(|  '--. |  |'.'|  |  |  |(_/|  |_.' | \| |_.'  | 
# |  |   / :  \ |  | |  |(|  | '. (_/ |  .--' |  |   |  | ,|  |_.'|  .  '.'  |  .-.  | 
# |  '--'  /   `'  '-'  ' |  '--'  |  |  `---.|  |   |  |(_|  |   |  |\  \   |  | |  | 
# `-------'      `-----'   `------'   `------'`--'   `--'  `--'   `--' '--'  `--' `--' 
# 
# Automation for creating a Kerberos service account Honey credential:
# 
# In order to avoid false positive detections you can create a service account honeypot to detect Kerberoasting:
# 
#
# Manually you would do this by executing steps:
#
# Step 1: Create a new AD user account (not an admin user). 
#	Example name: backupexec
#	
# Step 2: Add a Service Principal Name (SPN) to the account 
#	setspn -A backupsvc/Blu-DC00.miratime.org:80 backupexec
# 
# Step 3: Confirm the SPN was created correctly
#	setspn -Q */* | findstr backupexec
#
# Requirements: 
# 		- Generate SPN artifacts for the purpose of detecting kerberoasting in otherwise noisy enviroments
# 		- This powershell script should be executed by a user account with privledges for creating Active directory accounts and SPN's
#
# Version: 1.0
# Author: Bill Reyor, Blumira
# https://www.blumira.com
# Twitter: @blumirasec


import-module ActiveDircetory
Add-Type -AssemblyName System.Web

#Select a username and store in $user
$uprefix = "DefaultAppPool_"
$userrnd = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}) 
$user = $uprefix + $userrnd

#Create SPN Name - store in $spnb
$sprefix = "IIS_IUSRSB_"
$SPNrnd = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}) 
$spnb = $sprefix + $SPNrnd

#Generate SPNhost
$currentdmn = get-addomain | select-object -ExpandProperty DNSRoot
$HOSTrnd = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}) 
$spnhost = "portal." + $currentdmn

#Password Creation
$minLength = 25 ## characters
$maxLength = 30 ## characters
$length = Get-Random -Minimum $minLength -Maximum $maxLength
$nonAlphaChars = 5
$password = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
$secPw = ConvertTo-SecureString -String $password -AsPlainText -Force

#Create the user
New-ADUser -SamAccountName $user -Name $user -AccountPassword $secPw -Enabled 1
$Command = "setspn -A " + $spnb + "/" + $spnhost + ":80 " + $user
Invoke-Expression $Command