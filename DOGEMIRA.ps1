# _ .-') _                              ('-.  _   .-')            _  .-')     ('-.     
#( (  OO) )                           _(  OO)( '.( OO )_         ( \( -O )   ( OO ).-. 
# \     .'_  .-'),-----.   ,----.    (,------.,--.   ,--.) ,-.-') ,------.   / . --. / 
# ,`'--..._)( OO'  .-.  ' '  .-./-')  |  .---'|   `.'   |  |  |OO)|   /`. '  | \-.  \  
# |  |  \  '/   |  | |  | |  |_( O- ) |  |    |         |  |  |  \|  /  | |.-'-'  |  | 
# |  |   ' |\_) |  |\|  | |  | .--, \(|  '--. |  |'.'|  |  |  |(_/|  |_.' | \| |_.'  | 
# |  |   / :  \ |  | |  |(|  | '. (_/ |  .--' |  |   |  | ,|  |_.'|  .  '.'  |  .-.  | 
# |  '--'  /   `'  '-'  ' |  '--'  |  |  `---.|  |   |  |(_|  |   |  |\  \   |  | |  | 
# `-------'      `-----'   `------'   `------'`--'   `--'  `--'   `--' '--'  `--' `--' 
# 
# Automation for creating Kerberoast and AS-Reproast honeypot accounts
#
# Requirements: 
#       - Generate SPN artifacts for the purpose of detecting kerberoasting in otherwise noisy enviroments
#       - This powershell script should be executed by a user account with privledges for creating Active directory accounts and SPN's
#
# Security Considerations:
#       - To prevent these honeypot accounts from being abused during an incident, the following configurations are set
#            - Primary group is set to 'Domain Guests'
#            - Accounts are removed from 'Domain Users' default group
#            - Logon Hours is set to 0 (disabled) for DefaultAppGroup honeypot account
#            - 'Log on to' restrictions set for both accounts
#            - Special note - logon hours must remain fully enabled for the Winnie account. Disabling for this account reduces its effectiveness as a honeypot
#
# Version: 1.4
# Author: Bill Reyor, Blumira
# https://www.blumira.com
# Twitter: @blumirasec
#
# version_changelog:
# v1.0 2021-02-05 - Initial creation
# v1.1 2021-07-08 - fixed import-module typo
# v1.2 2021-11-22 - updates to aid in AS-REP Roasting detection
# v1.3 2022-11-03 - fixes to AS-REP roasting account creation
# v1.4 2024-10-31 - enhancements made to honeypot account creation to make the accounts themselves more secure and less prone to follow-on activity. Additional QoL enhancements such as displaying actions taken by the script as well as error handling.


import-module ActiveDirectory
Add-Type -AssemblyName System.Web

function Remove-CreatedAccounts {
    param(
        [string]$user1,
        [string]$user2
    )
    
    try {
        if ($user1) {
            if (Get-ADUser -Filter {SamAccountName -eq $user1}) {
                Remove-ADUser -Identity $user1 -Confirm:$false
                Write-Host "Cleaned up user account: $user1" -ForegroundColor Yellow
            }
        }
        if ($user2) {
            if (Get-ADUser -Filter {SamAccountName -eq $user2}) {
                Remove-ADUser -Identity $user2 -Confirm:$false
                Write-Host "Cleaned up user account: $user2" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "Error during cleanup: $_" -ForegroundColor Red
    }
}

function Set-RestrictedLogonHours {
    param(
        [string]$Username
    )
    
    # Create a byte array of 21 bytes (represents the week in 1-hour intervals)
    $logonHours = New-Object byte[] 21
    
    # Set all hours to 0 (no access)
    for ($i = 0; $i -lt 21; $i++) {
        $logonHours[$i] = 0
    }
    
    try {
        Set-ADUser -Identity $Username -Replace @{logonHours = $logonHours}
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "Failed to set logon hours for $Username`: $errorMessage" -ForegroundColor Red
    }
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator. Please restart PowerShell as Administrator." -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit
}


try {

    #Select a username and store in $user
    $uprefix = "DefaultAppPool_"
    $userrnd = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}) 
    $user = $uprefix + $userrnd

    #Select a 2nd username and store in $user2
    $uprefix2 = "Winnie_"
    $userrnd2 = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_}) 
    $user2 = $uprefix2 + $userrnd2 

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

    #Create the first honeypot account
    New-ADUser -UserPrincipalName $user -SamAccountName $user -Name $user -AccountPassword $secPw -Enabled 1
    Write-Host "[INFO] Created user $user" -ForegroundColor Yellow
    Add-ADGroupMember -Identity "Domain Guests" -Members $user
    $guestGroupID = (Get-ADGroup "Domain Guests" -Properties primaryGroupToken).primaryGroupToken
    Set-ADUser -Identity $user -Replace @{primaryGroupID=$guestGroupID}
    Write-Host "[INFO] Added $user to Domain Guests and set as primary group" -ForegroundColor Yellow
    Remove-ADGroupMember -Identity "Domain Users" -Members $user -Confirm:$false
    Write-Host "[INFO] Removed $user from Domain Users group" -ForegroundColor Yellow
    Set-RestrictedLogonHours -Username $user
    Write-Host "[INFO] Set restricted logon hours for $user" -ForegroundColor Yellow
    Set-ADUser -Identity $user -LogonWorkstations DefaultAppPool-pc
    Write-Host "[INFO] Set 'Log on to' restrictions for $user" -ForegroundColor Yellow

    $Command = "setspn -A " + $spnb + "/" + $spnhost + ":80 " + $user
    Invoke-Expression $Command | Out-Null

    #Create second honeypot account
    New-ADUser -UserPrincipalName $user2 -Name $user2 -GivenName "Winnie" -Surname "TP" -SamAccountName $user2 -AccountPassword $secPw -Enabled $true -ChangePasswordAtLogon $false
    Set-ADAccountControl -Identity $user2 -DoesNotRequirePreAuth $true
    Write-Host "[INFO] Created user $user2" -ForegroundColor Yellow
    Add-ADGroupMember -Identity "Domain Guests" -Members $user2
    $guestGroupID = (Get-ADGroup "Domain Guests" -Properties primaryGroupToken).primaryGroupToken
    Set-ADUser -Identity $user2 -Replace @{primaryGroupID=$guestGroupID}
    Write-Host "[INFO] Added $user2 to Domain Guests and set as primary group" -ForegroundColor Yellow
    Remove-ADGroupMember -Identity "Domain Users" -Members $user2 -Confirm:$false
    Write-Host "[INFO] Removed $user2 from Domain Users group" -ForegroundColor Yellow
    Set-ADUser -Identity $user2 -LogonWorkstations Winnie-pc
    Write-Host "[INFO] Set 'Log on to' restrictions for $user2" -ForegroundColor Yellow


    # If we've made it this far without any errors, display success message
    Write-Host "$user and $user2 honeypot accounts successfully created!" -ForegroundColor Green

} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Host "Attempting to clean up created accounts..." -ForegroundColor Yellow
    Remove-CreatedAccounts -user1 $user -user2 $user2
    Write-Host "Cleanup completed." -ForegroundColor Yellow
}
