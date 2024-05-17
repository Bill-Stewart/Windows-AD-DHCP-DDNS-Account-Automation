<!-- omit in toc -->
# Update DHCP Dynamic DNS Registration Credentials Automatically Using a Group Managed Service Account (gMSA)

In an Active Directory domain using AD-integrated DNS zones, the general recommendation is to configure the DHCP server to use specify an unprivileged domain account to register dynamic DNS records on behalf of DHCP clients. Currently this account must be a domain user account and cannot be a Group Managed Service Account (gMSA).

While it is true that the DHCP dynamic DNS registration account cannot be a gMSA, we can work around this limitation by creating a gMSA and a scheduled task that runs a [script](https://gist.github.com/Bill-Stewart/fd588bc4fd42a9cd6eaece83e465fcdc) that performs the following actions:

1. Reset the dynamic DNS registration account's password to a long, random password
2. Set the dynamic DNS registration account's credentials in all authorized DHCP servers

This solution is based on Windows PowerShell on a recent Windows server version (Windows Server 2012 or later) and uses the following modules:

* ActiveDirectory
* DhcpServer

On a Windows server, you can meet these prerequisites by installing the following feature administration tools found in Remote Server Administration
Tools:

* AD DS and AD LDS Tools: **Active Directory Module for Windows PowerShell**
* **DHCP Server Tools**

> **NOTE:** This solution assumes you have sufficient permissions in a domain to create the necessary objects. If you are not able to log on with an account that's a member of the `Domain Admins` security group, you will need to coordinate this solution with an administrator who has sufficient permissions.

<!-- omit in toc -->
# Solution Summary

- [Create and Populate a Domain Security Group](#create-and-populate-a-domain-security-group)
- [Create an Unprivileged Domain User Account for DHCP Dynamic DNS Registrations](#create-an-unprivileged-domain-user-account-for-dhcp-dynamic-dns-registrations)
- [Create a Key Distribution Service (KDS) Root Key if Needed](#create-a-key-distribution-service-kds-root-key-if-needed)
- [Create the Group Managed Service Account (gMSA)](#create-the-group-managed-service-account-gmsa)
- [Add the gMSA to the DHCP Administrators Group](#add-the-gmsa-to-the-dhcp-administrators-group)
- [Grant the gMSA Permission to Reset the Password of the Domain User Account](#grant-the-gmsa-permission-to-reset-the-password-of-the-domain-user-account)
- [Create a Scheduled Task to Run the Script](#create-a-scheduled-task-to-run-the-script)

## Create and Populate a Domain Security Group

Create a domain security group (e.g., `DHCP Dynamic DNS Reset`) and add the computers to the group that will be allowed to use the Group Managed Service Account (gMSA). PowerShell:

```
New-ADGroup "DHCP Dynamic DNS Reset" Global -SamAccountName "DHCPDynamicDNSReset" -Path "OU=Groups,DC=fabrikam,DC=local" -Description "Computers permitted to use the DHCPDynDNSReset gMSA" -PassThru | Add-ADGroupMember -Members 'SERVER01$'
```

This example creates a domain security group named `DHCP Dynamic DNS Reset` and adds the computer account `SERVER01` to it. (The trailing `$` at the end of the computer account name is required.) Customize the group name, sAMAccountName, path, etc. as appropriate for your environment.

Note that group membership changes aren't reflected for computers until their Kerberos tickets expire. To force an immediate group membership update on a computer, do one of the following:

1. Restart the computer, or
2. Run the following command line from an elevated PowerShell window on the affected computer:

        klist -li 0x3e7 purge;gpupdate /target:computer

## Create an Unprivileged Domain User Account for DHCP Dynamic DNS Registrations

Create an unprivileged domain user account (PowerShell):

```
New-ADUser "DHCPDynDNS" -Description "DHCP servers use this account to register dynamic DNS records on behalf of DHCP clients."
```

Use whatever account name is appropriate for your environment. After creating the user account, set a temporary random password, remove the **User must change password at next logon** requirement, and enable the account. This account will have permissions over all dynamic DNS records managed by DHCP servers.

> **NOTE:** It is important that this account should not be a member of any privileged security groups.

## Create a Key Distribution Service (KDS) Root Key if Needed

First, determine if any KDS root keys exist (PowerShell):

```
Get-KdsRootKey
```

If the `Get-KdsRootKey` cmdlet returns no output, then create a KDS root key if one doesn't exist (PowerShell):

```
Add-KdsRootKey
```

## Create the Group Managed Service Account (gMSA)

The following is a PowerShell script that creates the gMSA. Customize the variables at the top of the script as appropriate for your environment.

Note the following for the script:

* The gMSA name can be up to 15 characters in length.
* Use the sAMAccountName attribute of the security group for the `$gMSAGroupAllowed` variable.

```
#requires -version 3
#requires -RunAsAdministrator

# Customize these variables as appropriate
$gMSAName = "DHCPDynDNSReset"
$gMSAGroupAllowed = "DHCPDynamicDNSReset"

Import-Module ActiveDirectory -ErrorAction Stop

$domainDNSName = (Get-ADDomain).DNSRoot
if ( $null -eq $domainDNSName ) {
  return
}

$params = @{
  "Name" = $gMSAName
  "DnsHostName" = "{0}.{1}" -f $gMSAName,$domainDNSName
  "Description" = "Resets DHCP dynamic DNS registration credentials on DHCP servers."
  "TrustedForDelegation" = $false
  "ManagedPasswordIntervalInDays" = 30  # Can only be set at creation
  "PrincipalsAllowedToRetrieveManagedPassword" = $gMSAGroupAllowed
  "PassThru" = $true
}
New-ADServiceAccount @params
```

## Add the gMSA to the DHCP Administrators Group

The gMSA needs to be a member of the `DHCP Administrators` group in the domain in order to be able to set DHCP dynamic DNS credentials on DHCP servers. PowerShell command example:

```
Get-ADServiceAccount "DHCPDynDNSReset" | Add-ADPrincipalGroupMembership -MemberOf "DHCP Administrators"
```

Customize the gMSA account name as appropriate for your environment.

## Grant the gMSA Permission to Reset the Password of the Domain User Account

The following is a PowerShell script that grants the gMSA permission to reset the password of the domain user account. Customize the account names at the top of the script as appropriate for your environment.

```
#requires -version 3
#requires -RunAsAdministrator

# Customize these account names as appropriate
$gMSAName = "DHCPDynDNSReset"
$domainUserAccountName = "DHCPDynDNS"

$identityReference = (Get-ADServiceAccount $gMSAName).SID.Translate([Security.Principal.NTAccount])
if ( $null -eq $identityReference ) {
  return
}

$resetPassword = [Guid] "00299570-246d-11d0-a768-00aa006e0529"

$accessRule = New-Object DirectoryServices.ActiveDirectoryAccessRule(
  $identityReference,                                           # IdentityReference
  [DirectoryServices.ActiveDirectoryRights]::ExtendedRight,     # ActiveDirectoryRights
  [Security.AccessControl.AccessControlType]::Allow,            # AccessControlType
  $resetPassword,                                               # ObjectType
  [DirectoryServices.ActiveDirectorySecurityInheritance]::None  # InheritanceFlags
)

$searcher = [ADSISearcher] "(&(objectClass=user)(sAMAccountName=$domainUserAccountName))"
$searchResult = $searcher.FindOne()
if ( $null -eq $searchResult ) {
  throw "Domain user account '$domainUserAccountName' was not found."
}
$adUser = $searchResult.GetDirectoryEntry()
$adUser.ObjectSecurity.AddAccessRule($accessRule)
$adUser.CommitChanges()
```

## Create a Scheduled Task to Run the Script

The following PowerShell script configures the [**Reset-DhcpServerDnsCredential.ps1**](https://gist.github.com/Bill-Stewart/fd588bc4fd42a9cd6eaece83e465fcdc) script to run daily at 0300 using the gMSA. Run this script on the computer where you want to create the scheduled task (customized as appropriate for your environment).

```
#requires -RunAsAdministrator
#requires -version 3

# Customize these variables as appropriate
$gMSAName = "DHCPDynDNSReset"
$domainUserAccountName = "DHCPDynDNS"
$delayAfterPasswordReset = 5  # Seconds
$scriptFileName = "Reset-DhcpServerDnsCredential.ps1"
$scriptFilePath = "C:\Scripts\ScheduledTasks\Reset-DhcpServerDnsCredential"
$scheduledTaskName = [IO.Path]::GetFileNameWithoutExtension($scriptFileName)
$scheduledTaskPath = "\"

# Reusable hashtable for parameter splatting
$params = @{}

# Scheduled task action
$params.Clear()
$params["Execute"] = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "WindowsPowerShell\v1.0\powershell.exe"
$params["Argument"] = "-ExecutionPolicy Bypass -NonInteractive -NoProfile -File ""$scriptFileName"" $domainUserAccountName -Delay $delayAfterPasswordReset"
$params["WorkingDirectory"] = $scriptFilePath
$taskAction = New-ScheduledTaskAction @params

# Scheduled task trigger
$params.Clear()
$params["Daily"] = $true
$params["At"] = [DateTime]::Today.AddHours(3)
$taskTrigger = New-ScheduledTaskTrigger @params

# Scheduled task principal
$params.Clear()
$params["UserID"] = "{0}$" -f $gMSAName  # Trailing '$' required for gMSA
$params["LogonType"] = "Password"
$params["Id"] = "Author"
$taskPrincipal = New-ScheduledTaskPrincipal @params

# Create scheduled task
$params.Clear()
$params["Action"] = $taskAction
$params["Trigger"] = $taskTrigger
$params["Principal"] = $taskPrincipal
$task = New-ScheduledTask @params

# Register scheduled task
$params.Clear()
$params["TaskName"] = $scheduledTaskName
$params["TaskPath"] = $scheduledTaskPath
$params["Action"] = $taskAction
$params["Trigger"] = $taskTrigger
$params["Principal"] = $taskPrincipal
$params["Description"] = "Resets DHCP server dynamic DNS registration credentials on all authorized DHCP servers."
Register-ScheduledTask @params
```
