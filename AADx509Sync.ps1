###############################################################################################
#
# AADx509Sync
# by tcppapi - Free to use or modify, just please leave credit here :-)
#
# ---About---
# This script syncs AAD devices, users, and groups with on-prem objects to allow for 
#   certificate authentication using Intune, ADCS, AAD Connect, and NPS. You can use the  
#   resulting objects in the DeviceOU and '{name}_AADx509Sync' groups in GroupsOU to create 
#   policies in NPS.
#
# Certificates MUST include "host/{{AAD_Device_ID}}" for devices and "{{UserPrincipalName}}" 
#   for users in UPN attribute of certificate's SAN to be synced
#
# ---Requirements---
#   1. ADCS as your CA/PKI issuing certificates via Intune PKCS or SCEP profiles
#   2. Device writeback enabled via Azure AD Connect
#   3. Group writeback v2 enabled via Azure AD Connect w/ DN as display name enabled
#   4. Disable SAN to UPN mapping on all DCs
#   5. ActiveDirectory and PSPKI PowerShell modules (recommended to run on DCs)
#
# ---Settings---
#   
#   !!NOTE: Make sure you check your DeviceOU is not enabled for syncing in AAD Connect, or !!
#   !! all AADx509 computer objects will be sycned back to Azure and script will stop!!
#   $DeviceOU - The OU the script will use for newly made AADx509 computer objects
#
#   $UserMappingEnabled - Maps AD users to certificates using matching UserPrincipalName user 
#     attribute and SAN UPN certificate attribute (pre-existing/hybrid users only)
#   $GroupOU - The OU AAD Connect group writeback is configured to use, and where _AADx509Sync
#     groups will be created
#   $DefaultGroup - The group all new AADx509 computer objects will have set as their primary, 
#     and the 'Domain Computers' group removed
#   $LogFile - Where the script logs will be stored on each run
#   $LogMaxLines - Max number of lines in log file, 10000 lines = ~1MB, not setting value will 
#     allow log file to infinitely grow
#
# The DefaultGroup variable only applies on computer object creation and will not update during
#   subsequent runs. You must delete AADx509 computer objects and re-run script for re-creation.
#
# ---Uninstalling/removing---
# Because the script is stateless, removing is easy. Simply stop running the script and delete
#   the DeviceOU and all objects within, and delete the _AADx509Sync groups.
#   Note: Users mapped to certificates using the UserMappingEnabled option will still be mapped
# 
# For more information on how this script works, please see this link
#   https://github.com/tcppapi/AADx509Sync
#
###############################################################################################

$UserMappingEnabled = "TRUE"
$GroupOU = "OU=GroupWritebackv2,DC=my,DC=domain,DC=com"
$DeviceOU = "OU=AADx509Sync,DC=my,DC=domain,DC=com"
$DefaultGroup = "_AADx509Sync Default Group"
$LogFile = "C:\ProgramData\AADx509Sync.log"
$LogMaxLines = "20000"

#############################################################################################################################################################
function Write-Log{
    param(
        [string]$Severity,
        [string]$Message,
        [switch]$Exit
    )
    $Date = Get-Date
    Get-Date $Date -f "MM/dd/yyyy HH:mm:ss" | Out-Null
    $Date = $Date.ToUniversalTime().ToString("MM/dd/yyyy HH:mm:ss")
    if($LogFile){
        if(!(Test-Path $LogFile)){
            try { Write-Output $NULL | Out-File -Append -FilePath $LogFile -Encoding utf8 }
            catch { 
                $BadLogFile = $LogFile
                $LogFile = "C:\ProgramData\AADx509Sync.log"
                Write-Output "[$Date] [Error]   Log file '$BadLogFile' could not be validated, using default..." | Out-File -Append -FilePath $LogFile -Encoding utf8
            }
        }
    }
    if(!$LogFile){
        $LogFile = "C:\ProgramData\AADx509Sync.log"
        Write-Output "[$Date] [Error]   No log file specified, using default..." | Out-File -Append -FilePath $LogFile -Encoding utf8
    }
    if($Message){
        if(!$Severity) { $Severity = "N/A"}
        Write-Output "[$Date] [$Severity]   $Message" | Out-File -Append -FilePath $LogFile -Encoding utf8
    }
        if($LogMaxLines){
            $LogMaxLines = $LogMaxLines -1
            $c = Get-Content $LogFile -Tail $LogMaxLines -ReadCount 0 
            $c | Out-File -FilePath $LogFile -Encoding utf8
        }
    if($Exit){
        Write-Output "[$Date] [$Severity]   Exiting..." | Out-File -Append -FilePath $LogFile -Encoding utf8
        if($Severity -eq "Error"){ exit 1 }
        else{ exit 0 }
    }
}
#############################################################################################################################################################
Write-Log -Severity "Info" -Message "-----SCRIPT STARTED-----"
Write-Log -Severity "Info" -Message "<SETUP> Validating variables..."
if(![AdsI]::Exists("LDAP://$GroupOU")){
    Write-Log -Severity "Error" -Message "<SETUP> Error validating GroupOU, check the OU exists"
    Write-Log -Severity "Error" -Exit
}

if(![AdsI]::Exists("LDAP://$DeviceOU")){
    Write-Log -Severity "Error" -Message "<SETUP> Error validating DeviceOU, check the OU exists"
    Write-Log -Severity "Error" -Exit
}
try { 
    if(!(Get-ADGroup -Filter "Name -Like `"$DefaultGroup`"")){ 
        Write-Log -Severity "Info" -Message "<SETUP> Group '$DefaultGroup' not found, creating in device OU..." 
        New-ADGroup -Path $DeviceOU -Name $DefaultGroup -GroupCategory Security -GroupScope Global 
    } 
}
catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
        Write-Log -Severity "Error" -Message "<SETUP> Error creating default device group"
        Write-Log -Severity "Error" -Exit 
}
Write-Log -Severity "Info" -Message "<SETUP> Success"
Write-Log -Severity "Info" -Message "<SETUP> GroupOU set to '$GroupOU'"
Write-Log -Severity "Info" -Message "<SETUP> DeviceOU set to '$DeviceOU'"
Write-Log -Severity "Info" -Message "<SETUP> DefaultGroup set to '$DefaultGroup'"
Write-Log -Severity "Info" -Message "<SETUP> LogFile set to '$LogFile'"
Write-Log -Severity "Info" -Message "<SETUP> LogMaxLines set to '$LogMaxLines'"
#############################################################################################################################################################
Write-Log -Severity "Info" -Message "<SETUP> Importing required modules..."
try{
    Import-Module ActiveDirectory
    Import-Module PSPKI
    $Modules = Get-Module
    if(!($Modules.Name -Contains "ActiveDirectory") -or !($Modules.Name -Contains "PSPKI")) {
        Write-Log -Severity "Error" -Message "<SETUP> Error detecting required modules after import - ensure 'ActiveDirectory' and 'PSPKI' modules are installed on your system"
        Write-Log -Severity "Error" -Exit
    }
}
catch{  
    Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
    Write-Log -Severity "Error" -Message "<SETUP> Error importing required modules - ensure 'ActiveDirectory' and 'PSPKI' modules are installed on your system"
    Write-Log -Severity "Error" -Exit 
}
Write-Log -Severity "Info" -Message "<SETUP> Success"
#############################################################################################################################################################
Write-Log -Severity "Info" -Message "<DEVICE> Starting AD msDS-Device to computer object sync..."
try{
    $msDSDevs = Get-ADObject -Filter 'objectClass -eq "msDS-Device"' -Properties DisplayName
    $AADx509Devs = Get-ADComputer -Filter '(objectClass -eq "computer")' -SearchBase $DeviceOU -Properties servicePrincipalName
}
catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
        Write-Log -Severity "Error" -Message "<DEVICE> Error getting AD objects for device sync"
        Write-Log -Severity "Error" -Exit  
}
foreach($dev in $msDSDevs){
    $guid = $dev.Name
    $AADx509Dev = $AADx509Devs |? ServicePrincipalName -eq "host/$guid"
    try{

	# DO NOT REMOVE THIS PORTION FROM THE SCRIPT OR DEVICE OBJECTS MAY BE INFINITELY CREATED BETWEEN AD AND AAD
	$detect = $AADx509Devs |? ObjectGUID -eq $guid
        if($detect){ 
            Write-Log -Severity "Error" -Message "<DEVICE> AZURE AD CONNECT SYNC LOOP DETECTED ON AAD DEVICE ID '$guid'"
            Write-Log -Severity "Error" -Message "<DEVICE> Verify DeviceOU variable is not synced by Azure AD Connect and re-run the script"
            Write-Log -Severity "Error" -Exit
        }
	# DO NOT REMOVE THIS PORTION FROM THE SCRIPT OR DEVICE OBJECTS MAY BE INFINITELY CREATED BETWEEN AD AND AAD

        if(!$AADx509Dev){
            $guid -match "^([0-9a-fA-F]{8})(-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)([0-9a-fA-F]{11})([0-9a-fA-F])$" | Out-Null
            $SAMAccountName = "$($matches[1])"+"$($matches[3])"+"$"
            Write-Log -Severity "Info" -Message "<DEVICE> AADx509 computer object '$guid' not found for matching msDS-Device object, creating ADDx509 computer object..."
            $New = New-ADComputer -Name $guid -ServicePrincipalNames "host/$guid" -SAMAccountName $SAMAccountName -Description "$($dev.DisplayName)" -Path $DeviceOU -AccountPassword $NULL -PasswordNotRequired $False -PassThru
            Add-ADGroupMember -Identity $DefaultGroup -Members $New 
            $Group = Get-ADGroup $DefaultGroup -Properties @("primaryGroupToken")
            Get-ADComputer $New | Set-ADComputer -Replace @{primaryGroupID=$Group.primaryGroupToken}
            Remove-ADGroupMember -Identity "Domain Computers" -Members $New -Confirm:$false
        }
    }
    catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
            Write-Log -Severity "Error" -Message "<DEVICE> Error checking for AADx509 computer object '$guid'"
    }
}
foreach($dev in $AADx509Devs){
    try{
        if(!($msDSDevs |? Name -Like $dev.Name)){
            Write-Log -Severity "Info" -Message "<DEVICE> msDS-Device object '$guid' not found for matching AADx509 computer object, deleting AADx509 computer object..."
            Get-ADComputer -Filter "Name -eq `"$($dev.Name)`"" | Remove-ADComputer -Confirm:$false
        }
    }
    catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
            Write-Log -Severity "Error" -Message "<DEVICE> Error checking for AD msDS-Device object '$guid'"
    }
}
Write-Log -Severity "Info" -Message "<DEVICE> AD msDS-Device to computer object sync completed"
################################################################################################################################################################
Write-Log -Severity "Info" -Message "<CERT> Starting certificate hash sync..."
Clear-Variable IssuedCerts -ErrorAction SilentlyContinue
try{
    foreach($CAHost in (Get-CertificationAuthority).ComputerName){
        Write-Log -Severity "Info" -Message "<CERT> Getting all issued certs from '$CAHost'..."
        $IssuedRaw = Get-IssuedRequest -CertificationAuthority $CAHost -Property RequestID,ConfigString,CommonName,CertificateHash,RawCertificate
        $IssuedCerts += $IssuedRaw | Select-Object -Property RequestID,ConfigString,CommonName,CertificateHash,@{
            name='SANPrincipalName';
            expression={
                ($(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,[Convert]::FromBase64String($_.RawCertificate))).Extensions | `
                ? {$_.Oid.FriendlyName -eq "Subject Alternative Name"}).Format(0) -match "^(.*)(Principal Name=)([^,]*)(,?)(.*)$" | Out-Null;
                if($matches.GetEnumerator() |? Value -eq "Principal Name=") {
                    $n = ($matches.GetEnumerator() |? Value -eq "Principal Name=").Name +1;
                    $matches[$n]
                }
            }
        }
    }
}
catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
        Write-Log -Severity "Error" -Message "<CERT> Error getting issued certificates from ADCS servers"
        Write-Log -Severity "Error" -Exit  
}
try { 
    Write-Log -Severity "Info" -Message "<CERT> Getting AD objects..."
    $AADx509Devs = Get-ADComputer -Filter '(objectClass -eq "computer")' -SearchBase $DeviceOU -Property Name,altSecurityIdentities
    if($UserMappingEnabled -eq "TRUE"){ $ADUsers = Get-ADUser -Filter "(UserPrincipalName -Like '*')" -Property Name,altSecurityIdentities }
}
catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
        Write-Log -Severity "Error" -Message "<CERT> Error getting AADx509 computers for hash sync"
        Write-Log -Severity "Error" -Exit  
}
foreach($dev in $AADx509Devs){
    $certs = $IssuedCerts |? SANPrincipalName -Like "host/$($dev.Name)"
    if($certs) {
        $a = @()
        $b = @()
        foreach($cert in $certs){
            $hash = ($cert.CertificateHash) -Replace '\s',''
            $a += "X509:<SHA1-PUKEY>$hash"
            $b += "($($cert.ConfigString)-$($cert.RequestID))$hash"
        }
        [Array]::Reverse($a)
        try{
            if(!((-Join $dev.altSecurityIdentities) -eq (-Join $a))){
                [Array]::Reverse($a)
                $ht = @{"altSecurityIdentities"=$a}
                Write-Log -Severity "Info" -Message "<CERT> Mapping AADx509 computer '$($dev.Name)' to (CA-RequestID) SHA1-hash '$($b -Join ',')'"
                Get-ADComputer -Filter "(servicePrincipalName -like 'host/$($dev.Name)')" | Set-ADComputer -Add $ht
            }
        }
        catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
                Write-Log -Severity "Error" -Message "<CERT> Error mapping AADx509 computer object '$($dev.Name)' to (CA-RequestID) SHA1-hash '$($b -Join ',')'"
        }
    }
}
if($UserMappingEnabled -eq "TRUE"){
    foreach($user in $ADUsers){
        $certs = $IssuedCerts |? SANPrincipalName -Like "$($user.UserPrincipalName)"
        if($certs) {
            $a = @()
            $b = @()
            foreach($cert in $certs){
                $hash = ($cert.CertificateHash) -Replace '\s',''
                $a += "X509:<SHA1-PUKEY>$hash"
                $b += "($($cert.ConfigString)-$($cert.RequestID))$hash"
            }
            [Array]::Reverse($a)
            try{
                if(!(-Join $user.altSecurityIdentities) -eq (-Join $a)){
                    [Array]::Reverse($a)
                    $ht = @{"altSecurityIdentities"=$a}
                    Write-Log -Severity "Info" -Message "<CERT> Mapping AD user '$($user.UserPrincipalName)' to (CA-RequestID) SHA1-hash '$($b -Join ',')'"
                    $user | Set-ADUser -Add $ht
                }
            }
            catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
                    Write-Log -Severity "Error" -Message "<CERT> Error mapping AD user object '$($user.UserPrincipalName)' to (CA-RequestID) SHA1-hash '$($b -Join ',')'"
            }
        }
    }
}
Write-Log -Severity "Info" -Message "<CERT> Certificate hash sync completed"
#############################################################################################################################################################
Write-Log -Severity "Info" -Message "<GROUP> Starting group sync..."
try{
    $WBGroups = Get-ADGroup -Filter * -SearchBase $GroupOU -Properties Description |? Name -Match "^(.*)(_[0-9a-fA-F]{12})$"
    $AADx509Groups = Get-ADGroup -Filter * -SearchBase $GroupOU |? Name -Match "^(.*)(_AADx509Sync)$"
    $ADObjects = Get-ADObject -Filter '(objectClass -eq "msDS-Device" -or objectClass -eq "user" -or objectClass -eq "computer")' -Properties MemberOf,servicePrincipalName
}
catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
        Write-Log -Severity "Error" -Message "<GROUP> Error getting AD objects for group sync"
        Write-Log -Severity "Error" -Exit  
}
foreach($group in $WBGroups){
    Write-Log -Severity "Info" -Message "<GROUP> Syncing writeback group '$($group.Name)'"
    $group.Name -Match "^(.*)(_[0-9a-fA-F]{12})$" | Out-Null
    $AADx509GrpName = "$($matches[1])_AADx509Sync"
    if(!($AADx509Groups |? Name -like $AADx509GrpName)){
        Write-Log -Severity "Info" -Message "<GROUP> Creating AADx509Group '$AADx509GrpName' for syncing '$($group.Name)'"
        try{
            New-ADGroup -Path $GroupOU -Name $AADx509GrpName -Description $group.Description -GroupCategory Security -GroupScope Global 
        }
        catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
                Write-Log -Severity "Error" -Message "<GROUP> Error creating group $AADx509GrpName, skipping group..." 
                return
        }
    }
    $SyncGroup = Get-ADGroup -Identity $AADx509GrpName
    $WBGrpMembers = $ADObjects |? MemberOf -Like $group.DistinguishedName
    $SyncGrpMembers = $ADObjects |? MemberOf -Like $SyncGroup.DistinguishedName
    foreach($ADObject in $WBGrpMembers){
        if(!($SyncGrpMembers.Name -contains $ADObject.Name)){
            Write-Log -Severity "Info" -Message "<GROUP> Added AD object '$($ADObject.Name)' to AADx509Group '$($SyncGroup.Name)'"
            try{
                switch($ADObject.objectClass) {
                    "msDS-Device" { Add-AdGroupMember -Identity $SyncGroup.Name -Members $(Get-ADComputer -Filter "Name -Like `"$($ADObject.Name)`"") }
                    "computer" { Add-AdGroupMember -Identity $SyncGroup.Name -Members $(Get-ADComputer -Filter "Name -Like `"$($ADObject.Name)`"") }
                    "user" { Add-AdGroupMember -Identity $SyncGroup.Name -Members $(Get-ADUser -Filter "Name -Like `"$($ADObject.Name)`"") }
                }
            }
            catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
                    Write-Log -Severity "Error" -Message "<GROUP> Error adding AD object '$($ADObject.Name)' to AADx509Group '$($SyncGroup.Name)'" 
            }
        }
    }
    foreach($ADObject in $SyncGrpMembers){
        if(!($WBGrpMembers.Name -contains $ADObject.Name)){
            Write-Log -Severity "Info" -Message "<GROUP> Removing ADobject '$($ADObject.Name)' from group '$($SyncGroup.Name)'"
            try{
                switch($ADObject.objectClass) {
                    "msDS-Device" { Remove-AdGroupMember -Identity $SyncGroup.Name -Members $(Get-ADComputer -Filter "Name -Like `"$($ADObject.Name)`"") -Confirm:$false }
                    "computer" { Remove-AdGroupMember -Identity $SyncGroup.Name -Members $(Get-ADComputer -Filter "Name -Like `"$($ADObject.Name)`"") -Confirm:$false }
                    "user" { Remove-AdGroupMember -Identity $SyncGroup.Name -Members $(Get-ADUser -Filter "Name -Like `"$($ADObject.Name)`"") -Confirm:$false }
                }
            }
            catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
                    Write-Log -Severity "Error" -Message "<GROUP> Error removing AD object '$($ADObject.Name)' from AADx509Group '$($SyncGroup.Name)'" 
            }
        }
    }
}
foreach($group in $AADx509Groups){
    $group.Name -match "^(.*)(_AADx509Sync)$" | Out-Null
    if(!($WBGroups |? Name -Match "^($($matches[1]))(_[0-9a-fA-F]{12})$")){
        Write-Log -Severity "Info" -Message "<GROUP> Writeback group for '$($matches[1])' not found, deleteing AADx509Group '$($group.Name)'"
        try{
            Remove-ADGroup -Identity $group.Name -Confirm:$false
        }
        catch{  Write-Log -Severity "Error" -Message "$($_.Exception.Message)" 
                Write-Log -Severity "Error" -Message "<GROUP> Error removing AD AADx509Group '$($group.Name)'"
        }
    }
}
Write-Log -Severity "Info" -Message "<GROUP> Group sync completed"
Write-Log -Severity "Info" -Message "-----SCRIPT COMPLETED-----" -Exit
#############################################################################################################################################################
