#########################################################################
# Test script to check Windows Secure Boot Certificates and boot binaries
# Version 1.5
#########################################################################
# References for the process:
# https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
# https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e
# https://support.microsoft.com/en-us/topic/windows-devices-for-businesses-and-organizations-with-it-managed-updates-e2b43f9f-b424-42df-bc6a-8476db65ab2f
# https://techcommunity.microsoft.com/blog/windows-itpro-blog/updating-microsoft-secure-boot-keys/4055324
# https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69
# https://learn.microsoft.com/en-us/answers/questions/2153845/windows-11-double-checking-updated-microsoft-secur
# https://support.microsoft.com/en-gb/topic/kb5036210-deploying-windows-uefi-ca-2023-certificate-to-secure-boot-allowed-signature-database-db-a68a3eae-292b-4224-9490-299e303b450b
#
# Reference for Secure Boot
# https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process
# https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot?source=recommendations
#
# Creator(s) / Kudos:
# Main Script: Joerg Wunderlich
# Function (Get-UEFISecureBootCerts): Michael Niehaus (Get all UEFI functions https://www.powershellgallery.com/packages/UEFIv2/3.0/Content/UEFIv2.psm1) also see https://oofhours.com
#
# Script need to be executed as admin!

# Exit Codes: 

########################################################
Start-Transcript -Path $env:windir\temp\Check-Secure-Boot-Certs.log -Append
$scriptVersion = "1.5"
$currentRunTime = Get-Date
$debuggingEnabled = $true  # will control further debug output
$developmentMode = $true    # will allow admins to use different Models CSV file! (test & release process)

###############################################################################################################
# Variable for logging NEED TO BE FILLED FOR EVERY COMPANY WITH THEIR OWN VALUES! KEEP THEM SECRET!!!
$Global:azureLogAnalyticsWorkspaceID = "39090783-b5d3-4565-9e33-d8250294b2b7" # Set Azure Log Analytics Workspace ID (unique for every company)
$Global:azureLogAnalyticsWorkspaceKey = "wJut4+GFKYDdg3kNBCjcvu5U1JgheXPs5dt2ZwWFhY2Kzdr5hP8goiYb0bLmuY+EAK+lhADb++KGvSSsPi/0ww==" # Set Azure Log Analytics Workspace Key (unique for every company)
# First logging and check if we need to run again (for cost savings in Azure Log Analytics the count of executions is throttled)
$scriptLastRunInterval = 6  # every x days the script get re-executed and generate upload data. 
#This lowers the cost of Azure Log Analytics as long as you do not want to see daily data.
###############################################################################################################

########################################################

# First loading public available functions

# -----------------------------------------------------------------------------
# UEFI PowerShell Functions v3 (here limited to Secure Boot certs)
# Author: Michael Niehaus
# Description:
# A sample function to show how to extract with UEFI certificates using
# PowerShell. Provided as-is with no support. See https://oofhours.com
# for related information.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# One-time initialization
# -----------------------------------------------------------------------------

$definition = @'
 using System;
 using System.Runtime.InteropServices;
 using System.Text;
   
 public class UEFINative
 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 GetFirmwareEnvironmentVariableA(string lpName, string lpGuid, [Out] Byte[] lpBuffer, UInt32 nSize);
 
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 SetFirmwareEnvironmentVariableA(string lpName, string lpGuid, Byte[] lpBuffer, UInt32 nSize);
 
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtEnumerateSystemEnvironmentValuesEx(UInt32 function, [Out] Byte[] lpBuffer, ref UInt32 nSize);
 }
'@

$uefiNative = Add-Type $definition -PassThru

# Global constants
$global:UEFIGlobal = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
$global:UEFIWindows = "{77FA9ABD-0359-4D32-BD60-28F4E78F784B}"
$global:UEFISurface = "{D2E0B9C9-9860-42CF-B360-F906D5E0077A}"
$global:UEFITesting = "{1801FBE3-AEF7-42A8-B1CD-FC4AFAE14716}"
$global:UEFISecurityDatabase = "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}"

function Get-UEFISecureBootCerts {
    <#
.SYNOPSIS
    Gets details about the UEFI Secure Boot-related variables.
 
.DESCRIPTION
    Gets details about the UEFI Secure Boot-related variables (db, dbx, kek, pk).
 
.PARAMETER Variable
    The UEFI variable to retrieve (defaults to db)
 
.EXAMPLE
    Get-UEFISecureBootCerts
 
.EXAMPLE
    Get-UEFISecureBootCerts -db
 
.EXAMPLE
    Get-UEFISecureBootCerts -dbx
 
.LINK
    https://oofhours.com/2021/01/19/uefi-secure-boot-who-controls-what-can-run/
 
#Requires -Version 2.0
#>        
    [cmdletbinding()]
    Param (
        [Parameter()]
        [String]$Variable = "db"
    )
    BEGIN {
        $EFI_CERT_X509_GUID = [guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
        $EFI_CERT_SHA256_GUID = [guid]"c1c41626-504c-4092-aca9-41f936934328"
    }
    PROCESS {
        $db = (Get-SecureBootUEFI -Name $variable).Bytes

        $o = 0

        while ($o -lt $db.Length) {
            $guidBytes = $db[$o..($o + 15)]
            [Guid] $guid = [Byte[]]$guidBytes
            $signatureListSize = [BitConverter]::ToUInt32($db, $o + 16)
            $signatureHeaderSize = [BitConverter]::ToUInt32($db, $o + 20)
            $signatureSize = [BitConverter]::ToUInt32($db, $o + 24)
            $signatureCount = ($signatureListSize - 28) / $signatureSize 
            # Write-Host "GUID: $guid"
            # Write-Host "SignatureListSize: $signatureListSize"
            # Write-Host "SignatureHeaderSize: $signatureHeaderSize"
            # Write-Host "SignatureSize: $signatureSize"
            # Write-Host "SignatureCount: $signatureCount"

            $so = $o + 28
            1..$signatureCount | % {

                $ownerBytes = $db[$so..($so + 15)]
                [Guid] $signatureOwner = [Byte[]]$ownerBytes
                # Write-Host "SignatureOwner: $signatureOwner"

                if ($guid -eq $EFI_CERT_X509_GUID) {
                    $certBytes = $db[($so + 16)..($so + 16 + $signatureSize - 1)]
                    if ($PSEdition -eq "Core") {
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate]::new([Byte[]]$certBytes)
                    }
                    else {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $cert.Import([Byte[]]$certBytes)
                    }
                    [PSCustomObject] @{
                        SignatureOwner   = $signatureOwner
                        SignatureSubject = $cert.Subject
                        Signature        = $cert
                        SignatureType    = $guid
                    }
                }
                elseif ($guid -eq $EFI_CERT_SHA256_GUID) {
                    $sha256hash = ([Byte[]] $db[($so + 16)..($so + 48 - 1)] | % { $_.ToString('X2') } ) -join ''
                    [PSCustomObject] @{
                        SignatureOwner = $signatureOwner
                        Signature      = $sha256Hash
                        SignatureType  = $guid
                    }
                }
                else {
                    Write-Warning "Unable to decode EFI signature type: $guid"
                }

                $so = $so + $signatureSize
            }

            $o = $o + $signatureListSize
        }

    }
}

# General script related functions (are pascal case)

# Functions (are pascal case)
function Get-FirstAvailableDrive {
    # Define excluded drive letters
    $excluded = @('A', 'B', 'C', 'D')

    # Get currently used drive letters
    $used = Get-PSDrive -PSProvider 'FileSystem' | Select-Object -ExpandProperty Name

    # Generate all possible drive letters from E to Z
    $all = [char[]](69..90) | ForEach-Object { [string]$_ }

    # Find the first free drive letter not in use and not excluded
    $firstavailabledrive = $all | Where-Object { $_ -notin $used -and $_ -notin $excluded } | Select-Object -First 1

    # Output result
    if ($firstavailabledrive) {
        $script:debugAvailableFirstDrive = $firstavailabledrive
        Return $firstavailabledrive
    }
    else {
        $script:debugAvailableFirstDriveError = "No available drive letters found. Exiting (0)!"
        Write-Output $script:debugAvailableFirstDriveError 
        Send-LogDebugMessage -Table Error-Debug -Message $script:debugAvailableFirstDriveError 
        Exit 0
    }
}

function Test-AdminRole {
    
    $isAdmin = $null
    $isSystem = $null
    $isElevated = $null

    # Get current user
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    # Create a WindowsPrincipal object
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)

    # Check if user is in Administrators group or System
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $currentUser.Name -eq "NT AUTHORITY\SYSTEM"

    if (($isAdmin -eq $true) -or ($isSystem -eq $true)) {
        $isElevated = $true
    }

    # Output result
    if ($isElevated) {
        $script:debugAdminRole = $true
        Write-Host "User is a member of the local Administrators group or System. Continuing ..." -ForegroundColor Green        
    }
    else {
        $script:debugAdminRoleError = "User is NOT a member of the local Administrators group or System. Exiting (0)!"
        Write-Host $script:debugAdminRoleError -ForegroundColor Red
        Send-LogDebugMessage -Table Error-Debug -Message $script:debugAdminRoleError
        Exit 0
    }
}

function Get-CertInfo {
    param (
        [string]$FilePath,
        [string]$OldCert,
        [string]$NewCert,
        [string]$Description
    )
    $script:debugCertCounter = 0 # 0 in the log indicates that all bootloader files could be successfully checked. If this is not 0 then check the logs!
    try {
        $cert = Get-PfxCertificate -FilePath $FilePath
        $certIssuer = $cert.Issuer
        $certExpirationDate = $cert.GetExpirationDateString()
        Write-Host "$Description - Certificate found: $certIssuer"
        Write-Host "$Description - Expiration date  : $certExpirationDate"
        if ($certIssuer -eq $OldCert) {
            Write-Warning "$Description still signed with old Windows Production certificate (PCA 2011 Version)"
        }
        elseif ($certIssuer -eq $NewCert) {
            Write-Host "SUCCESS: $Description now signed with new KEK certificate (UEFI CA 2023 Version)" -ForegroundColor Green
        }
        else {
            Write-Warning "$Description certificate issuer is unknown or not matched!"
            $script:debugCertCounter ++
        }
    }
    catch {
        Write-Warning "$Description - Unable to retrieve certificate: $_"
        $script:debugCertCounter ++
    }
}

function Get-BitlockerInfo {
    # Check if BitLocker is enabled and key protectors exist
    Write-Host "------------------------------------------------------"
    Write-Host "Checking Bitlocker device keys ..." -ForegroundColor Cyan
    $volumes = Get-BitLockerVolume
    foreach ($volume in $volumes) {
        Write-Host "Drive: $($volume.VolumeLetter)"
        Write-Host "Protection Status: $($volume.ProtectionStatus)"
        Write-Host "Key Protectors:"
        $volume.KeyProtector | ForEach-Object {
            Write-Host "`tType: $($_.KeyProtectorType)"
            Write-Host "`tID: $($_.KeyProtectorId)"
        }
    }
}

function Get-BitlockerRecoveryKeyInfo {
    # Look for recovery password protector
    Write-Host "------------------------------------------------------"
    Write-Host "Checking Bitlocker device recovery key ..." -ForegroundColor Cyan
    $hasRecoveryPassword = $false
    foreach ($volume in Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "OperatingSystem" }) {
        foreach ($kp in $volume.KeyProtector) {
            if ($kp.KeyProtectorType -eq 'RecoveryPassword') {
                $hasRecoveryPassword = $true
            }
        }
    }
    
    If ($hasRecoveryPassword -eq $true) {
        $script:debugBitlockerRecoveryPresent = "Recovery Password Protector Present: $hasRecoveryPassword on OS Drive!"
        Write-Host $script:debugBitlockerRecoveryPresent
        # Continue
    }
    else {
        $script:debugBitlockerRecoveryPasswordError = "Recovery Password Protector is missing on OS Drive! Exiting (0)!"
        Send-LogDebugMessage -Table Error-Debug -Message $script:debugBitlockerRecoveryPasswordError
        Exit 0
    }
}

function Get-DeviceInformation {
    Write-Host "Device Information:"

    # Checking WMI for Secure Boot relevant entries
    $system = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS

    # Display Device Infos (as global object data can be accessed by the log function as well!)
    $Global:deviceInfo = [PSCustomObject]@{
        Device           = "--------------"
        DeviceName       = $system.Name
        SystemType       = $system.SystemType
        Manufacturer     = $system.Manufacturer
        Model            = $system.Model
        BIOS             = "--------------"
        BiosManufacturer = $bios.Manufacturer
        SerialNumber     = $bios.SerialNumber
        BIOSDescription  = $bios.Description
        BIOSVersionName  = $bios.BIOSVersion
        BIOSVersion      = $bios.SMBIOSBIOSVersion
        BIOSReleaseDate  = $bios.ReleaseDate
    }

    $Global:deviceInfo | Format-List
}
function Get-BitlockerEntraIDBackup {
    # Check for Event ID 845 indicating successful upload to EntraID
    Write-Host "------------------------------------------------------"
    Write-Host "Checking Bitlocker backup in EntraID or Microsoft Account ..." -ForegroundColor Cyan
    $eventsBLR = Get-WinEvent -LogName "Microsoft-Windows-BitLocker/BitLocker Management"  | Where-Object {
        $_.Id -eq 845
    }
    if ($eventsBLR.Count -gt 0) {
        $script:debugBlrUploadSuccess = "BitLocker recovery key was uploaded to EntraID."
        Write-Host $script:debugBlrUploadSuccess
        $script:blrUploadSuccess = $true
    }
    else {
        Write-Host "No evidence of EntraID escrow found in event logs. Therefore we trigger it again!" -ForegroundColor Yellow
        BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId ( (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } ).KeyProtectorId -Verbose
        Start-Sleep -Seconds 10 # we give Windows a bit time to get this done!
        $eventsRepeatedBLR = Get-WinEvent -LogName "Microsoft-Windows-BitLocker/BitLocker Management"  | Where-Object { $_.Id -eq 845 }
        if ($eventsRepeatedBLR -gt 0) {
            $script:debugBlrUploadSuccess = "Bitlocker recovery key was uploaded to EntraID during an additional triggered process!"
            Write-Host $script:debugBlrUploadSuccess -ForegroundColor Yellow
            $script:blrUploadSuccess = $true
        }
        else {
            $script:debugBitlockerRecoveryUploadError = "Bitlocker Recovery repair was not successfull! Please check the log! Exiting (0)!"
            Send-LogDebugMessage -Table Error-Debug -Message $script:debugBitlockerRecoveryUploadError
            $script:blrUploadSuccess = $false
        }
    }

    $EventIDs = @(845, 875, 868)

    # Get events from System log where Source is Microsoft-Windows-BitLocker-API and Event ID matches
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = 'Microsoft-Windows-BitLocker/BitLocker Management'
        ProviderName = 'Microsoft-Windows-BitLocker-API'
        Id           = $EventIDs
    } | Select-Object Id, LevelDisplayName, TimeCreated, Message | Sort-Object TimeCreated -Descending

    # Display as a table
    Write-Host "Showing other relevant Bitlocker messages:" 
    $events | Format-Table @{Label = "Event ID"; Expression = { $_.Id } },
    @{Label = "State"; Expression = { $_.LevelDisplayName } },
    @{Label = "Date of Occurrence"; Expression = { $_.TimeCreated } },
    @{Label = "Message"; Expression = { $_.Message } }

    if ($script:blrUploadSuccess -eq $false) {
        Write-Host "Something went wrong so it might be still a good idea to double check your bitlocker recovery key in EntraID or your Microsoft account!"
        Write-Error $script:debugBitlockerRecoveryUploadError
        Exit 0
    }
    
}

function Send-LogInfo {

    Get-DeviceInformation # to gather data we want to send to Azure Log Analytics

    # This is a stub still need to be extended!
    # $Global:azureLogAnalyticsWorkspaceID
    # $Global:azureLogAnalyticsWorkspaceKey
}

function Download-CsvFile {
    param (
        [string]$Url,
        [string]$DestinationPath
    )
    
    try {
        # Ensure destination directory exists
        if (-not (Test-Path $DestinationPath)) {
            New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        }
        
        # Extract filename from URL
        $fileName = [System.IO.Path]::GetFileName($Url)
        $fullPath = Join-Path -Path $DestinationPath -ChildPath $fileName
        
        # Download the file
        Invoke-WebRequest -Uri $Url -OutFile $fullPath -ErrorAction Stop
        
        Write-Host "CSV file downloaded successfully to: $fullPath" -ForegroundColor Green
        return $fullPath
    }
    catch {
        Write-Error "Failed to download CSV file: $_"
        return $null
    }
}
 
function Send-LogDebugMessage {
    # Function to log Host Name and IP Address to custom log in Azure Log Analytics!
    # Simply use start-transcript at the beginning your script and 
    # stop-transcript as last line in your script for easy logging. 
    # This will catch up all the write-host and other output as well!
    param (
        [string]$Table,
        [string]$Message
    )

    Write-Host "Log Debug Message ($Table) - $env:Computername : $Message"

    $apiVersion = "2016-04-01"
    $workspaceId = $Global:azureLogAnalyticsWorkspaceID
    $workspaceKey = $Global:azureLogAnalyticsWorkspaceKey
   
    # Name of your log in your Azure Log Analytics Workspace
    $logType = $Table

    # Generation of some sample custom log data. Change this for your purpose
    $hostname = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"

    # Creation of the log entry. Its good to have a timestamp and may be a host reference if you want! And add here whatever you want!
    $logEntry = @(
        @{
            TimeGenerated = $timestamp
            Hostname      = $hostname
            DebugMessage  = $Message
        }
    )

    # Generate log entry body and header to send. It will be encrypted and signed with your shared Workspace key from above.
    $body = $logEntry | ConvertTo-Json -Depth 3
    # Ensure the date is in RFC1123 format
    $date = [DateTime]::UtcNow.ToString("r")
    # Construct the string to sign
    $stringToHash = "POST`n$($body.Length)`napplication/json`nx-ms-date:$date`n/api/logs"
    $hmacsha256 = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha256.Key = [Convert]::FromBase64String($workspaceKey)
    $hash = $hmacsha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToHash))
    $signature = [Convert]::ToBase64String($hash)
    $authkey = $workspaceId + ":" + $signature
    $authorization = "SharedKey $authkey"

    $headers = @{
        "Content-Type"  = "application/json"
        "Authorization" = $authorization
        "Log-Type"      = $logType
        "x-ms-date"     = $date
    }

    # Lets look into the header we have created (this is just for reference in your local logs if you want!)
    Write-Host "Header:"
    $headers

    Write-Host "======================================================================================"
    # Lets look into the body we have created (this is just for reference in your local logs if you want!)
    Write-Host "Body:"
    $body

    # Now lets send the data to the workspace (may be you want to adjust the catch block & finally text)
    try {
        $response = Invoke-RestMethod -Method Post -Uri "https://$workspaceId.ods.opinsights.azure.com/api/logs?api-version=$apiVersion" -Headers $headers -Body $body

        # Output the response (so it got catched in start-transcript log, no response is fine as well!)
        Write-Host "Response: $response"         
    }
    catch {
        Write-Error "Failed to send data for debug log entry: $_"
    }
    finally {
        Write-Host "Processing done for debug log entry upload!"
    }
}

function Test-UEFIBiosUpdateProcessRequired {
    # Check certain things to figure out if the UEFI certificate update is required (Returns $true or $false)
    # This will ensure we do not run on a machine that is already handled.
    
    # Error Handling in front. Whenever there is an unsupported condition we get this message! We need to add the new condition as well!
    # These values get overwritten by the different conditions.
    $Global:centralUefiRequiredLogState = "An error occured while testing the UEFI requirement!"
    $Global:scriptProcess = "unknown"

    # Condition 1 (Reg WindowsUEFICA2023Capable = 2 (DB update + Booted from new bootloader) AND Reg ..\State\UEFISecureBootEnabled = 1 (enabled))
    # Target condition nothing to do!
    If (($regWindowsUEFICA2023Capable -eq 2) -and ($regUEFISecureBootEnabled -eq 1)) {
        Write-Host "Test requirement for Secure Boot Certificate Update: System is already fully prepared (DB and Bootloader). Nothing required"
        $Global:centralUefiRequiredLogState = "update finished"
        $Global:scriptProcess = "notRequired"
        return $false
    }

    # Condition 2 (Reg WindowsUEFICA2023Capable = 1 (DB update ) AND Reg ..\State\UEFISecureBootEnabled = 1 (enabled))
    # On this case we need we only check and DO NOT set MicrosoftUpdateManagedOptIn or AvailableUpdates
    If (($regWindowsUEFICA2023Capable -eq 1) -and ($regUEFISecureBootEnabled -eq 1)) {
        Write-Host "Test requirement for Secure Boot Certificate Update: System update is currently partially done (DB certificate only)"
        $Global:centralUefiRequiredLogState = "update in progress"
        $Global:scriptProcess = "checkOnly"
        return $true
    }

    # Condition 3 (Reg WindowsUEFICA2023Capable = 0 (Nothing done ) AND Reg ..\State\UEFISecureBootEnabled = 1 (enabled))
    # On this case we need we need to set MicrosoftUpdateManagedOptIn and AvailableUpdates
    If ((($regWindowsUEFICA2023Capable -eq 0) -or ($regWindowsUEFICA2023Capable -eq $null)) -and ($regUEFISecureBootEnabled -eq 1)) {
        Write-Host "Test requirement for Secure Boot Certificate Update: System update is required"
        $Global:centralUefiRequiredLogState = "required"
        $Global:scriptProcess = "updateSBcerts"
        return $true
    }

    # Condition 4 (Reg WindowsUEFICA2023Capable = 0 (Nothing done ) AND Reg ..\State\UEFISecureBootEnabled = 0 (disabled))
    # On this case we can immediatelly stop as this is not required as its not applicable. May be we have an MBR instead of UEFI etc.
    If ((($regWindowsUEFICA2023Capable -eq 0) -or ($regWindowsUEFICA2023Capable -eq $null)) -and ($regUEFISecureBootEnabled -eq 0)) {
        Write-Host "Test requirement for Secure Boot Certificate Update: System had no secure boot enabled!"
        $Global:centralUefiRequiredLogState = "not applicable"
        $Global:scriptProcess = "notRequired"
        return $false
    }
}

Write-Host "=============================================================================================="
# Prepare environment and ensure everything is in place and only running when needed.
# Check if the script was ever running or if its the first time. Handle cost savings in Azure
If (Test-Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate") {
    # We are running consecutive times already therefore the key must exist
    try {
        $lastRunString = (Get-ItemPropertyValue -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Name "LastRun" -ErrorAction Stop)
        $lastRun = [DateTime]::ParseExact($lastRunString, 'o', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
    }
    catch {
        # Missing LastRun property — treat as first run
        $lastRun = $null
    }

    if ($lastRun) {
        $ageDays = (Get-Date) - $lastRun
        $ageDays = $ageDays.TotalDays

        # If last run was within the configured interval, exit with code 2
        if ($ageDays -lt $scriptLastRunInterval) {
            Write-Host "Former execution $lastRun - Last run was $([math]::Round($ageDays,2)) days ago — less than $scriptLastRunInterval days. Exiting (2)." -ForegroundColor Yellow
            Stop-Transcript
            Exit 2
        }
        else {
            # Update LastRun to mark this execution
            Set-ItemProperty -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Name "LastRun" -Value $currentRunTime.ToString('o') -Force
        }
    }
    else {
        # No LastRun value found, set it now
        Set-ItemProperty -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Name "LastRun" -Value $currentRunTime.ToString('o') -Force
    }
    
}
else {
    # We are running the first time. We need to create the structure first and 
    Write-Host "Script Version $scriptVersion running for the first time on $currentRunTime"
    New-Item -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Name "LastRun" -Value $currentRunTime -Force
}

# General variables (all variables are camelcase!)

try {
    $prerequisiteCheckSuccessful = (Get-ItemPropertyValue -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Name "PrerequisiteSuccessfullyChecked" -ErrorAction Stop)
}
catch {
    # Obviously the registrykey does not exist at the beginning. So we created it and set if to 0 (false)
    Set-ItemProperty -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Name "PrerequisiteSuccessfullyChecked" -Type DWord -Value 0 -Force
    $prerequisiteCheckSuccessful = 0
}

# BIOS List to check for applicable BIOS versions for process control
$publicProductionBiosListUrl = "https://raw.githubusercontent.com/JoergWu/uefi-secure-boot-cert-check-remediate/main/bioslist"
$publicDevelopmentBiosListUrl = "https://raw.githubusercontent.com/JoergWu/uefi-secure-boot-cert-check-remediate/development/bioslist"
$privateProductionBiosListUrl = $null
$privateDevelopmentBiosListUrl = $null
$biosListUrl = $null

$regWindowsUEFICA2023Status = (Get-Itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing).UEFICA2023Status # Status = NotStarted (Update not yet run), InProgress, Updated (completed succesfully finally after a few reboots (3-4 + waiting time))
$regWindowsUEFICA2023Capable = (Get-Itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing).WindowsUEFICA2023Capable # 0 or does not exist = new WinCA2023 certificate is not in store, 1 Cert is in DB, 2 Cert is in DB AND system was starting from a signed bootmanager
$regAvailableUpdates = (Get-Itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot).AvailableUpdates # controls the required steps (decrement bitwise with each step done!)
$regMicrosoftUpdateManagedOptIn = (Get-Itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot).MicrosoftUpdateManagedOptIn # $null = the managed process not started yet
$regUEFISecureBootEnabled = (Get-Itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State).UEFISecureBootEnabled # 1 (yes) or 0 (no)
$Global:centralUefiRequiredLogState = $null # This will be filled by the Test-UEFIBiosRequired
$Global:scriptProcess = $null # First run if UEFI update is required this is becoming "updateSB" and when the MS process kicks in then the is "checkOnly" and with "notRequired" we stop execution

# Switch to the right URL depending on preceding definitions
# When the private BiosListUrls are filled they have precedence!
If ($developmentMode = $true) {
    $biosListUrl = $publicDevelopmentBiosListUrl
    If ($privateDevelopmentBiosListUrl -ne $null) {
        $biosListUrl = $privateDevelopmentBiosListUrl
    }
    Write-Host "Script in development mode with URL: $biosListUrl"
}

# If script running in production mode you could overwrite your source of truth from Github to anything else
If ($developmentMode = $false) {
    $biosListUrl = $publicProductionBiosListUrl
    If ($privateProductionBiosListUrl -ne $null) {
        $biosListUrl = $privateProductionBiosListUrl
    }
    Write-Host "Script in production mode with URL: $biosListUrl"
}

Write-Host "Windows Secure Boot - Certificate Check for updated certificates (CA2023) - Scriptversion: $scriptVersion"
Test-AdminRole
Write-Host "Logfile: C:\Windows\temp\boot-cert-check.log"

# Checking where we are in the process (if its done, even required etc.)
$script:uefiSecureBootUpdateRequired = Test-UEFIBiosUpdateProcessRequired

If ($Global:scriptProcess -eq "notRequired") {
    $debugUpdateRequiredMessage = "No UEFI Secure Boot certificate and bootloader update required. (Logstate: $Global:centralUefiRequiredLogState)"
    Write-Host $debugUpdateRequiredMessage
    Send-LogDebugMessage -Table "SecureBoot-Not-Required-Devices" -Message
    Exit 0
}

if ($prerequisiteCheckSuccessful -eq 0) {
    Write-Host "Pre-Requisite check is required (Bios, SecureBoot, Bitlocker are already ok). Continue ..."

    # Extract device information like Bios version to compare with supported versions! (collecting data for $deviceInfo object)
    Get-DeviceInformation
    Write-Host "Check for required Bios comparison file"

    # Normalize vendor informations for downloading CSV file sources!
    # Some vendors rename over time so adjustments here might be required!

    # Use the given vendor name first and only overwrite when special rules apply!
    $vendor = $deviceInfo.Manufacturer

    if ($deviceInfo.Manufacturer -like "*Dell*") {
        $vendor = "Dell"
    }
    elseif ($deviceInfo.Manufacturer -like "*Hewlett-Packard*" -or $deviceInfo.Manufacturer -like "*HP*") {
        $vendor = "HP"
    }     
    elseif ($deviceInfo.Manufacturer -like "*FUJITSU*") {
        $vendor = "Fujitsu"
    }    
    elseif ($deviceInfo.Manufacturer -like "*Microsoft*") {
        $vendor = "Microsoft"
    }

    ############# to extend for further vendor handlings the elseif with further statements if needed
    # This allows you to consolidate different name strings for some vendors like HP under one unique vendor name.

    $localCsvPath = "$env:windir\temp\SecureBootUpdate\$vendor-models.csv"
    $localCsvDirectory = Split-Path -Path $localCsvPath -Parent

    If (Test-Path $localCsvPath) {
        Write-Host "Vendor CSV $vendor-models.csv found"
    }
    else {
        Write-Host "Vendor CSV $vendor-models.csv not found. Download required!"
        New-Item -ItemType Directory -Path $localCsvDirectory -Force | Out-Null
        $fullBiosListUrl = "$biosListUrl/$vendor-models.csv"
        Download-CsvFile -Url $fullBiosListUrl -DestinationPath $localCsvDirectory
    }


    Write-Host "Comparing supported reference Bios list $localCsvPath with current device Bios version:"
    $referenceBiosTable = (Import-Csv -Path $localCsvPath -Delimiter ",")

    [Version]$deviceBiosVersion = [regex]::Match($Global:deviceInfo.BIOSVersion, '\d+(\.\d+)*').Value
    [version]$minimumRequiredBios = [regex]::Match(($referenceBiosTable | Where-Object { $_.Platform -eq $Global:deviceInfo.Model }).MinimumBIOSVersion, '\d+(\.\d+)*').Value
    If ([version]$deviceBiosVersion -ge [version]$minimumRequiredBios) {
        Write-Host "SUCCESS: BIOS version meets minimum requirement" -ForegroundColor Green
        $Global:enableSBUpdate = $true
    }
    else {
        $debugBiosUpdateRequired = "Vendor: $vendor Model: $($Global:deviceInfo.Model) BIOS update required. Current: $deviceBiosVersion, Required: $minimumRequiredBios"
        Write-Warning $debugBiosUpdateRequired
        $Global:enableSBUpdate = $false
        Send-LogDebugMessage -Table BiosUpdateRequired -Message $debugBiosUpdateRequired
    }

    Write-Host " "
    Write-Host "Checking Secure Boot Status ..." -ForegroundColor Cyan

    If (Confirm-SecureBootUEFI) {
        Write-Host "SUCCESS: Secure Boot is enabled on this system" -ForegroundColor Green
        $secureBootEnabled = $true
    }
    else {
        Write-Warning "Secure Boot is disabled on this system"
        $secureBootEnabled = $false
    }

    Write-Host " "
    Write-Host "Checking Bitlocker state and recovery key backup"
    Get-BitlockerInfo
    Get-BitlockerRecoveryKeyInfo
    Get-BitlockerEntraIDBackup

    if ($Global:enableSBUpdate -eq $true) {
        # We are good to go and are able to enable now the update trigger (Microsoft Reg Key) once!
    
        # First set the prerequisite check to successfully completed (1)
        Set-ItemProperty -Path "HKLM:\Software\MySystemMaintenance\SecureBootUpdate" -Name "PrerequisiteSuccessfullyChecked" -Type DWord -Value 1 -Force
        
        # Set the registry key once to enable the Secure Boot Update
        
        ##################################
        #### HERE with double checkk!!!
        #################################
    } else {
        Write-Warning "Stop process as we need to wait until Bios is updated first from Current: $deviceBiosVersion, to the Required: $minimumRequiredBios!"
        Exit 0
    }
}
else {
    Write-Host "Pre-requisite check is already successfully passed!"
}

Write-Host " "
Write-Host "------------------------------------------------------"
Write-Host "Checking Registry Keys ..." -ForegroundColor Cyan

# Checking Registry for Secure Boot relevant entries
$sbUpdateFlagAvailableUpdates = $null

$sbUpdateFlagAvailableUpdates = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
If ($sbUpdateFlagAvailableUpdates -eq $null) {
    Write-Warning "Registrykey Available Updates is not set!"    
}

If ($sbUpdateFlagAvailableUpdates -eq 0) {
    Write-Host "INFO:    Registrykey Available Updates is set to 0 = no updates enforced or we are finished again!"
}

If ($sbUpdateFlagAvailableUpdates -eq 64) {
    Write-Host "SUCCESS: Registrykey Available Updates is set to 64 = update next time to Secure Boot Microsoft CA 2023" -ForegroundColor Green
}

$sbUpdateFlagUefiCapable = $null

$sbUpdateFlagUefiCapable = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name WindowsUEFICA2023Capable -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
If ($sbUpdateFlagUefiCapable -eq $null) {
    Write-Warning "Check for CA UEFI2023 capability was not yet running!"    
}

If ($sbUpdateFlagUefiCapable -eq 0) {
    Write-Warning "Check for CA UEFI2023 capability was running and your device is not yet capable! Please update your Bios first to the latest version!"
}

If ($sbUpdateFlagUefiCapable -eq 1) {
    Write-Warning "Check for CA UEFI2023 capability was running and your device had the new Windows PCA CA certificate (db)! But no new signed bootloader was loaded or is available yet!"
}

If ($sbUpdateFlagUefiCapable -eq 2) {
    Write-Host "SUCCESS: Check for CA UEFI2023 capability was running and your device had the new Windows PCA CA certificate (db) and the new signed bootloader was loaded sucessfully!" -ForegroundColor Green
}

If ($sbUpdateFlagUefiCapable -eq 64) {
    Write-Host "SUCCESS: Check for CA UEFI2023 capability was running and your device had updated certificates in the boot loader see detailed values below!" -ForegroundColor Green #References here are unclear, some say so others did not mention 64
}

$managedMSupdateForDBcert = $null
$managedMSupdateForDBcert = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name MicrosoftUpdateManagedOptIn -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn

If ($managedMSupdateForDBcert -eq $null) {
    Write-Warning "Check for Microsoft managed certificate update was running and the device is NOT enabled for the Microsoft managed process!"
}
If ($managedMSupdateForDBcert -eq '22852') {
    Write-Host "SUCCESS: Check for Microsoft managed certificate update was running and the device is enabled for the Microsoft managed process!" -ForegroundColor Green
}

Write-Host " "



# Checking existing UEFI certificates in UEFI Bios
Write-Host " "
Write-Host "Checking Certs for Platform Key in Firmware (PK - Root of trust)..." -ForegroundColor Cyan
Write-Host "==================================================================="
$uefiPkSecureBootCerts = Get-UEFISecureBootCerts -Variable "pk"

ForEach ($uefiPkSecureBootCert in $uefiPkSecureBootCerts) {
    Write-Host "Platform Key found: $($uefiPkSecureBootCert.Signature.Issuer) with expiration date: $($uefiPkSecureBootCert.Signature.GetExpirationDateString())"
}

Write-Host " "
Write-Host "Checking Certs for Key Exchange Key in Firmware (KEK)..." -ForegroundColor Cyan
Write-Host "==================================================================="
# Get the UEFI KEK Secure Boot certificates
$uefiKekSecureBootCerts = Get-UEFISecureBootCerts -Variable "kek"
$kekOldCert = ($uefiKekSecureBootCerts | Where-Object { $_.SignatureSubject -like "*CN=Microsoft Corporation KEK CA 2011*" })
$kekNewCert = ($uefiKekSecureBootCerts | Where-Object { $_.SignatureSubject -like "*CN=Microsoft Corporation KEK 2K CA 2023*" })

If ($kekOldCert -ne $null) {
    Write-Host "Old Key Exchange Key (KEK) 2011 certificate exists: $(($kekOldCert.Signature.Subject -split 'CN=')[1]) with expiration date: $($kekOldCert.Signature.GetExpirationDateString())"
}
else {
    Write-Host "Old Key Exchange Key (KEK) 2011 certificate does not exist!"
}
If ($kekNewCert -ne $null) {
    Write-Host "New Key Exchange Key (KEK) 2023 certificate exists: $(($kekNewCert.Signature.Subject -split 'CN=')[1]) with expiration date: $($kekNewCert.Signature.GetExpirationDateString())"
}
else {
    Write-Warning "New Key Exchange Key (KEK) 2023 certificate does not exist!"
}

If (($kekOldCert -ne $null) -and ($kekNewCert -eq $null)) {
    Write-Warning "Key Exchange Key (KEK) certificate is not yet updated!"
    Write-Warning "Bios Update is required to get the new KEK certificate!"
    $biosUpdateRequired = $true
}
If (($kekOldCert -ne $null) -and ($kekNewCert -ne $null)) {
    Write-Host "SUCCESS: Key Exchange Key (KEK) 2023 certificate is updated!" -ForegroundColor Green
    $biosUpdateRequired = $false
}
If (($kekOldCert -eq $null) -and ($kekNewCert -ne $null)) {
    Write-Host "SUCCESS: Key Exchange Key (KEK) 2023 certificate is the latest!" -ForegroundColor Green
    $biosUpdateRequired = $false
}
Write-Host "---------------------------------------------------------------------------------------"

Write-Host "Checking DB Certs in Firmware (DB)..." -ForegroundColor Cyan
Write-Host "==================================================================="

# Get the UEFI Secure Boot certificates
$uefiSecureBootCerts = Get-UEFISecureBootCerts -Variable "db"
$winOldProdCA = ($uefiSecureBootCerts | Where-Object { $_.SignatureSubject -like "*CN=Microsoft Windows Production PCA 2011*" })
$winNewProdCA = ($uefiSecureBootCerts | Where-Object { $_.SignatureSubject -like "*CN=Windows UEFI CA 2023*" })

If ($winOldProdCA -ne $null) {
    Write-Host "Old Windows Prodcution PCA 2011 certificate exists: $(($winOldProdCA.Signature.Subject -split 'CN=')[1]) with expiration date: $($winOldProdCA.Signature.GetExpirationDateString())"
}
else {
    Write-Host "Old Windows Prodcution PCA 2011 does not exist!"
}
If ($winNewProdCA -ne $null) {
    Write-Host "New Windows UEFI CA 2023 certificate exists: $(($winNewProdCA.Signature.Subject -split 'CN=')[1]) with expiration date: $($winNewProdCA.Signature.GetExpirationDateString())"
}
else {
    Write-Warning "New Windows UEFI CA 2023 certificate does not exist!"
}



If (($winOldProdCA -ne $null) -and ($winNewProdCA -eq $null)) {
    Write-Warning "Windows Bootloader (DB) certificate is not yet updated!"
}
If (($winOldProdCA -ne $null) -and ($winNewProdCA -ne $null)) {
    Write-Host "SUCCESS: Windows Bootloader (DB) certificate is updated!" -ForegroundColor Green
}
If (($winOldProdCA -eq $null) -and ($winNewProdCA -ne $null)) {
    Write-Host "SUCCESS: Windows Bootloader (DB) certificate is the latest!" -ForegroundColor Green
}

Write-Host "-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -"
$3rdPartyOldUefiCA = ($uefiSecureBootCerts | Where-Object { $_.SignatureSubject -like "*CN=Microsoft UEFI CA 2011*" })
$3rdPartyNewUefiCA = ($uefiSecureBootCerts | Where-Object { $_.SignatureSubject -like "*CN=Microsoft UEFI CA 2023*" })

If ($3rdPartyOldUefiCA -ne $null) {
    Write-Host "Old Windows third party bootloader certificate exists: $(($3rdPartyOldUefiCA.Signature.Subject -split 'CN=')[1]) with expiration date: $($3rdPartyOldUefiCA.Signature.GetExpirationDateString())"
    $3rdPartyBootLoaderRequried = $true
}
else {
    Write-Host "Old Windows third party bootloader certificate does not exist!"
    $3rdPartyBootLoaderRequried = $false
}

If ($3rdPartyNewUefiCA -ne $null) {
    Write-Host "New Windows third party bootloader certificate exists: $(($3rdPartyNewUefiCA.Signature.Subject -split 'CN=')[1]) with expiration date: $($3rdPartyNewUefiCA.Signature.GetExpirationDateString())"
}
else {
    If ($3rdPartyBootLoaderRequried -eq $true) {
        Write-Warning "New Windows third party bootloader certificate is required!"
    }
    else {
        Write-Host "New Windows third party bootloader certificate does not exist and is also not required!" -ForegroundColor Green 
    }
    
}

If (($3rdPartyOldUefiCA -ne $null) -and ($3rdPartyNewUefiCA -eq $null)) {
    Write-Warning "3rd Party Bootloader (DB) certificate is not yet updated!"
}
If (($3rdPartyOldUefiCA -ne $null) -and ($3rdPartyNewUefiCA -ne $null)) {
    Write-Host "SUCCESS: 3rd Party Bootloader (DB) certificate is updated!" -ForegroundColor Green
}
If (($3rdPartyOldUefiCA -eq $null) -and ($3rdPartyNewUefiCA -eq $null)) {
    Write-Host "SUCCESS: 3rd Party Bootloader does not apply for this system!" -ForegroundColor Green
}
Write-Host "-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -"
$3rdPartyOldOptionRomCA = ($uefiSecureBootCerts | Where-Object { $_.SignatureSubject -like "*CN=Microsoft UEFI CA 2011*" })
$3rdPartyNewOptionRomCA = ($uefiSecureBootCerts | Where-Object { $_.SignatureSubject -like "*Microsoft Option ROM UEFI CA 2023*" })

If ($3rdPartyOldOptionRomCA -ne $null) {
    Write-Host "Old Windows third party option rom loader certificate exists: $(($3rdPartyOldOptionRomCA.Signature.Subject -split 'CN=')[1]) with expiration date: $($3rdPartyOldOptionRomCA.Signature.GetExpirationDateString())"
    $3rdPartyOptionRomLoaderRequried = $true
}
else {
    Write-Host "Old Windows third party option rom loader certificate does not exist!"
    $3rdPartyBootLoaderRequried = $false
}

If ($3rdPartyOptionRomLoaderRequried -ne $null) {
    Write-Host "New Windows third party option rom loader certificate exists: $(($3rd3rdPartyNewOptionRomCAPartyNewUefiCA.Signature.Subject -split 'CN=')[1]) with expiration date: $($3rdPartyNewOptionRomCA.Signature.GetExpirationDateString())"
}
else {
    If ($3rdPartyOptionRomLoaderRequried -eq $true) {
        Write-Warning "New Windows third party option rom loader certificate is required!"
    }
    else {
        Write-Host "New Windows third party option rom loader certificate does not exist and is also not required!" -ForegroundColor Green 
    }
    
}

If (($3rdPartyOldOptionRomCA -ne $null) -and ($3rdPartyNewOptionRomCA -eq $null)) {
    Write-Warning "3rd Party option rom loader (DB) certificate is not yet updated!"
}
If (($3rdPartyOldOptionRomCA -ne $null) -and ($3rdPartyNewOptionRomCA -ne $null)) {
    Write-Host "SUCCESS: 3rd Party option rom loader (DB) certificate is updated!" -ForegroundColor Green
}
If (($3rdPartyOldOptionRomCA -eq $null) -and ($3rdPartyNewOptionRomCA -eq $null)) {
    Write-Host "SUCCESS: 3rd Party option rom loader certificate does not apply for this system!" -ForegroundColor Green
}

Write-Host "---------------------------------------------------------------------------------------"

If (($winNewProdCA -ne $null) -and ($3rdPartyNewUefiCA -eq $null) -and ($kekNewCert -ne $null) ) {
    Write-Host "SUCCESS: Your device had the minimum required Secure Boot certificates for Windows" -ForegroundColor Green
    $exitCertCode = 0
}

If (($winNewProdCA -ne $null) -and ($3rdPartyNewUefiCA -ne $null) -and ($3rdPartyNewOptionRomCA -ne $null) -and ($kekNewCert -ne $null)) {
    Write-Host "SUCCESS: Your device had the all required Secure Boot certificates for Windows incl. 3rd party Option Roms" -ForegroundColor Green
    $exitCertCode = 2
}
else {
    Write-Warning "Your device is missing important Windows Secure Boot certificates to operate fully functional after June 2026"
    $exitCertCode = 1
}
Write-Host " "

# Now we need to check the boot loader certificates. Updated systems get updated bootloader and boot once from them!
Write-Host "---------------------------------------------------------------------------------------"
Write-Host "Checking the boot loader files certificate signatures in UEFI partition and Windows ..."
Write-Host " "
$oldBootLoaderCert = "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
$newBootLoaderCert = "CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US"

# Mount UEFI Partition in a new drive for certificate examination (first one which is not used on the machine)
$drive = Get-FirstAvailableDrive
$driveName = ($drive + ":")
$arguments = ($driveName + " /S")
start-process -FilePath "C:\Windows\System32\mountvol.exe" -ArgumentList $arguments -Wait
# Check the certificate signatures of boot critical files
Get-CertInfo -FilePath ($driveName + "\EFI\Microsoft\Boot\bootmgfw.efi") `
    -OldCert $oldBootLoaderCert -NewCert $newBootLoaderCert -Description "UEFI-FW Bootloader"

Get-CertInfo -FilePath ($driveName + "\EFI\Microsoft\Boot\bootmgr.efi") `
    -OldCert $oldBootLoaderCert -NewCert $newBootLoaderCert -Description "UEFI-Win Bootloader"

Get-CertInfo -FilePath ($driveName + "\EFI\Boot\bootx64.efi") `
    -OldCert $oldBootLoaderCert -NewCert $newBootLoaderCert -Description "UEFI-Bootx64 Loader"

Get-CertInfo -FilePath ($driveName + "\EFI\Microsoft\Boot\SecureBootRecovery.efi") `
    -OldCert $oldBootLoaderCert -NewCert $newBootLoaderCert -Description "UEFI-Recovery Loader"

# Unmount EFI Partition
$arguments = ($driveName + " /D")
start-process -FilePath "C:\Windows\System32\mountvol.exe" -ArgumentList $arguments -Wait

Get-CertInfo -FilePath "C:\Windows\System32\Boot\winload.efi" `
    -OldCert $oldBootLoaderCert -NewCert $newBootLoaderCert -Description "C-Drive-EFI Loader"

Get-CertInfo -FilePath "C:\Windows\System32\Boot\winload.exe" `
    -OldCert $oldBootLoaderCert -NewCert $newBootLoaderCert -Description "C-Drive-EXE Loader"

Get-CertInfo -FilePath "C:\Windows\System32\ntoskrnl.exe" `
    -OldCert $oldBootLoaderCert -NewCert $newBootLoaderCert -Description "NT OS Kernel"
Write-Host "---------------------------------------------------------------------------------------"
Write-Host " "
Write-Host "Historical Event IDs for Secure Boot actions in SYSTEM eventlog ..."

# Define the Event IDs from Microsoft documentation
$EventIDs = @(1032, 1033, 1034, 1036, 1037, 1043, 1044, 1045, 1795, 1796, 1797, 1798, 1799, 1800, 1801, 1808)

# Get events from System log where Source is TPM-WMI and Event ID matches
$events = Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-TPM-WMI'
    Id           = $EventIDs
} | Select-Object Id, LevelDisplayName, TimeCreated, Message | Sort-Object TimeCreated -Descending

# Display as a table

$events | Format-Table @{Label = "Event ID"; Expression = { $_.Id } },
@{Label = "State"; Expression = { $_.LevelDisplayName } },
@{Label = "Date of Occurrence"; Expression = { $_.TimeCreated } },
@{Label = "Message"; Expression = { $_.Message } }

If ($debuggingEnabled -eq $true) {
    Write-Host "Debugging Info (enabled)" -ForegroundColor Red

    Write-Host "developmentmode = $developmentMode"
    Write-Host "debugPreference = $debugPreference"
    Write-Host "biosListUrl = $biosListUrl"
    Write-Host "Global:centralUefiRequiredLogState = $Global:centralUefiRequiredLogState"
    Write-Host "Global:scriptProcess= $Global:scriptProcess "
    Write-Host "regWindowsUEFICA2023Status = $regWindowsUEFICA2023Status"
    Write-Host "regWindowsUEFICA2023Capable = $regWindowsUEFICA2023Capable"
    Write-Host "regAvailableUpdates = $regAvailableUpdates"
    Write-Host "regMicrosoftUpdateManagedOptIn = $regMicrosoftUpdateManagedOptIn"
    Write-Host "regUEFISecureBootEnabled = $regUEFISecureBootEnabled"
    Write-Host "Global azureLogAnalyticsWorkspaceID = $Global:azureLogAnalyticsWorkspaceID"
    Write-Host "Global azureLogAnalyticsWorkspaceKey = $Global:azureLogAnalyticsWorkspaceKey"

    Write-Host "PK Certs:"
    Start-Sleep -Seconds 1
    $uefiPkSecureBootCerts | Select-Object @{Name = 'Subject'; Expression = { $_.Signature.Subject } }, @{Name = 'ExpirationDate'; Expression = { $_.Signature.GetExpirationDateString() } } -Wait
    Start-Sleep -Seconds 5
    Write-Host "KEK Certs:"
    Start-Sleep -Seconds 1
    $uefiKekSecureBootCerts | Select-Object @{Name = 'Subject'; Expression = { $_.Signature.Subject } }, @{Name = 'ExpirationDate'; Expression = { $_.Signature.GetExpirationDateString() } } -Wait
    Start-Sleep -Seconds 5
    Write-Host "DB Certs:"
    $uefiSecureBootCerts | Select-Object @{Name = 'Subject'; Expression = { $_.Signature.Subject } }, @{Name = 'ExpirationDate'; Expression = { $_.Signature.GetExpirationDateString() } } -Wait
    Start-Sleep -Seconds 5
    Write-Host "Device Information:"  
    $Global:deviceInfo | Format-List
    Start-Sleep -Seconds 1
}

Stop-Transcript
Write-Host "Exitcode = $exitCode"
exit $exitCode
