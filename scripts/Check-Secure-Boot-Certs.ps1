#########################################################################
# Test script to check Windows Secure Boot Certificates and boot binaries
# Version 1.4
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
# Script need to be executed as admin!

########################################################
$scriptVersion = "1.4"
# Functions
function get-firstavailabledrive {
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
        Return $firstavailabledrive
    } else {
        Write-Output "No available drive letters found. Exiting (99)!"
        $exitCode = 99
        Exit 99
    }
}

function test-adminrole {

    # Get current user
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    # Create a WindowsPrincipal object
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)

    # Check if user is in Administrators group
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    # Output result
    if ($isAdmin) {
        Write-Host "User is a member of the local Administrators group. Continuing ..." -ForegroundColor Green
    } else {
        Write-Host "User is NOT a member of the local Administrators group. Exiting (98)!" -ForegroundColor Red
        Exit 98
    }
}

function Get-CertInfo {
    param (
        [string]$FilePath,
        [string]$OldCert,
        [string]$NewCert,
        [string]$Description
    )
    try {
        $cert = Get-PfxCertificate -FilePath $FilePath
        $certIssuer = $cert.Issuer
        $certExpirationDate = $cert.GetExpirationDateString()
        Write-Host "$Description - Certificate found: $certIssuer"
        Write-Host "$Description - Expiration date  : $certExpirationDate"
        if ($certIssuer -eq $OldCert) {
            Write-Warning "$Description still signed with old KEK certificate (2011 Version)"
        } elseif ($certIssuer -eq $NewCert) {
            Write-Host "SUCCESS: $Description now signed with new KEK certificate (2023 Version)" -ForegroundColor Green
        } else {
            Write-Warning "$Description certificate issuer is unknown or not matched!"
        }
    } catch {
        Write-Warning "$Description - Unable to retrieve certificate: $_"
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
    foreach ($volume in Get-BitLockerVolume) {
        foreach ($kp in $volume.KeyProtector) {
            if ($kp.KeyProtectorType -eq 'RecoveryPassword') {
                $hasRecoveryPassword = $true
            }
        }
    }
    Write-Host "Recovery Password Protector Present: $hasRecoveryPassword"
}

function Get-BitlockerEntraIDBackup {
    # Check for Event ID 845 indicating successful upload to EntraID
    Write-Host "------------------------------------------------------"
    Write-Host "Checking Bitlocker backup in EntraID or Microsoft Account ..." -ForegroundColor Cyan
    $events = Get-WinEvent -LogName "Microsoft-Windows-BitLocker/BitLocker Management"  | Where-Object {
        $_.Id -eq 845
    }
    if ($events.Count -gt 0) {
        Write-Host "BitLocker recovery key was uploaded to EntraID."
    } else {
        Write-Host "No evidence of EntraID escrow found in event logs."
    }

    $EventIDs = @(845, 875, 868)

    # Get events from System log where Source is Microsoft-Windows-BitLocker-API and Event ID matches
    $events = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'
    ProviderName = 'Microsoft-Windows-BitLocker-API'
    Id = $EventIDs
    } | Select-Object Id, LevelDisplayName, TimeCreated, Message | Sort-Object TimeCreated -Descending

    # Display as a table
    Write-Host "Showing other relevant Bitlocker messages:" 
    $events | Format-Table @{Label="Event ID";Expression={$_.Id}},
                            @{Label="State";Expression={$_.LevelDisplayName}},
                            @{Label="Date of Occurrence";Expression={$_.TimeCreated}},
                            @{Label="Message";Expression={$_.Message}}

    Write-Host "It might be still a good idea to double check your bitlocker recovery key in EntraID or your Microsoft account!"
}

$runningDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Start-Transcript -Path $env:windir\temp\boot-cert-check.log -Append
Write-Host "=============================================================================================="
Write-Host "Windows Secure Boot - Certificate Check for updated certificates (CA2023) - Scriptversion: $scriptVersion"
test-adminrole
Write-Host "Execution date: $runningDate"
Write-Host "Logfile: C:\Windows\temp\boot-cert-check.log"

# Checking WMI for Secure Boot relevant entries
$system = Get-CimInstance -ClassName Win32_ComputerSystem
$bios = Get-CimInstance -ClassName Win32_BIOS

Write-Host " "
Write-Host "Checking Secure Boot Status ..." -ForegroundColor Cyan

If (Confirm-SecureBootUEFI){
    Write-Host "SUCCESS: Secure Boot is enabled on this system" -ForegroundColor Green
    $secureBootEnabled = $true}
 else {
    Write-Warning "Secure Boot is disabled on this system"
    $secureBootEnabled = $false
 }

Write-Host " "
Write-Host "Checking Bitlocker state"
Get-BitlockerInfo
Get-BitlockerRecoveryKeyInfo
Get-BitlockerEntraIDBackup

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

If ($sbUpdateFlagAvailableUpdates -eq 64){
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

If ($sbUpdateFlagUefiCapable -eq 2){
    Write-Host "SUCCESS: Check for CA UEFI2023 capability was running and your device had the new Windows PCA CA certificate (db) and the new signed bootloader was loaded sucessfully!" -ForegroundColor Green
    }

If ($sbUpdateFlagUefiCapable -eq 64){
    Write-Host "SUCCESS: Check for CA UEFI2023 capability was running and your device had updated certificates in the boot loader see detailed values below!" -ForegroundColor Green #References here are unclear, some say so others did not mention 64
    }

$managedMSupdateForDBcert = $null
$managedMSupdateForDBcert = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name MicrosoftUpdateManagedOptIn -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn

If ($managedMSupdateForDBcert -eq $null){
    Write-Warning "Check for Microsoft managed certificate update was running and the device is NOT enabled for the Microsoft managed process!"
    }
If ($managedMSupdateForDBcert -eq '22852'){
    Write-Host "SUCCESS: Check for Microsoft managed certificate update was running and the device is enabled for the Microsoft managed process!" -ForegroundColor Green
    }

Write-Host " "
Write-Host "Device Information"

# Display Device Infos
$deviceInfo = [PSCustomObject]@{
    Device            = "--------------"
    DeviceName        = $system.Name
    SystemType        = $system.SystemType
    Manufacturer      = $system.Manufacturer
    Model             = $system.Model
    BIOS              = "--------------"
    BiosManufacturer  = $bios.Manufacturer
    SerialNumber      = $bios.SerialNumber
    BIOSDescription   = $bios.Description
    BIOSVersionName   = $bios.BIOSVersion
    BIOSVersion       = $bios.SMBIOSBIOSVersion
    BIOSReleaseDate   = $bios.ReleaseDate
}

$deviceInfo | Format-List

# Checking existing UEFI certificates
Write-Host " "
Write-Host "Checking Certs for Key Exchange Key in Firmware (KEK)..." -ForegroundColor Cyan
Write-Host "========================================================"
$kekOldCert = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).bytes) -match "Microsoft Corporation KEK CA 2011"
$kekNewCert = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).bytes) -match "Microsoft Corporation KEK CA 2023"

Write-Host "Old KEK 2011 certificate exists: $kekOldCert"
Write-Host "New KEK 2023 certificate exists: $kekNewCert"
If (($kekOldCert -eq $true) -and ($kekNewCert -eq $false)) {
 Write-Warning "Key Exchange Key (KEK) certificate is not yet updated!"
 }
If (($kekOldCert -eq $true) -and ($kekNewCert -eq $true)) {
 Write-Host "SUCCESS: Key Exchange Key (KEK) certificate is updated!" -ForegroundColor Green
 }
If (($kekOldCert -eq $false) -and ($kekNewCert -eq $true)) {
 Write-Host "SUCCESS: Key Exchange Key (KEK) certificate is the latest!" -ForegroundColor Green
 }
Write-Host "---------------------------------------------------------------------------------------"
Write-Host "Checking DB Certs in Firmware (DB)..." -ForegroundColor Cyan
Write-Host "====================================="

$winOldProdCA = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match "Microsoft Windows Production PCA 2011"
$winNewProdCA = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match "Windows UEFI CA 2023"

$3rdPartyOldUefiCA = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match "Microsoft UEFI CA 2011*"
$3rdPartyNewUefiCA = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match "Microsoft UEFI CA 2023"

$3rdPartyOldOptionRomCA = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match "Microsoft UEFI CA 2011*"
$3rdPartyNewOptionRomCA = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match "Microsoft Option ROM CA 2023"

Write-Host "Old Production PCA 2011 certificate exists  : $winOldProdCA"
Write-Host "New Production PCA 2023 certificate exists  : $winNewProdCA"
If (($winOldProdCA -eq $true) -and ($winNewProdCA -eq $false)) {
 Write-Warning "Windows Bootloader (DB) certificate is not yet updated!"
 }
If (($winOldProdCA -eq $true) -and ($winNewProdCA -eq $true)) {
 Write-Host "SUCCESS: Windows Bootloader (DB) certificate is updated!" -ForegroundColor Green
 }
If (($winOldProdCA -eq $false) -and ($winNewProdCA -eq $true)) {
 Write-Host "SUCCESS: Windows Bootloader (DB) certificate is the latest!" -ForegroundColor Green
 }

Write-Host "-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -"
Write-Host "Old 3rd Party  PCA 2011 certificate exists  : $3rdPartyOldUefiCA"
Write-Host "New 3rd Party  PCA 2023 certificate exists  : $3rdPartyNewUefiCA"
If (($3rdPartyOldUefiCA -eq $true) -and ($3rdPartyNewUefiCA -eq $false)) {
 Write-Warning "3rd Party Bootloader (DB) certificate is not yet updated!"
 }
If (($3rdPartyOldUefiCA -eq $true) -and ($3rdPartyNewUefiCA -eq $true)) {
 Write-Host "SUCCESS: 3rd Party Bootloader (DB) certificate is updated!" -ForegroundColor Green
 }
If (($3rdPartyOldUefiCA -eq $false) -and ($3rdPartyNewUefiCA -eq $false)) {
 Write-Host "SUCCESS: 3rd Party Bootloader does not apply for this system!" -ForegroundColor Green
 }
Write-Host "-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -"
Write-Host "Old 3rd Party OptRom 2011 certificate exists: $3rdPartyOldOptionRomCA"
Write-Host "New 3rd Party OptRom 2023 certificate exists: $3rdPartyNewOptionRomCA"
If (($3rdPartyOldOptionRomCA -eq $true) -and ($3rdPartyNewOptionRomCA -eq $false)) {
 Write-Warning "3rd Party Option Rom (DB) certificate is not yet updated!"
 }
If (($3rdPartyOldOptionRomCA -eq $true) -and ($3rdPartyNewOptionRomCA -eq $true)) {
 Write-Host "SUCCESS: 3rd Party Option Rom (DB) certificate is updated!" -ForegroundColor Green
 }
If (($3rdPartyOldOptionRomCA -eq $false) -and ($3rdPartyNewOptionRomCA -eq $false)) {
 Write-Host "SUCCESS: 3rd Party Option Rom does not apply for this system!" -ForegroundColor Green
 }
Write-Host "---------------------------------------------------------------------------------------"

If ($winNewProdCA -eq $true -and $3rdPartyNewUefiCA -eq $true -and $kekNewCert -eq $true ){
        Write-Host "SUCCESS: Your device had the minimum required Secure Boot certificates for Windows" -ForegroundColor Green
        $exitCode = 2
    }

If ($winNewProdCA -eq $true -and $3rdPartyNewUefiCA -eq $true -and $3rdPartyNewOptionRomCA -eq $true -and $kekNewCert -eq $true){
        Write-Host "SUCCESS: Your device had the all required Secure Boot certificates for Windows incl. 3rd party Option Roms" -ForegroundColor Green
        $exitCode =  3
    } else {
        Write-Warning "Your device is missing important Windows Secure Boot certificates to operate fully functional after June 2026"
        $exitCode =  1
    }
Write-Host " "
Write-Host "---------------------------------------------------------------------------------------"
Write-Host "Checking the boot loader files certificate signatures in UEFI partition and Windows ..."
Write-Host " "
$oldBootLoaderCert = "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
$newBootLoaderCert = "CN=Windows UEFI CA 2023, O=Microsoft Corporation, C=US"

# Mount UEFI Partition
$drive = get-firstavailabledrive
$driveName = ($drive+":")
$arguments = ($driveName+" /S")
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
$arguments = ($driveName+" /D")
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
    LogName = 'System'
    ProviderName = 'Microsoft-Windows-TPM-WMI'
    Id = $EventIDs
} | Select-Object Id, LevelDisplayName, TimeCreated, Message | Sort-Object TimeCreated -Descending

# Display as a table

$events | Format-Table @{Label="Event ID";Expression={$_.Id}},
                        @{Label="State";Expression={$_.LevelDisplayName}},
                        @{Label="Date of Occurrence";Expression={$_.TimeCreated}},
                        @{Label="Message";Expression={$_.Message}}

Stop-Transcript
Write-Host "Exitcode = $exitCode"
exit $exitCode
