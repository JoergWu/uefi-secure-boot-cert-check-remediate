# UEFI Secure Boot Certificate check and remediation scripts 
Powershell Scripts to check the UEFI secure boot certificates and start the remediation (Windows 2023 UEFI certificates)
For more informations from Microsoft around this topic please visit https://aka.ms/getsecureboot

## Why is this here needed?

There is no general Intune functionality available for this issue. Its required to track specific registry keys and files and report on them for progress.
Therefore this workaround solution is developed to make sure this is happening. Especially as we need to track BIOS updates and only act when certain versions are reached!

Also please keep in mind this issue is related to the fact that UEFI uses certificates (which is a great idea in terms of security) to protect any UEFI bootloaders (Windows, Linux, Mac, etc).
But the drawback of certificates is that they will expire. Even when we had about 15 years next year in June 2026 is the first time this need to be exchanged. Microsoft added support for this already a while ago but now also the Hardware Vendors adding support in their BIOS versions as well.  

This is a complex certificate dependency thing which involves close OEM vendor support. So its not just deploying a Microsoft Update and thats it! You need to update the BIOS of your devices. Many OEMs limit the support to devices they have still under support. In general often devices older than 5 years are not considered to get updates. Some provide more time.  

HP for example does not provide BIOS update support for devices sold before 2018 (in terms of clients, servers are supported longer!). Which is quite fair. They cover devices from 2018 which is in June 2026 already 8.5 years.

### What you need in place is:
1. A corporate Azure Subscription (for Azure Log Analytics to track status and progress)
2. Intune (to run detection and remediation scripts, to provide BIOS updates via Windows Update for Business)

This solution is currently in development (ALPHA).

The check script is working already but not yet optimized to run as an Intune remediation script yet.

### The final solution process is planned:

1. Check if the device is already prepared (all the certificates, bootloaders, DB, KEK etc. is in place) and report this to Azure Log Analytics
2. If your device is not yet prepared we will check if the Bios is already supported with a public repository (Community support is required for this! A private repository is planned as well!)
3. If the BIOS is supported the remediation script will add the required registry keys
5. Progress and success will be logged in Azure Log Analytics

### OEM Vendor Support Statements (revisit them as they update their lists regularly):

HP (Clients) https://support.hp.com/ie-en/document/ish_13070353-13070429-16
HP Enterprise (Servers)  coming soon
Dell (Clients) https://www.dell.com/support/kbdoc/en-us/000347876/microsoft-2011-secure-boot-certificate-expiration
Dell (Servers) https://www.dell.com/support/kbdoc/en-us/000362511/microsoft-secure-boot-2011-certificate-expiration-impact-on-dell-poweredge-servers
Lenovo (Clients) https://support.lenovo.com/us/en/solutions/HT518129
Lenovo (Servers)  coming soon
Fujitsu (Clients) coming soon
Fujitsu (Servers) coming soon

Microsoft (Clients) https://support.microsoft.com/en-us/surface/surface-secure-boot-certificates-532abf3b-bafe-420f-b615-bf174105549e

## Please be aware this is a best effort solution and there is NO WARRANTY and WE ARE NOT LIABLE FOR ANY ISSUES OR DAMAGES you will have.

Some of the authors are tech consultants having 100k+ devices in their companies or customer companies and therefore we try to be as cautious as possible while still dealing with this.


