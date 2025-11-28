# Uefi Secure Boot Certificate check and remediation scripts 
Powershell Scripts to check the UEFI secure boot certificates and start the remediation (Windows 2023 UEFI certificates)
For more informations from Microsoft around this topic please visit https://aka.ms/getsecureboot

Why is this here needed?

There is no general Intune functionality available for this issue. Its required to track specific registry keys and files and report on them for progress.
Therefore this workaround solution is developed to make sure this is happening. Especially as we need to track BIOS updates and only act when certain versions are reached!

What you need in place is:
1. A corporate Azure Subscription (for Azure Log Analytics to track status and progress)
2. Intune (to run detection and remediation scripts, to provide BIOS updates via Windows Update for Business)

This solution is currently in development (ALPHA).

The check script is working already but not yet optimized to run as an Intune remediation script yet.

The final solution process is planned:

1. Check if the device is already prepared (all the certificates, bootloaders, DB, KEK etc. is in place) and report this to Azure Log Analytics
2. If your device is not yet prepared we will check if the Bios is already supported with a public repository (Community support is required for this! A private repository is planned as well!)
3. If the BIOS is supported the remediation script will add the required registry keys
5. Progress and success will be logged in Azure Log Analytics

## Please be aware this is a best effort solution and there is NO WARRANTY and WE ARE NOT LIABLE FOR ANY ISSUES OR DAMAGES you will have.

Some of the authors are tech consultants having 100k+ devices in their companies or customer companies and therefore we try to be as cautious as possible while still dealing with this.


