# SANtricity_Automation
Script for deploying and implementing basic configuration for SANtricity system

## How to run?
The script use dynamic variable for getting root folder. Keep all file structure as presented

1. login for the first time to SANtricity gui for setting new password
2. change dir to script location and run:
```
./Configuring_SANtricity -username <admin> -password <some plain password> -ipaddress <ip of cluster>
```
3. follow the output per section.

## Requirements
Powershell v3 + <br>
No special modules are requires

## Things to know
1. ALL script must run first to end and not partially because of dependencies from one section to others
2. Use at your own risk

