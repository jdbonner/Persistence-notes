# Persistence-notes
for test
# Windows persistence checklist 
**Powershell profiles** PowerShell profiles are a convenient way to store PowerShell configuration information as well as personalized aliases and functions to persistent use in every PowerShell session.

Malware is running on the primary PowerShell profile on the File-Server. Based on PowerShell profile order of precedence (what is read first), find the correct flag Run get-content on each profile path

$PsHome\Profile.ps1

$PsHome\Microsoft.PowerShell_profile.ps1

$Home[My]Documents\Profile.ps1

$Home[My ]Documents\WindowsPowerShell\Profile.ps1
```
answer 
PS C:\Users\andy.dwyer> get-content $PsHome\Profile.ps1
# I am definitely not the malware
```
# Windows Registry 
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
https://os.cybbh.io/public/os/latest/004_windows_registry/primer.html
# window services

# sysinternals




# linux process

Cat into them looking anything weirdcat

/etc/rc*d
/etc/init This will boot system
/etc/inittab **Important to look into for files**
/etc/systemd/*
/lib/systemd/system/*
/run/systemd/generation/*
Look for services in units when looking for persistence
/etc/profile
/etc/bash.bashrc
/etc/profile.d
/etc/environment

Look into crontab






