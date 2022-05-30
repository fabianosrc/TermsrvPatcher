# TermsrvPatcher
Patch termsrv.dll so that multiple remote users can open an RDP session on a non-Windows Server computer

## Credits
This work is based on the [patch-termsrv.dll](https://github.com/ReneNyffenegger/patch-termsrv.dll) project by Rene Nyffenegger

## Links
[How to Allow Multiple RDP Sessions in Windows 10 and 11?](http://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10)

[Multiple RDP (Remote Desktop) sessions in Windows 10](https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10)

## Prerequisites
Requires PowerShell 5.1 or higher

[Download and install Windows PowerShell 5.1](https://docs.microsoft.com/en-us/skypeforbusiness/set-up-your-computer-for-windows-powershell/download-and-install-windows-powershell-5-1)

# How to use
Download TermsrvPatcher.ps1 file and place it in any folder e.g. 'C:\Users\YourUserName\Downloads'

Run PowerShell as Administrator

Go to the folder your script is in

> PowerShell Cmdlet

```powershell
Set-Location -Path C:\Users\YourUserName\Downloads
```

> CMD

```cmd
cd c:\Users\YourUserName\Downloads
```

Before running the script, need to change PowerShell script execution policy

```powershell
Set-ExecutionPolicy Unrestricted
```
Run the script
```powershell
.\TermsrvPatcher.ps1
```

If you don't want to change it right now, you can bypass it and use the command below

```powershell
powershell -ExecutionPolicy Bypass -NoProfile -NonInteractive -File C:\Users\YourUserName\Downloads\TermsrvPatcher.ps1
```
