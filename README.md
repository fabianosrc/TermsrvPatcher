# TermsrvPatcher
![Environment](https://img.shields.io/badge/Windows-7,%2010-brightgreen.svg)
![license](https://img.shields.io/github/license/fabianomsrc/TermsrvPatcher)

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
Download TermsrvPatcher.ps1 file and place it in any folder e.g.

```txt
C:\Users\YourUserName\Downloads
```

Go to the folder your script is in

> PowerShell Cmdlet

```powershell
Set-Location -Path C:\Users\YourUserName\Downloads
```
> CMD syntax

```cmd
cd c:\Users\YourUserName\Downloads
```
> Run the script
```powershell
.\TermsrvPatcher.ps1
```

#### Supported Terminal Services versions:
 - Windows 7 Pro SP1 64-bit
 - Windows 10 Pro 21H1 64-bit
 - Windows 10 Pro 21H1 64-bit
