# TermsrvPatcher
![Environment](https://img.shields.io/badge/Windows-7,%2010,%2011-brightgreen.svg)
![License](https://img.shields.io/github/license/fabianomsrc/TermsrvPatcher)
[![Hits](https://hits.sh/github.com/fabianomsrc/TermsrvPatcher.svg)](https://github.com/fabianosrc/RDPControl)

---

> A new, more complete solution is available: **[RDPControl](https://github.com/fabianosrc/RDPControl)**
>
> RDPControl is a full PowerShell module that covers everything TermsrvPatcher did — and much more:
>
> - ✅ Multi-session configuration with `-DryRun` preview
> - ✅ Automatic snapshot and restore
> - ✅ Self-healing watchdog (survives Windows Updates automatically)
> - ✅ Port management and firewall rules
> - ✅ User access control
> - ✅ Session management
> - ✅ Full audit trail
> - ✅ PowerShell Gallery ready
>
> 👉 **[Migrate to RDPControl](https://github.com/fabianosrc/RDPControl)**

---

# Windows 11 25H2 support added!

Patch termsrv.dll so that multiple remote users can open an RDP session on a non-Windows Server computer

## Credits
This work is based on the [patch-termsrv.dll](https://github.com/ReneNyffenegger/patch-termsrv.dll) project by Rene Nyffenegger

## Links
[How to Allow Multiple RDP Sessions in Windows 10 and 11?](http://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10)

[Multiple RDP (Remote Desktop) sessions in Windows 10](https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10)

## Prerequisites
Requires PowerShell 5.1 or higher

[Download and install Windows PowerShell 5.1](https://www.microsoft.com/en-us/download/details.aspx?id=54616)

---

### How to use

Download `TermsrvPatcher.ps1` and place it in any folder, then run:

```powershell
.\TermsrvPatcher.ps1
```

---

## Automate on Boot
To run the script automatically after updates, import the task into Windows Task Scheduler:

1. **Open Task Scheduler**: Run `taskschd.msc`.
2. **Import**: Select _Action_ > _Import Task..._ and choose [TermsrvPatcherScheduledTask.xml](TermsrvPatcherScheduledTask.xml).
3. **Configure Path**: The default path is `C:\TermsrvPatcher.ps1`. If your script is elsewhere, go to _Actions_ > _Edit_ and update the script path in the _Arguments_ input.

> **Security notice:** The scheduled task runs as SYSTEM with `HighestAvailable` privileges and passes `-ExecutionPolicy Bypass` to PowerShell. These settings are required because the task must modify a protected system file (`termsrv.dll`) without a UAC prompt at boot. The practical consequence is that **whoever controls the script file controls what runs as SYSTEM** — ensure `TermsrvPatcher.ps1` is stored in a location writable only by Administrators (e.g. `C:\` or `C:\Program Files`), not in a user-writable folder such as `Downloads` or `AppData`. Do not use this scheduled task on shared or multi-tenant systems where non-administrator users could replace the script.


# Supported Terminal Services versions:
 - Windows 7 Pro SP1 64-bit
 - Windows 10
 - Windows 11 22H2, 23H2, 24H2, 25H2
 - Windows Server 2016
 - Windows Server 2019
 - Windows Server 2022 (including Datacenter Azure Edition / HCI, build 25398)
 - Windows Server 2025

---

### See also

👉 **[RDPControl](https://github.com/fabianosrc/RDPControl)** — the recommended replacement for this project.