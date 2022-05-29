<#
.SYNOPSIS
    Patch termsrv.dll so that multiple remote users can open an RDP session on a non-Windows Server computer.
.DESCRIPTION
    This script patches the termsrv.dll file, changing a binary string to allow multiple simultaneous sessions
    via Remote Desktop Connection (RDP) on non-Windows Server computers.
.LINK
    http://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10
    https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10
#>
