#Requires -Version 5.1

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

$termsrvDll = 'C:\Windows\System32\termsrv.dll'
$termsrvCopy = 'C:\Windows\System32\termsrv.dll.copy'
$termsrvPatched = 'C:\Windows\System32\termsrv.dll.patched'

# Remote Desktop Services
$termServiceStatus = (Get-Service -Name TermService).Status

# Remote Desktop Services UserMode Port Redirector
$umRdpServiceStatus = (Get-Service -Name UmRdpService).Status

Write-Output "Status of service UmRdpService: $umRdpServiceStatus"
Write-Output "Status of service TermService: $termServiceStatus"

if ($termServiceStatus -eq 'Running') {
    Stop-Service TermService -Force
}

if ($umRdpServiceStatus -eq 'Running') {
    Stop-Service UmRdpService -Force
}

# Save Access Control List (ACL) of termsrv.dll file.
$termsrvDllAcl = Get-Acl -Path $termsrvDll

Write-Host "Owner of termsrv.dll: $($termsrvDllAcl.Owner)"

# Create a backup of the original termsrv.dll file.
Copy-Item -Path $termsrvDll -Destination $termsrvCopy

# Take ownership of the DLL...
takeown.exe /F $termsrvDll

# Get Current User logged in
$currentUserName = (Get-WmiObject -Class Win32_ComputerSystem).UserName

# Grant full control to the currently logged in user.
icacls.exe $termsrvDll /grant "$($currentUserName):F"

# Read DLL as byte array in order to modify the bytes.
$dllAsBytes = Get-Content -Path $termsrvDll -Encoding Byte -Raw

# Convert the byte array to a string that represents each byte value as a hexadecimal value, separated by spaces.
$dllAsText = $dllAsBytes.ForEach('ToString', 'X2') -join ' '

function Get-FullWindowsBuildNumber {
    $currentBuild = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild

    $updateBuildVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR

    return $("$currentBuild.$updateBuildVersion")
}

# Search for byte array (which depends on Windows edition) and replace them.
switch ($(Get-FullWindowsBuildNumber)) {
    '19044.1706' { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 2B 86 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
    '7601.23964' { $dllAsTextReplaced = $dllAsText -replace '3B 86 20 03 00 00 0F 84 03 15 01 00 57 6A 20 E8', 'B8 00 01 00 00 90 89 86 20 03 00 00 57 6A 20 E8' }
    Default { Write-Host 'Xii, deu ruim'}
}

# Use the replaced string to create a byte array again.
[byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'

# Create termsrv.dll.patched from the byte array.
Set-Content -Path $termsrvPatched -Value $dllAsBytesReplaced -Encoding Byte

<#
.SYNOPSIS
    Compares the original termsrv.dll file and the patched file.
.DESCRIPTION
    Compares two files or sets of files and displays the differences between them.
.EXAMPLE
    PS C:\> fc.exe C:\Windows\System32\termsrv.dll C:\Windows\System32\termsrv.dll.patched

    00017BB5: 39 B8
    00017BB6: 81 00
    00017BB7: 3C 01
    00017BB8: 06 00
    00017BBA: 00 89
    00017BBB: 0F 81
    00017BBC: 84 38
    00017BBD: 2B 06
    00017BBE: 86 00
    00017BBF: 01 00
    00017BC0: 00 90
#>
fc.exe /B $termsrvDll $termsrvPatched

# Overwrite original DLL with patched version:
Copy-Item -Path $termsrvPatched -Destination $termsrvDll

# Restore original Access Control List (ACL):
Set-Acl -Path $termsrvDll -AclObject $termsrvDllAcl

if ($termServiceStatus -eq 'Stopped') {
    Start-Service TermService -Force
}

if ($umRdpServiceStatus -eq 'Stopped') {
    Start-Service UmRdpService -Force
}
