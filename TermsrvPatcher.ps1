#Requires -Version 5.1

<#PSScriptInfo

.VERSION 1.0

.GUID 41543292-9400-41d5-8bb8-5fe43f167a03

.AUTHOR Fabiano Silva

.COPYRIGHT Copyright (c) Fabiano Silva

.TAGS Windows PowerShell Multiple RDP

.PROJECTURI https://github.com/fabianosrc/TermsrvPatcher

#>

<#
.SYNOPSIS
    Patch termsrv.dll so that multiple remote users can open an RDP session on a non-Windows Server computer
.DESCRIPTION
    This script patches the termsrv.dll file to allow multiple simultaneous sessions via
    Remote Desktop Connection (RDP) on non-Windows Server computers
.LINK
    http://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10
    https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10
#>

# Self-elevate the script so with a UAC prompt since this script needs to be run as an Administrator in order to function properly
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    switch ((Get-Culture).Name) {
        'pt-BR' { Write-Host 'Você não executou este script como Administrador. Este script será executado automaticamente como Administrador.' -ForegroundColor Green }
        Default { Write-Host 'You didn''t run this script as an Administrator. This script will self elevate to run as an Administrator and continue.' -ForegroundColor Green }
    }

    Start-Sleep -Milliseconds 2500
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit
}

$windowsVersion = [System.Environment]::OSVersion.Version
$OSArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

$termsrvDllFile = "$env:SystemRoot\System32\termsrv.dll"
$termsrvPatched = "$env:SystemRoot\System32\termsrv.dll.patched"

function Get-FullOSBuildNumber {
    $currentBuild = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild
    $updateBuildRevision = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR

    return $currentBuild, $updateBuildRevision -join '.'
}

if ((Get-Service -Name TermService).Status -eq 'Running') {
    switch ((Get-Culture).Name) {
        'pt-BR' { Write-Host $("O serviço $((Get-Service -Name TermService).DisplayName) será encerrado agora.") -ForegroundColor Green }
        Default { Write-Host $("The $((Get-Service -Name TermService).DisplayName) service is stopping now.") -ForegroundColor Green }
    }

    Start-Sleep -Milliseconds 2500
    Stop-Service -Name TermService -Force
}

if ((Get-Service -Name UmRdpService).Status -eq 'Running') {
    switch ((Get-Culture).Name) {
        'pt-BR' { Write-Host $("O serviço $((Get-Service -Name UmRdpService).DisplayName) será encerrado agora.") -ForegroundColor Green }
        Default { Write-Host $("The $((Get-Service -Name UmRdpService).DisplayName) service is stopping now.") -ForegroundColor Green }
    }

    Start-Sleep -Milliseconds 2500
    Stop-Service -Name UmRdpService -Force
}

# Save Access Control List (ACL) of termsrv.dll file.
$termsrvDllAcl = Get-Acl -Path $termsrvDllFile

Write-Host "Owner of termsrv.dll: $($termsrvDllAcl.Owner)"

# Create a backup of the original termsrv.dll file.
Copy-Item -Path $termsrvDllFile -Destination "$env:SystemRoot\System32\termsrv.dll.copy"

# Take ownership of the DLL...
takeown.exe /F $termsrvDllFile

# Get Current User logged in
$currentUserName = (Get-WmiObject -Class Win32_ComputerSystem).UserName

# Grant full control to the currently logged in user.
icacls.exe $termsrvDllFile /grant "$($currentUserName):F"

# Read termsrv.dll as byte array to modify bytes
$dllAsByte = Get-Content -Path $termsrvDllFile -Raw -Encoding Byte

# Convert the byte array to a string that represents each byte value as a hexadecimal value, separated by spaces
$dllAsText = ($dllAsByte | ForEach-Object { $_.ToString('X2') }) -join ' '

# OS is Windows 7
if ($windowsVersion.Major -eq '6' -and $windowsVersion.Minor -eq '1') {
    if ($OSArchitecture -eq '32-bit') {

    }
    else {
        switch ($(Get-FullOSBuildNumber)) {
            '7601.23964' {
                $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 2F C3 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                -replace '83 7C 24 50 00 74 18 48 8D', '83 7C 24 50 00 EB 18 48 8D'
            }
            Default {}
        }
    }
}

# OS is Windows 10
if ($windowsVersion.Major -eq '10') {
    if ($OSArchitecture -eq '32-bit') {

    }
    else {
        switch ($(Get-FullOSBuildNumber)) {
            '19044.1826' { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 73 55 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
            '19044.1741' { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 73 55 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
            '19044.1706' { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 2B 86 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
            '19045.2251' { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 85 45 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
            '19045.2546' { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 85 45 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
            '19045.2913' { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 25 48 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
            Default { $dllAsTextReplaced = $dllAsText -replace '39 81 3C 06 00 00 0F 84 85 45 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' }
        }
    }
}

# Use the replaced string to create a byte array again.
[byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'

# Create termsrv.dll.patched from the byte array.
Set-Content -Path $termsrvPatched -Value $dllAsBytesReplaced -Encoding Byte

# Compares termsrv.dll with tersrv.dll.patched and displays the differences between them.
fc.exe /B $termsrvDllFile $termsrvPatched

# Overwrite original DLL with patched version:
Copy-Item -Path $termsrvPatched -Destination $termsrvDllFile

# Restore original Access Control List (ACL):
Set-Acl -Path $termsrvDllFile -AclObject $termsrvDllAcl

Start-Sleep -Seconds 4

# Start services again...
Start-Service TermService
Start-Service UmRdpService
