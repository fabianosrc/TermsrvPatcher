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
$OSArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture

$termsrvDllFile = "$env:SystemRoot\System32\termsrv.dll"
$termsrvPatched = "$env:SystemRoot\System32\termsrv.dll.patched"

$patterns = @{
    Pattern = [regex]'39 81 3C 06 00 00 0F (?:[0-9A-F]{2} ){4}00'
    Win24H2 = [regex]'8B 81 38 06 00 00 39 81 3C 06 00 00 75'
}

function Get-OSInfo {
    $OSInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    [PSCustomObject]@{
        CurrentBuild = $OSInfo.CurrentBuild
        BuildRevision = $OSInfo.UBR
        FullOSBuild = "$($OSInfo.CurrentBuild).$($OSInfo.UBR)"
        DisplayVersion = $OSInfo.DisplayVersion
    }
}

function Update-Dll {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [regex]$InputPattern,

        [Parameter(Mandatory)]
        [string]$Replacement,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsText,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsFile,

        [Parameter(Mandatory)]
        [string]$TermsrvDllAsPatch,

        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSecurity]$TermsrvAclObject
    )

    begin {
        $match = $TermsrvDllAsText -match $InputPattern
    }

    process {
        if ($match) {
            Write-Host "`nPattern matching!`n" -ForegroundColor Green

            $dllAsTextReplaced = $TermsrvDllAsText -replace $InputPattern, $Replacement

            # Use the replaced string to create a byte array again.
            [byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'

            # Create termsrv.dll.patched from the byte array.
            [System.IO.File]::WriteAllBytes($TermsrvDllAsPatch, $dllAsBytesReplaced)

            fc.exe /B $TermsrvDllAsPatch $TermsrvDllAsFile
            <#
            .DESCRIPTION
                Compares termsrv.dll with tersrv.dll.patched and displays the differences between them.
            .NOTES
                Expected output something like:

                00098BA2: B8 8B
                00098BA3: 00 99
                00098BA4: 01 30
                00098BA5: 00 03
                00098BA7: 89 00
                00098BA8: 81 8B
                00098BA9: 38 B1
                00098BAA: 06 34
                00098BAB: 00 03
                00098BAD: 90 00
            #>

            Start-Sleep -Milliseconds 1500

            # Overwrite original DLL with patched version:
            Copy-Item -Path $TermsrvDllAsPatch -Destination $TermsrvDllAsFile -Force
        } else {
            Write-Warning -Message 'The pattern was not found. Therefore, no changes will be made.'
        }

        # Restore original Access Control List (ACL):
        Set-Acl -Path $TermsrvDllAsFile -AclObject $TermsrvAclObject

        # Start services again...
        Start-Service TermService -PassThru
    }
}

if ((Get-Service -ServiceName TermService).Status -eq 'Running') {
    while ((Get-Service -ServiceName TermService).Status -ne 'Stopped') {
        try {
            Stop-Service -ServiceName TermService -Force -PassThru
            Start-Sleep -Milliseconds 1500
        } catch {
            Write-Warning -Message $_.Exception.Message
        }
    }
}

# Save Access Control List (ACL) of termsrv.dll file.
$termsrvDllAcl = Get-Acl -Path $termsrvDllFile

Write-Host "Owner of termsrv.dll: $($termsrvDllAcl.Owner)"

# Create a backup of the original termsrv.dll file.
Copy-Item -Path $termsrvDllFile -Destination "$env:SystemRoot\System32\termsrv.dll.copy" -Force

# Take ownership of the DLL...
takeown.exe /F $termsrvDllFile

# Get Current logged in user (changed by .NET class, because in remote connection WMI Object cannot retrieve the user)
$currentUserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Grant full control to the currently logged in user.
icacls.exe $termsrvDllFile /grant "$($currentUserName):F"

# Read termsrv.dll as byte array to modify bytes
$dllAsByte = [System.IO.File]::ReadAllBytes($termsrvDllFile)

# Convert the byte array to a string that represents each byte value as a hexadecimal value, separated by spaces
$dllAsText = ($dllAsByte | ForEach-Object { $_.ToString('X2') }) -join ' '

# OS is Windows 7
if ($windowsVersion.Major -eq '6' -and $windowsVersion.Minor -eq '1') {
    if ($OSArchitecture -eq '32-bit') {
    } else {
        switch ((Get-OSInfo).FullOSBuild) {
            '7601.23964' {
                $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 2F C3 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                -replace '83 7C 24 50 00 74 18 48 8D', '83 7C 24 50 00 EB 18 48 8D'
            }
            '7601.24546' {
                $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                -replace '83 7C 24 50 00 74 43 48 8D', '83 7C 24 50 00 EB 18 48 8D'
            }
            Default {
                $dllAsTextReplaced = $dllAsText -replace '8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 3E C4 00 00', 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90' `
                -replace '4C 24 60 BB 01 00 00 00', '4C 24 60 BB 00 00 00 00' `
                -replace '83 7C 24 50 00 74 43 48 8D', '83 7C 24 50 00 EB 18 48 8D'
            }
        }
    }

    # Use the replaced string to create a byte array again.
    [byte[]] $dllAsBytesReplaced = -split $dllAsTextReplaced -replace '^', '0x'

    # Create termsrv.dll.patched from the byte array.
    [System.IO.File]::WriteAllBytes($termsrvPatched, $dllAsBytesReplaced)

    fc.exe /B $termsrvPatched $termsrvDllFile
    <#
    .DESCRIPTION
        Compares termsrv.dll with tersrv.dll.patched and displays the differences between them.
    .NOTES
        Expected output something like:

        00098BA2: B8 8B
        00098BA3: 00 99
        00098BA4: 01 30
        00098BA5: 00 03
        00098BA7: 89 00
        00098BA8: 81 8B
        00098BA9: 38 B1
        00098BAA: 06 34
        00098BAB: 00 03
        00098BAD: 90 00
    #>

    Start-Sleep -Milliseconds 1500

    # Overwrite original DLL with patched version:
    Copy-Item -Path $termsrvPatched -Destination $termsrvDllFile -Force

    # Restore original Access Control List (ACL):
    Set-Acl -Path $termsrvDllFile -AclObject $termsrvDllAcl

    Start-Sleep -Milliseconds 2500

    # Start services again...
    Start-Service TermService -PassThru
}

# OS is Windows 10
if ($windowsVersion.Major -eq '10' -and $windowsVersion.Build -lt '2200') {
    $params = @{
        InputPattern = $patterns.Pattern
        Replacement = [string]'B8 00 01 00 00 89 81 38 06 00 00 90'
        TermsrvDllAsText = $dllAsText
        TermsrvDllAsFile = $termsrvDllFile
        TermsrvDllAsPatch = $termsrvPatched
        TermsrvAclObject = $termsrvDllAcl
    }

    Update-Dll @params

    # OS is Windows 11
} elseif ($windowsVersion.Major -eq '10' -and $windowsVersion.Build -gt '2200') {
    if ((Get-OSInfo).DisplayVersion -eq '24H2') {
        $params = @{
            InputPattern = $patterns.Win24H2
            Replacement = [string]'B8 00 01 00 00 89 81 38 06 00 00 90 EB'
            TermsrvDllAsText = $dllAsText
            TermsrvDllAsFile = $termsrvDllFile
            TermsrvDllAsPatch = $termsrvPatched
            TermsrvAclObject = $termsrvDllAcl
        }

        Update-Dll @params
    }
} else {
    Write-Warning 'Unable to get Windows version'
}
