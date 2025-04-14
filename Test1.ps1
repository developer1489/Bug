# Minimal logging and stealthy privilege enumeration
Write-Host "== System Info =="
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture

Write-Host "`n== User Info =="
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "Username: $($me.Name)"
Write-Host "SID: $($me.User.Value)"

Write-Host "`n== Privileges (High-Value) =="
$highPrivs = @(
    'SeImpersonatePrivilege', 
    'SeAssignPrimaryTokenPrivilege', 
    'SeTcbPrivilege',
    'SeBackupPrivilege', 
    'SeRestorePrivilege'
)
$me.UserClaims | ForEach-Object {
    if ($highPrivs -contains $_.Right) {
        Write-Host $_.Right
    }
}

Write-Host "`n== Print Spooler Status =="
(Get-Service -Name Spooler -ErrorAction SilentlyContinue).Status

Write-Host "`n== Unquoted Service Paths =="
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch '^".*"$' -and $_.PathName -match ' '
} | Select-Object Name, PathName

Write-Host "`n== AlwaysInstallElevated Check =="
$ae1 = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$ae2 = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
Write-Host "HKLM: $ae1"
Write-Host "HKCU: $ae2"

Write-Host "`n== Writable Directories in PATH =="
$env:Path -split ';' | ForEach-Object {
    if (Test-Path $_) {
        $access = (Get-Acl $_).Access
        foreach ($entry in $access) {
            if ($entry.FileSystemRights -match 'Write' -and $entry.AccessControlType -eq 'Allow') {
                Write-Host "Writable: $_ by $($entry.IdentityReference)"
            }
        }
    }
}
