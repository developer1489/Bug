# PrivilegeEscalationCheck.ps1
Write-Host "=== Basic System Info ==="
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

Write-Host "`n=== Current User Info ==="
Write-Host "Username: $(whoami)"
whoami /groups
whoami /priv

Write-Host "`n=== Privileges to Look Out For ==="
$privs = whoami /priv
$privs | findstr "SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege SeTcbPrivilege SeBackupPrivilege SeRestorePrivilege"

Write-Host "`n=== Spooler Service Check ==="
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler) {
    Write-Host "Spooler Status: $($spooler.Status)"
} else {
    Write-Host "Spooler Service not found."
}

Write-Host "`n=== Unquoted Service Paths ==="
Get-WmiObject win32_service | Where-Object {
    ($_.PathName -notlike '"*') -and
    ($_.PathName -match ' ')
} | Select-Object Name, DisplayName, PathName

Write-Host "`n=== Checking for AlwaysInstallElevated ==="
$reg1 = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
$reg2 = Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
Write-Host "HKLM: AlwaysInstallElevated = $($reg1.AlwaysInstallElevated)"
Write-Host "HKCU: AlwaysInstallElevated = $($reg2.AlwaysInstallElevated)"

Write-Host "`n=== DLL Hijacking Candidates (Path Environment) ==="
$env:Path.Split(";") | ForEach-Object {
    if (Test-Path $_) {
        $acl = Get-Acl $_
        if ($acl.AccessToString -match "Everyone\s+Allow\s+Modify" -or $acl.AccessToString -match "$env:USERNAME\s+Allow\s+Modify") {
            Write-Host "Writable by current user: $_"
        }
    }
}
