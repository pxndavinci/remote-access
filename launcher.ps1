# ============================================================
# Secure Remote Access Launcher
# Host this on GitHub Gist (public) — contains zero secrets
# Invoke via: irm bit.ly/yourlink | iex
# ============================================================

$BACKEND_URL = "https://remote-access-worker.yourname.workers.dev"
$SSH_TARGET  = "100.87.37.57"      # Your home machine's Tailscale IP
$SSH_USER    = "pxanda"
$SSH_PORT    = 22
$TS_INSTALL  = "C:\Program Files\Tailscale\tailscale.exe"
$TS_SVC      = "Tailscale"

# ── Elevate to admin if not already ──────────────────────────────────────────
if (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $cmd = "irm bit.ly/yourlink | iex"
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -Command `"$cmd`""
    exit
}

# ── UI ────────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║    Secure Remote Access Launcher     ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Install Tailscale silently if not present ────────────────────────
function Install-Tailscale {
    if (Test-Path $TS_INSTALL) {
        Write-Host "  [1/4] Tailscale already installed" -ForegroundColor DarkGray
        return
    }
    Write-Host "  [1/4] Installing Tailscale silently..." -ForegroundColor Gray
    $tmp = "$env:TEMP\ts-setup.exe"
    Invoke-WebRequest "https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe" `
        -OutFile $tmp -UseBasicParsing -ErrorAction Stop
    Start-Process $tmp -ArgumentList "/S /norestart" -Wait -NoNewWindow
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Stop-Service  -Name $TS_SVC -Force              -ErrorAction SilentlyContinue
    Set-Service   -Name $TS_SVC -StartupType Disabled -ErrorAction SilentlyContinue
    foreach ($hive in @("HKCU", "HKLM")) {
        Remove-ItemProperty `
            -Path "$hive`:\Software\Microsoft\Windows\CurrentVersion\Run" `
            -Name "Tailscale" -ErrorAction SilentlyContinue
    }
    Get-Process -Name "Tailscale" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "  [1/4] Tailscale installed (no tray, no autostart) ✓" -ForegroundColor Green
}

# ── Step 2: Send OTP to worker, get back ephemeral Tailscale key ──────────────
function Get-EphemeralKey {
    Write-Host "  [2/4] Authentication" -ForegroundColor Gray
    Write-Host ""
    $attempts = 0
    while ($attempts -lt 3) {
        $otp = Read-Host "        Enter 6-digit code from Authy"
        if ($otp -notmatch '^\d{6}$') {
            Write-Host "        [!] Must be exactly 6 digits" -ForegroundColor Red
            $attempts++
            continue
        }
        try {
            $response = Invoke-RestMethod `
                -Uri         $BACKEND_URL `
                -Method      POST `
                -Body        (@{ otp = $otp } | ConvertTo-Json) `
                -ContentType "application/json" `
                -TimeoutSec  15
            Write-Host ""
            Write-Host "  [2/4] Verified ✓" -ForegroundColor Green
            return $response.key
        } catch {
            $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
            $msg = if ($err.error) { $err.error } else { "Could not reach server" }
            Write-Host "        [!] $msg" -ForegroundColor Red
            $attempts++
        }
    }
    Write-Host "  [!] Too many failed attempts." -ForegroundColor Red
    return $null
}

# ── Step 3: Connect Tailscale with the ephemeral key ─────────────────────────
function Connect-VPN ($key) {
    Write-Host "  [3/4] Connecting to VPN..." -ForegroundColor Gray
    Set-Service   -Name $TS_SVC -StartupType Manual -ErrorAction SilentlyContinue
    Start-Service -Name $TS_SVC -ErrorAction Stop
    & $TS_INSTALL up --authkey=$key --reset --accept-routes 2>&1 | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep 1
        $s = & $TS_INSTALL status --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($s.BackendState -eq "Running") {
            Write-Host "  [3/4] VPN connected ✓" -ForegroundColor Green
            return $true
        }
    }
    Write-Host "  [!] VPN failed to connect." -ForegroundColor Red
    return $false
}

# ── Step 4: Open SSH session (blocks here until user types exit) ──────────────
function Start-SSHSession {
    Write-Host ""
    Write-Host "  [4/4] Opening SSH session..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  Type  exit  to close and disconnect    │" -ForegroundColor DarkGray
    Write-Host "  └─────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""
    ssh -p $SSH_PORT -o StrictHostKeyChecking=accept-new "$SSH_USER@$SSH_TARGET"
}

# ── Cleanup: always runs even if user hits Ctrl+C ────────────────────────────
function Disconnect-All {
    Write-Host ""
    Write-Host "  [*] Disconnecting..." -ForegroundColor Yellow
    & $TS_INSTALL down   2>&1 | Out-Null
    & $TS_INSTALL logout 2>&1 | Out-Null
    Stop-Service -Name $TS_SVC -Force              -ErrorAction SilentlyContinue
    Set-Service  -Name $TS_SVC -StartupType Disabled -ErrorAction SilentlyContinue
    Get-Process  -Name "Tailscale*" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "  [✓] VPN disconnected" -ForegroundColor Green
    Write-Host "  [✓] Device removed from your network" -ForegroundColor Green
    Write-Host "  [✓] Tailscale disabled — will not start on next boot" -ForegroundColor Green
    Write-Host ""
    Read-Host "  Press Enter to close"
}

# ── Main ──────────────────────────────────────────────────────────────────────
try {
    Install-Tailscale
    $key = Get-EphemeralKey
    if (-not $key) { exit 1 }
    $ok = Connect-VPN $key
    if (-not $ok) { Disconnect-All; exit 1 }
    Start-SSHSession
} finally {
    Disconnect-All
}
