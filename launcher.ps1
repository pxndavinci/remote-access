# ============================================================
# Secure Remote Access Launcher  ->  archie
# Served by gatekeeper.py over GET; contains zero secrets.
# Invoke:  irm https://remote.joatverse.com/archie | iex
#
# Tailscale lifecycle rule:
#   already installed  -> use it, leave it installed on exit
#   not installed      -> install silently, uninstall it on exit
#
# STYLE CONSTRAINTS - do not "tidy" these away:
#   1. ASCII only. No box-drawing, no check marks, no arrows. This text is
#      fetched by Invoke-RestMethod and piped to iex; if the charset is
#      mis-decoded, non-ASCII bytes turn into mojibake inside string literals.
#   2. No multi-line expressions and no backtick line continuations. Windows
#      PowerShell 5.1 fails to continue an expression across a newline when the
#      script arrives as one string through iex - that is a real parse error,
#      not a theoretical one.
# ============================================================

$BACKEND_URL = "{{BACKEND_URL}}"          # substituted by gatekeeper.py on GET
$SSH_USER    = "pxanda"
$SSH_HOST    = "archie.tailcf16e4.ts.net" # MagicDNS name
$SSH_HOST_IP = "100.87.37.57"             # fallback if MagicDNS is slow
$TS_EXE      = "C:\Program Files\Tailscale\tailscale.exe"
$TS_MSI      = "$env:TEMP\tailscale-setup.msi"
$TS_MSI_URL  = "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi"

# Did THIS script install Tailscale? Decides whether we uninstall it at exit.
$script:WeInstalledIt = $false

# TLS 1.2+ on PowerShell 5.1, which still defaults to TLS 1.0.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Hides the Invoke-WebRequest progress bar: cleaner console, much faster download.
$ProgressPreference = 'SilentlyContinue'

# --- Elevate to admin if not already --------------------------------------
$curId = [Security.Principal.WindowsIdentity]::GetCurrent()
$curPrincipal = New-Object Security.Principal.WindowsPrincipal($curId)
$isAdmin = $curPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $cmd = "irm $BACKEND_URL | iex"
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -Command `"$cmd`""
    exit
}

Clear-Host
Write-Host ""
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host "      Secure Remote Access Launcher    " -ForegroundColor Cyan
Write-Host "  ======================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Host "  [!] No ssh.exe found. Install the OpenSSH Client:" -ForegroundColor Red
    Write-Host "      Settings > Apps > Optional Features > OpenSSH Client" -ForegroundColor Gray
    Read-Host "  Press Enter to close"
    exit 1
}

# --- Step 1: Tailscale ----------------------------------------------------
function Ensure-Tailscale {
    if (Test-Path $TS_EXE) {
        Write-Host "  [1/4] Tailscale already installed - will leave it in place" -ForegroundColor DarkGray

        # We are about to run `tailscale up --reset`, which replaces whatever
        # account is signed in. There is no way to put it back, so this is the
        # one place the script stops and asks.
        $st = & $TS_EXE status --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($st -and $st.BackendState -eq "Running") {
            Write-Host ""
            Write-Host "        [!] Tailscale is currently signed in on this machine." -ForegroundColor Yellow
            Write-Host "            Continuing signs it OUT and will not sign it back in." -ForegroundColor Yellow
            $go = Read-Host "            Continue? (y/N)"
            if ($go -notmatch '^[Yy]') { throw "Cancelled by user." }
        }
        return
    }

    Write-Host "  [1/4] Installing Tailscale (silent, no dialogs)..." -ForegroundColor Gray
    Invoke-WebRequest $TS_MSI_URL -OutFile $TS_MSI -UseBasicParsing -ErrorAction Stop

    # /qn = no UI at all. The MSI is kept on disk because the same file is what
    # msiexec /x needs later to uninstall cleanly.
    $msiArgs = "/i `"$TS_MSI`" /qn /norestart"
    $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw "Tailscale install failed (msiexec exit $($p.ExitCode))"
    }

    $script:WeInstalledIt = $true
    Write-Host "  [1/4] Tailscale installed [OK]" -ForegroundColor Green
}

# --- Step 2: TOTP -> ephemeral key ----------------------------------------
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
            $body = @{ otp = $otp } | ConvertTo-Json
            $response = Invoke-RestMethod -Uri $BACKEND_URL -Method POST -Body $body -ContentType "application/json" -TimeoutSec 20
            Write-Host ""
            Write-Host "  [2/4] Verified [OK]" -ForegroundColor Green
            return $response.key
        } catch {
            $msg = "Could not reach server"
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($err -and $err.error) { $msg = $err.error }
            }
            Write-Host "        [!] $msg" -ForegroundColor Red
            $attempts++
        }
    }
    Write-Host "  [!] Too many failed attempts." -ForegroundColor Red
    return $null
}

# --- Step 3: Connect ------------------------------------------------------
function Connect-VPN ($key) {
    Write-Host "  [3/4] Connecting to VPN..." -ForegroundColor Gray
    Start-Service -Name "Tailscale" -ErrorAction SilentlyContinue
    & $TS_EXE up --authkey=$key --reset --accept-routes 2>&1 | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep 1
        $s = & $TS_EXE status --json 2>$null | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($s.BackendState -eq "Running") {
            Write-Host "  [3/4] VPN connected [OK]" -ForegroundColor Green
            return $true
        }
    }
    Write-Host "  [!] VPN failed to connect." -ForegroundColor Red
    return $false
}

# --- Step 4: SSH over Tailscale SSH ---------------------------------------
# No password and no private key ever touches this machine. archie runs
# Tailscale SSH, and the tailnet ACL grants tag:guest -> tag:remote-server as
# user pxanda. The WireGuard tunnel identity IS the authentication.
function Start-SSHSession {
    Write-Host ""
    Write-Host "  [4/4] Opening SSH session..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  +-----------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Type  exit  to close and disconnect    |" -ForegroundColor DarkGray
    Write-Host "  +-----------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    $target = $SSH_HOST
    if (-not (Resolve-DnsName $SSH_HOST -ErrorAction SilentlyContinue)) {
        $target = $SSH_HOST_IP
    }
    ssh -o StrictHostKeyChecking=accept-new "$SSH_USER@$target"
}

# --- Cleanup: always runs, even on Ctrl+C ---------------------------------
function Cleanup {
    Write-Host ""
    Write-Host "  [*] Disconnecting..." -ForegroundColor Yellow

    if (Test-Path $TS_EXE) {
        & $TS_EXE down   2>&1 | Out-Null
        & $TS_EXE logout 2>&1 | Out-Null   # ephemeral device deletes itself here
    }
    Write-Host "  [OK] VPN disconnected - device removed from the tailnet" -ForegroundColor Green

    if ($script:WeInstalledIt) {
        Write-Host "  [*] Uninstalling Tailscale..." -ForegroundColor Yellow
        Stop-Service -Name "Tailscale" -Force -ErrorAction SilentlyContinue
        $msiArgs = "/x `"$TS_MSI`" /qn /norestart"
        Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow -ErrorAction SilentlyContinue
        Remove-Item $TS_MSI -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Tailscale uninstalled - nothing left behind" -ForegroundColor Green
    } else {
        Write-Host "  [OK] Tailscale left installed (it was already here)" -ForegroundColor Green
    }

    Write-Host ""
    Read-Host "  Press Enter to close"
}

# --- Main -----------------------------------------------------------------
try {
    Ensure-Tailscale
    $key = Get-EphemeralKey
    if (-not $key) { exit 1 }
    if (-not (Connect-VPN $key)) { exit 1 }
    Start-SSHSession
} catch {
    Write-Host ""
    Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Cleanup
}
