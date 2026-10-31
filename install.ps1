# ──────────────────────────────────────────────────────────────
#  Nexus Toolkit v4 — Windows installer (PowerShell)
#  Usage:
#    powershell -ExecutionPolicy Bypass -File .\install.ps1
#    powershell -ExecutionPolicy Bypass -File .\install.ps1 -WithTools
# ──────────────────────────────────────────────────────────────
param(
    [switch]$WithTools,       # also install the pip/git auto-installable external tools
    [string]$Python = ""      # override the Python executable (e.g. "py -3.12")
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "   NEXUS Toolkit v4" -ForegroundColor Magenta
Write-Host "   Windows installer" -ForegroundColor DarkGray
Write-Host ""

# ── Resolve Python into an executable + fixed prefix args ─────
$script:PyExe = $null
$script:PyPre = @()
if ($Python) {
    $parts = $Python.Split(" ") | Where-Object { $_ -ne "" }
    $script:PyExe = $parts[0]
    if ($parts.Count -gt 1) { $script:PyPre = $parts[1..($parts.Count - 1)] }
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $script:PyExe = "py"; $script:PyPre = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $script:PyExe = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $script:PyExe = "python3"
}

if (-not $script:PyExe) {
    Write-Host "  [X] Python not found. Install 3.10+ :  winget install Python.Python.3.12" -ForegroundColor Red
    exit 1
}

function Invoke-Py { & $script:PyExe @script:PyPre @args }

# ── 1. Version check ──────────────────────────────────────────
$ver = Invoke-Py -c "import sys; print('%d.%d' % sys.version_info[:2])"
Write-Host "  [1/3] Python $ver detected ($script:PyExe $($script:PyPre -join ' '))" -ForegroundColor Cyan
Invoke-Py -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [X] Python 3.10+ required (found $ver)" -ForegroundColor Red
    exit 1
}

# ── 2. Install the package + dependencies ─────────────────────
Write-Host "  [2/3] Installing Nexus + Python dependencies..." -ForegroundColor Cyan
Push-Location $root
try {
    Invoke-Py -m pip install --user --upgrade pip | Out-Null
    Invoke-Py -m pip install --user -e .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] 'pip install -e .' failed, falling back to requirements.txt" -ForegroundColor Yellow
        Invoke-Py -m pip install --user -r requirements.txt
    }
} finally {
    Pop-Location
}
Write-Host "  [OK] Core installed" -ForegroundColor Green

# ── 3. Optional external tools (pip/git auto-installable only) ─
if ($WithTools) {
    Write-Host "  [3/3] Installing auto-installable external tools..." -ForegroundColor Cyan
    Push-Location $root
    try { Invoke-Py -m osint_toolkit --install-tools all } finally { Pop-Location }
} else {
    Write-Host "  [3/3] Skipping external tools (re-run with -WithTools to include them)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Done. Launch with:  " -NoNewline
Write-Host "nexus" -ForegroundColor Magenta
Write-Host "  (if 'nexus' is not found, use:  $script:PyExe $($script:PyPre -join ' ') -m osint_toolkit )" -ForegroundColor DarkGray
Write-Host ""
