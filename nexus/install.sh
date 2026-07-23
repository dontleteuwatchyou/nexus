#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${NEXUS_VENV:-$PROJECT_DIR/.venv}"
BIN_DIR="${NEXUS_BIN_DIR:-$HOME/.local/bin}"
SYSTEM_PYTHON="${PYTHON:-python3}"
WITH_TOOLS=false
WITH_DEV=false
INSTALL_SYSTEM=false

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_CYAN=$'\033[1;36m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
    C_RED=$'\033[1;31m'; C_PURPLE=$'\033[1;95m'; C_DIM=$'\033[2m'; C_RESET=$'\033[0m'
else
    C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_PURPLE=""; C_DIM=""; C_RESET=""
fi

usage() {
    cat <<'EOF'
Nexus Toolkit installer

Usage: ./install.sh [options]

Options:
  --with-tools       Install managed optional tools (toutatis, zehef, Mr.Holmes)
  --dev              Install development/test dependencies
  --install-system   Install missing dig/whois/git packages with the OS package manager
  -h, --help         Show this help

Environment:
  PYTHON             Python executable to use (default: python3)
  NEXUS_VENV         Virtual environment path (default: ./.venv)
  NEXUS_BIN_DIR      Launcher directory (default: ~/.local/bin)
  NO_COLOR=1         Disable terminal colours
EOF
}

while (($#)); do
    case "$1" in
        --with-tools) WITH_TOOLS=true ;;
        --dev) WITH_DEV=true ;;
        --install-system) INSTALL_SYSTEM=true ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%s\n' "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

info() { printf '%s→%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok() { printf '%s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die() { printf '%s✗%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

on_error() {
    local line=$1
    printf '%s✗%s Installation failed near line %s.\n' "$C_RED" "$C_RESET" "$line" >&2
    printf '  Re-run without --quiet details using: %s -m pip install -e %s\n' \
        "$VENV_DIR/bin/python" "$PROJECT_DIR" >&2
}
trap 'on_error "$LINENO"' ERR

printf '%s\n' "${C_PURPLE}╭──────────────────────────────────────────────╮${C_RESET}"
printf '%s\n' "${C_PURPLE}│  NEXUS TOOLKIT · isolated installer          │${C_RESET}"
printf '%s\n' "${C_PURPLE}╰──────────────────────────────────────────────╯${C_RESET}"

command -v "$SYSTEM_PYTHON" >/dev/null 2>&1 || die "$SYSTEM_PYTHON is not installed."
"$SYSTEM_PYTHON" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' \
    || die "Python 3.10 or newer is required."
PYTHON_VERSION=$("$SYSTEM_PYTHON" -c 'import platform; print(platform.python_version())')
ok "Python $PYTHON_VERSION"

missing_system=()
command -v dig >/dev/null 2>&1 || missing_system+=(dig)
command -v whois >/dev/null 2>&1 || missing_system+=(whois)
command -v git >/dev/null 2>&1 || missing_system+=(git)

if ((${#missing_system[@]})) && "$INSTALL_SYSTEM"; then
    info "Installing missing system commands: ${missing_system[*]}"
    if command -v pacman >/dev/null 2>&1; then
        packages=()
        [[ " ${missing_system[*]} " == *" dig "* ]] && packages+=(bind)
        [[ " ${missing_system[*]} " == *" whois "* ]] && packages+=(whois)
        [[ " ${missing_system[*]} " == *" git "* ]] && packages+=(git)
        sudo pacman -S --needed "${packages[@]}"
    elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y python3-venv dnsutils whois git
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3 whois bind-utils git
    else
        die "Unsupported package manager; install dig, whois and git manually."
    fi
elif ((${#missing_system[@]})); then
    warn "Optional system commands missing: ${missing_system[*]}"
    warn "Run ./install.sh --install-system to install them."
else
    ok "System helpers: dig, whois, git"
fi

info "Creating isolated environment at $VENV_DIR"
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
fi
VENV_PYTHON="$VENV_DIR/bin/python"
"$VENV_PYTHON" -m pip install --quiet --upgrade pip setuptools wheel

if "$WITH_DEV"; then
    info "Installing Nexus with development dependencies"
    "$VENV_PYTHON" -m pip install --quiet --editable "$PROJECT_DIR[dev]"
else
    info "Installing Nexus and all Python runtime dependencies"
    "$VENV_PYTHON" -m pip install --quiet --editable "$PROJECT_DIR"
fi

"$VENV_PYTHON" - <<'PY'
from importlib.util import find_spec

required = {
    "aiohttp", "bs4", "cryptography", "dns", "holehe", "httpx", "lxml",
    "phonenumbers", "rich", "textual", "tldextract", "whois",
}
missing = sorted(name for name in required if find_spec(name) is None)
if missing:
    raise SystemExit("Missing Python modules: " + ", ".join(missing))
PY
ok "Python runtime verified"

mkdir -p "$BIN_DIR" "$HOME/.osint-toolkit/output" "$HOME/.osint-toolkit/tools"
ln -sfn "$VENV_DIR/bin/nexus" "$BIN_DIR/nexus"
ln -sfn "$VENV_DIR/bin/osint" "$BIN_DIR/osint"
ln -sfn "$PROJECT_DIR/scripts/local_ai.sh" "$BIN_DIR/nexus-ai"
ok "Launchers installed: $BIN_DIR/nexus, $BIN_DIR/osint and $BIN_DIR/nexus-ai"

if "$WITH_TOOLS"; then
    info "Installing managed optional OSINT tools"
    for package in toutatis zehef; do
        if "$VENV_PYTHON" -m pip install --quiet "$package"; then
            ok "$package installed"
        else
            warn "$package could not be installed on Python $PYTHON_VERSION"
        fi
    done

    MRHOLMES_DIR="$HOME/.osint-toolkit/tools/mrholmes"
    if [[ -d "$MRHOLMES_DIR/.git" ]]; then
        info "Updating Mr.Holmes"
        git -C "$MRHOLMES_DIR" pull --ff-only || warn "Mr.Holmes update skipped"
    else
        git clone --depth 1 https://github.com/Lucksi/Mr.Holmes.git "$MRHOLMES_DIR" \
            && ok "Mr.Holmes installed" \
            || warn "Mr.Holmes clone failed"
    fi
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        warn "$BIN_DIR is not in the current PATH."
        printf '  Add this to your shell profile:\n  export PATH="$HOME/.local/bin:$PATH"\n'
        ;;
esac

printf '\n%sInstallation complete.%s\n' "$C_GREEN" "$C_RESET"
printf '  TUI:       %s\n' "$BIN_DIR/nexus"
printf '  Modules:   %s --list-modules\n' "$BIN_DIR/nexus"
printf '  Chat:      Nexus AI Core (local model optional)\n'
printf '  Local AI:  %s start\n' "$BIN_DIR/nexus-ai"
printf '  Monitor:   %s --ai-monitor\n' "$BIN_DIR/nexus"
printf '  Reports:   %s\n' "$HOME/.osint-toolkit/output"
printf '\n%sExternal tools are optional and are detected at runtime.%s\n' "$C_DIM" "$C_RESET"
