#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  OSINT Toolkit v4.0 — installer
# ──────────────────────────────────────────────────────────────
set -euo pipefail

PINK='\033[1;35m'
PURPLE='\033[1;95m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
DIM='\033[2m'
RESET='\033[0m'

cat <<EOF
${PINK}
   ███████╗ ███████╗ ██╗ ███╗   ██╗ ████████╗
   ██╔═══██╗██╔════╝ ██║ ████╗  ██║ ╚══██╔══╝
   ██║   ██║███████╗ ██║ ██╔██╗ ██║    ██║
   ██║   ██║╚════██║ ██║ ██║╚██╗██║    ██║
   ╚██████╔╝███████║ ██║ ██║ ╚████║    ██║
    ╚═════╝ ╚══════╝ ╚═╝ ╚═╝  ╚═══╝    ╚═╝${RESET}
            ${PURPLE}toolkit v4.0${RESET} ${DIM}· installer${RESET}

EOF

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

# ── Python check ──
echo -e "${CYAN}[1/4]${RESET} Checking Python..."
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo -e "  ${RED}✗ python3 not found${RESET}"
    exit 1
fi
PY_VER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if "$PYTHON" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"; then
    echo -e "  ${GREEN}✓${RESET} Python ${PY_VER} (≥ 3.10 required)"
else
    echo -e "  ${RED}✗ Python 3.10+ required, found ${PY_VER}${RESET}"
    exit 1
fi

# ── System deps ──
echo -e "${CYAN}[2/4]${RESET} Checking system tools..."
for cmd in dig whois; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${RESET} $cmd"
    else
        echo -e "  ${YELLOW}!${RESET} $cmd not found — DNS/WHOIS features will degrade gracefully"
                echo -e "    ${DIM}install with your package manager: dnsutils whois${RESET}"
    fi
done

# ── Python deps ──
echo -e "${CYAN}[3/4]${RESET} Installing Python dependencies..."
PIP_FLAGS=""
if "$PYTHON" -m pip install --help 2>&1 | grep -q "break-system-packages"; then
    PIP_FLAGS="--break-system-packages"
fi
"$PYTHON" -m pip install --quiet --upgrade $PIP_FLAGS -r "$DIR/requirements.txt" \
    || "$PYTHON" -m pip install --quiet --upgrade -r "$DIR/requirements.txt"
echo -e "  ${GREEN}✓${RESET} Dependencies installed"

# ── Optional: external OSINT tools ──
if [ "${1:-}" = "--with-tools" ]; then
    echo -e "${CYAN}[3.5/4]${RESET} Installing external OSINT tools..."
    TOOLS_DIR="$HOME/.osint-toolkit/tools"
    mkdir -p "$TOOLS_DIR"

    # Detect Python version for compatibility warnings
    PYVER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYMAJ=${PYVER%%.*}; PYMIN=${PYVER##*.}
    if [ "$PYMAJ" -ge 3 ] && [ "$PYMIN" -ge 13 ]; then
        echo -e "  ${YELLOW}⚠${RESET}  Python $PYVER detected. Legacy OSINT tools (toutatis, zehef,"
        echo -e "      Mr.Holmes) may not yet support 3.13+. If installs fail, install"
        echo -e "      python3.11 / python3.12 and re-run with: PYTHON=python3.11 ./install.sh --with-tools"
        echo
    fi

    # pip-installable tools — install one at a time, verify each
    for pkg in toutatis zehef; do
        if "$PYTHON" -c "import $pkg" 2>/dev/null; then
            echo -e "  ${DIM}·${RESET} $pkg already installed"
        else
            echo -e "  ${CYAN}·${RESET} Installing $pkg..."
            if "$PYTHON" -m pip install $PIP_FLAGS "$pkg" 2>&1 | tail -3; then
                if "$PYTHON" -c "import $pkg" 2>/dev/null \
                        || command -v "$pkg" >/dev/null 2>&1; then
                    echo -e "  ${GREEN}✓${RESET} $pkg installed and verified"
                else
                    echo -e "  ${YELLOW}!${RESET} $pkg pip succeeded but module not importable"
                    echo -e "    ${DIM}check: ${PYTHON} -c 'import $pkg' / command -v $pkg${RESET}"
                fi
            else
                echo -e "  ${YELLOW}!${RESET} $pkg install failed (see error above)"
            fi
        fi
    done

    # git-cloned (simple)
    for repo_pair in \
        "Mr.Holmes|https://github.com/Lucksi/Mr.Holmes.git|mrholmes"
    do
        IFS='|' read -r tool_name tool_url dirname <<< "$repo_pair"
        target="$TOOLS_DIR/$dirname"
        if [ -d "$target" ]; then
            echo -e "  ${DIM}·${RESET} $tool_name already cloned"
        else
            git clone --depth 1 "$tool_url" "$target" 2>/dev/null \
                && echo -e "  ${GREEN}✓${RESET} $tool_name cloned" \
                || echo -e "  ${YELLOW}!${RESET} $tool_name clone failed"
            if [ -f "$target/requirements.txt" ]; then
                "$PYTHON" -m pip install --quiet $PIP_FLAGS -r "$target/requirements.txt" 2>/dev/null
            fi
        fi
    done

    # DataProfiler — heavy deps, dedicated venv (capitalone/DataProfiler)
    DP_DIR="$TOOLS_DIR/dataprofiler"
    if [ -d "$DP_DIR/venv" ]; then
        echo -e "  ${DIM}·${RESET} DataProfiler already installed (venv present)"
    else
        echo -e "  ${CYAN}·${RESET} Installing DataProfiler (this may take a few minutes)..."
        if [ ! -d "$DP_DIR" ]; then
            git clone --depth 1 https://github.com/capitalone/DataProfiler.git "$DP_DIR" 2>/dev/null \
                && echo -e "  ${GREEN}✓${RESET} DataProfiler cloned" \
                || { echo -e "  ${YELLOW}!${RESET} DataProfiler clone failed"; DP_DIR=""; }
        fi
        if [ -n "$DP_DIR" ] && [ -d "$DP_DIR" ]; then
            "$PYTHON" -m venv "$DP_DIR/venv" 2>/dev/null && \
            "$DP_DIR/venv/bin/pip" install --quiet -U pip setuptools wheel 2>/dev/null && \
            "$DP_DIR/venv/bin/pip" install --quiet -r "$DP_DIR/requirements.txt" 2>/dev/null && \
                echo -e "  ${GREEN}✓${RESET} DataProfiler venv ready" \
                || echo -e "  ${YELLOW}!${RESET} DataProfiler venv install failed (try manually)"
        fi
    fi
    echo
fi

# ── Launcher script ──
echo -e "${CYAN}[4/4]${RESET} Installing launcher..."
LAUNCHER="/usr/local/bin/nexus"
LAUNCHER_CONTENT="#!/usr/bin/env bash
cd '$DIR' && exec '$PYTHON' -m osint_toolkit \"\$@\"
"
PRIV_CMD=""
for cmd in pkexec sudo doas; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PRIV_CMD="$cmd"
        break
    fi
done
if [ -n "$PRIV_CMD" ]; then
    echo "$LAUNCHER_CONTENT" | $PRIV_CMD tee "$LAUNCHER" >/dev/null 2>&1 && $PRIV_CMD chmod +x "$LAUNCHER" 2>/dev/null
fi
if [ -x "$LAUNCHER" ]; then
    echo -e "  ${GREEN}✓${RESET} Command ${PURPLE}osint${RESET} installed to ${LAUNCHER} (using $PRIV_CMD)"
    LAUNCH_HINT="nexus"
else
    echo -e "  ${YELLOW}!${RESET} Privileged command not available — use: ${PURPLE}python3 -m osint_toolkit${RESET}"
    LAUNCH_HINT="python3 -m osint_toolkit"
fi

# Also create osint alias for backward compatibility
if [ -x "$LAUNCHER" ] && [ ! -f "/usr/local/bin/osint" ]; then
    $PRIV_CMD ln -sf "$LAUNCHER" "/usr/local/bin/osint" 2>/dev/null
fi

mkdir -p "$HOME/.osint-toolkit/output"

cat <<EOF

${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}
   ${GREEN}✓ Installation complete${RESET}
${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}

   ${PURPLE}Usage:${RESET}
     ${CYAN}${LAUNCH_HINT}${RESET}                          ${DIM}# launch TUI${RESET}
     ${CYAN}${LAUNCH_HINT} test@example.com${RESET}         ${DIM}# auto OSINT${RESET}
     ${CYAN}${LAUNCH_HINT} -c recon -m ports example.com${RESET}
     ${CYAN}${LAUNCH_HINT} -c external -m nmap scanme.org${RESET}
     ${CYAN}${LAUNCH_HINT} --list-modules${RESET}            ${DIM}# show all modules + tool status${RESET}

   ${DIM}Reports saved to: ~/.osint-toolkit/output/${RESET}
   ${DIM}External tools installed to: ~/.osint-toolkit/tools/${RESET}

   ${YELLOW}To install external tools (Mr.Holmes, toutatis, DaProfiler, Zehef):${RESET}
     ${CYAN}./install.sh --with-tools${RESET}

EOF
