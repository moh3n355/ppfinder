#!/usr/bin/env bash
#
# ppfinder installer: checks/installs dependencies, verifies the Playwright
# browser binary, and puts a `ppfinder` command on PATH.
#
# Usage: ./install.sh
#
set -u  # treat unset vars as errors; NOT -e, because we want to handle
        # each failure ourselves with a clear message instead of dying
        # on the first one.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_BIN_DIR="/usr/local/bin"
EXIT_CODE=0

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
ok()   { printf '  [ok] %s\n' "$1"; }
err()  { printf '  [error] %s\n' "$1" >&2; EXIT_CODE=1; }
info() { printf '  [..] %s\n' "$1"; }

bold "ppfinder installer"
echo "project dir: $SCRIPT_DIR"
echo

# --- 1. Python version ------------------------------------------------------
info "checking Python 3..."
if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found on PATH."
    err "Fix: sudo apt update && sudo apt install python3 python3-pip -y   (Debian/Ubuntu)"
    err "     sudo dnf install python3 python3-pip -y                     (Fedora)"
    echo
    bold "Aborting: python3 is required before anything else can be installed."
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
PY_MAJOR=$(python3 -c 'import sys; print(sys.version_info[0])')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info[1])')
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    err "python3 found but version is $PY_VERSION; ppfinder needs 3.8+."
    echo
    bold "Aborting: upgrade Python and re-run."
    exit 1
fi
ok "python3 $PY_VERSION found"

# --- 2. pip ------------------------------------------------------------------
info "checking pip..."
if ! python3 -m pip --version >/dev/null 2>&1; then
    err "pip not available for python3."
    err "Fix: sudo apt install python3-pip -y   (Debian/Ubuntu)"
    err "     sudo dnf install python3-pip -y   (Fedora)"
    echo
    bold "Aborting: pip is required to install dependencies."
    exit 1
fi
ok "pip found"

# --- 3. Python dependencies (requests, playwright) ---------------------------
info "installing Python dependencies from requirements.txt..."
PIP_LOG=$(mktemp)
if python3 -m pip install --break-system-packages -r "$SCRIPT_DIR/requirements.txt" > "$PIP_LOG" 2>&1; then
    ok "requests + playwright installed"
else
    # --break-system-packages is unsupported on older pip (<23.0.1); retry without it
    if grep -qi "no such option" "$PIP_LOG"; then
        info "retrying without --break-system-packages (older pip detected)..."
        if python3 -m pip install -r "$SCRIPT_DIR/requirements.txt" > "$PIP_LOG" 2>&1; then
            ok "requests + playwright installed"
        else
            err "pip install failed. Last 15 lines of output:"
            tail -15 "$PIP_LOG" | sed 's/^/    /' >&2
            err "If this is an 'externally managed environment' error, create a venv first:"
            err "  python3 -m venv .venv && source .venv/bin/activate && ./install.sh"
        fi
    else
        err "pip install failed. Last 15 lines of output:"
        tail -15 "$PIP_LOG" | sed 's/^/    /' >&2
        err "If this is an 'externally managed environment' error, create a venv first:"
        err "  python3 -m venv .venv && source .venv/bin/activate && ./install.sh"
    fi
fi
rm -f "$PIP_LOG"

# --- 4. Playwright browser binary --------------------------------------------
info "installing Playwright's Chromium binary (this can take a minute)..."
PW_LOG=$(mktemp)
if python3 -m playwright install chromium --with-deps > "$PW_LOG" 2>&1; then
    ok "Chromium (with OS dependencies) installed"
elif python3 -m playwright install chromium > "$PW_LOG" 2>&1; then
    ok "Chromium installed (without --with-deps, since that needs root/sudo)"
    info "if client-side scans later fail to launch the browser, run as root/sudo:"
    info "  sudo python3 -m playwright install-deps chromium"
else
    err "playwright install chromium failed. Last 15 lines of output:"
    tail -15 "$PW_LOG" | sed 's/^/    /' >&2
    err "Client-side scanning will not work until this succeeds."
    err "Retry manually with: python3 -m playwright install chromium --with-deps"
fi
rm -f "$PW_LOG"

# --- 5. Make cli.py executable + put `ppfinder` on PATH ----------------------
info "setting up the 'ppfinder' command..."
chmod +x "$SCRIPT_DIR/cli.py" 2>/dev/null

LINK_PATH="$INSTALL_BIN_DIR/ppfinder"
LINKED=0
if [ -w "$INSTALL_BIN_DIR" ] || sudo -n true 2>/dev/null; then
    if sudo ln -sf "$SCRIPT_DIR/cli.py" "$LINK_PATH" 2>/dev/null; then
        ok "linked $LINK_PATH -> $SCRIPT_DIR/cli.py"
        LINKED=1
    fi
fi

if [ "$LINKED" -eq 0 ]; then
    # Fall back to a per-user location that's commonly already on PATH
    USER_BIN="$HOME/.local/bin"
    mkdir -p "$USER_BIN"
    if ln -sf "$SCRIPT_DIR/cli.py" "$USER_BIN/ppfinder" 2>/dev/null; then
        ok "linked $USER_BIN/ppfinder -> $SCRIPT_DIR/cli.py"
        case ":$PATH:" in
            *":$USER_BIN:"*)
                ;;
            *)
                err "$USER_BIN is not on your PATH yet. Add this to ~/.bashrc or ~/.zshrc:"
                err "  export PATH=\"\$HOME/.local/bin:\$PATH\""
                ;;
        esac
    else
        err "could not create a symlink in $INSTALL_BIN_DIR or $USER_BIN."
        err "Run this manually once you have a writable bin dir on PATH:"
        err "  ln -sf $SCRIPT_DIR/cli.py /path/on/your/PATH/ppfinder"
    fi
fi

# --- 6. Self-test --------------------------------------------------------------
echo
info "running a self-test (python3 cli.py --help)..."
if python3 "$SCRIPT_DIR/cli.py" --help >/dev/null 2>&1; then
    ok "cli.py runs correctly"
else
    err "cli.py failed to run --help. Something above didn't actually succeed."
fi

echo
if [ "$EXIT_CODE" -eq 0 ]; then
    bold "Install complete."
    echo "Try:  ppfinder client -u https://test.com --inject-points query,hash -v"
else
    bold "Install finished with errors (see [error] lines above)."
    echo "Fix those, then re-run ./install.sh - it's safe to run multiple times."
fi

exit $EXIT_CODE
