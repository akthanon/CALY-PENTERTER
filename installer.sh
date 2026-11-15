#!/usr/bin/env bash
# installer.sh — HIVEPLUS bootstrap & maintenance
#
# Modes:
#   ./installer.sh            full install / update
#   ./installer.sh --verify   checks only (no changes)
#   ./installer.sh --repair   re-pull model + re-sync analyzer, then verify
#
# Passwords:
#   - Read from config.yaml if present there.
#   - Otherwise prompted ONCE on stdin (hidden input) per host.
#   - After key-based auth works, config passwords are removed (null).
#
# All operations are idempotent: safe to re-run anytime.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${CONFIG:-$SCRIPT_DIR/config.yaml}"
ANALYZER_SRC="$SCRIPT_DIR/analyzer.py"
SSH_KEY_FILE="${SSH_KEY_FILE:-$HOME/.ssh/id_ed25519}"
REMOTE_ANALYZER="/usr/local/bin/analyzer.py"

MODE="full"
for arg in "$@"; do
  case "$arg" in
    --verify) MODE="verify" ;;
    --repair) MODE="repair" ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[1;33m'
  B=$'\033[0;34m'; N=$'\033[0m'
else R=""; G=""; Y=""; B=""; N=""; fi
log()  { echo -e "${G}[+]${N} $*"; }
info() { echo -e "${B}[i]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
err()  { echo -e "${R}[x]${N} $*"; }
step() { echo -e "\n${Y}==>${N} ${B}$*${N}"; }
die()  { err "$@"; exit 1; }

# ---------- preflight ----------
install_sshpass_if_possible() {
  command -v sshpass >/dev/null && return 0
  warn "sshpass not installed — will try to install it locally"
  if command -v apt-get >/dev/null; then
    info "trying: sudo apt-get install -y sshpass"
    sudo apt-get update -qq && sudo apt-get install -y -qq sshpass && return 0
  elif command -v dnf >/dev/null; then
    sudo dnf install -y sshpass && return 0
  elif command -v pacman >/dev/null; then
    sudo pacman -S --noconfirm sshpass && return 0
  elif command -v zypper >/dev/null; then
    sudo zypper install -y sshpass && return 0
  fi
  return 1
}

preflight() {
  step "Preflight"
  for c in ssh scp python3 curl; do
    command -v "$c" >/dev/null || die "missing local dep: $c"
  done
  [ -f "$CONFIG" ] || die "config not found: $CONFIG"
  python3 -c "import yaml"   2>/dev/null || die "missing python yaml: pip install pyyaml"
  python3 -c "import requests" 2>/dev/null || die "missing python requests: pip install requests"
  log "local deps OK (ssh, scp, python3, curl, yaml, requests)"

  if ! command -v sshpass >/dev/null; then
    if install_sshpass_if_possible; then
      log "sshpass installed"
    else
      warn "sshpass not available — first-time key bootstrap will need manual input"
    fi
  else
    log "sshpass present"
  fi

  if [ -f "$ANALYZER_SRC" ]; then
    log "analyzer.py found ($(stat -c%s "$ANALYZER_SRC") bytes)"
  else
    warn "analyzer.py missing ($ANALYZER_SRC) — sync will be skipped"
  fi
}

# ---------- load config ----------
load_config() {
  step "Loading config"
  eval "$(python3 - "$CONFIG" <<'PY'
import sys, yaml, shlex
cfg = yaml.safe_load(open(sys.argv[1])) or {}
def q(x): return shlex.quote("" if x is None else str(x))
for h in ("brain","control"):
    d = cfg.get(h) or {}
    print(f"{h.upper()}_HOST={q(d.get('host'))}")
    print(f"{h.upper()}_USER={q(d.get('user'))}")
    print(f"{h.upper()}_PASSWORD={q(d.get('password'))}")
print(f"MODEL_NAME={q((cfg.get('model') or {}).get('name',''))}")
PY
)"
  [ -n "${BRAIN_HOST:-}" ]   || die "config: brain.host missing"
  [ -n "${CONTROL_HOST:-}" ] || die "config: control.host missing"
  log "brain=$BRAIN_HOST ($BRAIN_USER)   control=$CONTROL_HOST ($CONTROL_USER)   model=$MODEL_NAME"

  # track whether passwords came from config
  if [ -n "${BRAIN_PASSWORD:-}" ];   then BRAIN_PASS_FROM_CONFIG=1;   else BRAIN_PASS_FROM_CONFIG=0;   fi
  if [ -n "${CONTROL_PASSWORD:-}" ]; then CONTROL_PASS_FROM_CONFIG=1; else CONTROL_PASS_FROM_CONFIG=0; fi
}

# ---------- SSH key ----------
ensure_ssh_key() {
  step "SSH key"
  if [ ! -f "$SSH_KEY_FILE" ]; then
    mkdir -p "$(dirname "$SSH_KEY_FILE")"
    chmod 700 "$(dirname "$SSH_KEY_FILE")"
    info "generating $SSH_KEY_FILE"
    ssh-keygen -t ed25519 -N "" -f "$SSH_KEY_FILE" -C "hiveplus@$(hostname)" >/dev/null
    log "new key generated"
  else
    log "key present: $SSH_KEY_FILE"
  fi
}

test_key() {
  local user=$1 host=$2
  ssh -o BatchMode=yes -o ConnectTimeout=5 \
      -o StrictHostKeyChecking=accept-new \
      -i "$SSH_KEY_FILE" \
      "$user@$host" "echo ok" >/dev/null 2>&1
}

# Copy pubkey in a single SSH session. Robust against sshpass's lack of
# multi-connection password forwarding.
copy_key_with_password() {
  local user=$1 host=$2 pass=$3
  [ -n "$pass" ] || return 1
  [ -f "$SSH_KEY_FILE.pub" ] || { err "public key missing: $SSH_KEY_FILE.pub"; return 1; }
  command -v sshpass >/dev/null || return 1

  local pub
  pub=$(cat "$SSH_KEY_FILE.pub")

  info "installing public key on $user@$host"
  cat "$SSH_KEY_FILE.pub" | sshpass -p "$pass" \
    ssh -o StrictHostKeyChecking=accept-new \
        -o PubkeyAuthentication=no \
        -o PreferredAuthentications=password \
        -o NumberOfPasswordPrompts=1 \
        -o ConnectTimeout=10 \
        "$user@$host" \
        'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
         cat >> ~/.ssh/authorized_keys && \
         chmod 600 ~/.ssh/authorized_keys && \
         sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys' 2>/dev/null \
  || return 1
  return 0
}

prompt_password() {
  local label=$1 host=$2 user=$3
  local p1 p2
  while true; do
    printf "  Enter password for %s (%s@%s): " "$label" "$user" "$host" >&2
    read -rs p1; echo >&2
    printf "  Confirm: " >&2
    read -rs p2; echo >&2
    if [ "$p1" = "$p2" ] && [ -n "$p1" ]; then
      printf '%s' "$p1"
      return 0
    fi
    warn "passwords empty or do not match; retry"
  done
}

# Resolve the password for a host: prefer config, else prompt once.
ensure_passwords_available() {
  step "Credentials"
  [ "$MODE" = "verify" ] && return 0

  if ! test_key "$BRAIN_USER" "$BRAIN_HOST"; then
    if [ -z "${BRAIN_PASSWORD:-}" ]; then
      info "brain key auth not yet working; prompting for brain password (once)"
      BRAIN_PASSWORD=$(prompt_password "brain" "$BRAIN_HOST" "$BRAIN_USER")
      BRAIN_PASS_FROM_CONFIG=0
    fi
  fi

  if ! test_key "$CONTROL_USER" "$CONTROL_HOST"; then
    if [ -z "${CONTROL_PASSWORD:-}" ]; then
      info "control key auth not yet working; prompting for control password (once)"
      CONTROL_PASSWORD=$(prompt_password "control" "$CONTROL_HOST" "$CONTROL_USER")
      CONTROL_PASS_FROM_CONFIG=0
    fi
  fi
}

ensure_key_access() {
  step "SSH key access"
  for triple in "brain|$BRAIN_USER|$BRAIN_HOST|${BRAIN_PASSWORD:-}" \
                "control|$CONTROL_USER|$CONTROL_HOST|${CONTROL_PASSWORD:-}"; do
    IFS='|' read -r label user host pass <<<"$triple"
    if test_key "$user" "$host"; then
      log "$label: key auth OK"
      continue
    fi
    if [ "$MODE" = "verify" ]; then
      warn "$label: key auth FAILING"
      continue
    fi
    if [ -z "$pass" ]; then
      err "$label: no password available to bootstrap key"
      continue
    fi
    if copy_key_with_password "$user" "$host" "$pass" && test_key "$user" "$host"; then
      log "$label: key installed, auth OK"
    else
      err "$label: bootstrap failed (wrong password? sshpass missing?)"
      echo "  Manual fallback:"
      echo "    cat $SSH_KEY_FILE.pub | ssh $user@$host 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'"
      die "cannot continue without key auth to $label"
    fi
  done
}

# ---------- brain ----------
ensure_ollama_brain() {
  step "Brain: Ollama"
  if ssh -i "$SSH_KEY_FILE" "$BRAIN_USER@$BRAIN_HOST" \
        "command -v ollama >/dev/null 2>&1"; then
    log "brain: ollama present"
    return 0
  fi
  info "brain: installing ollama (sudo may be prompted remotely)"
  ssh -t -i "$SSH_KEY_FILE" "$BRAIN_USER@$BRAIN_HOST" \
      "curl -fsSL https://ollama.com/install.sh | sh" \
    || die "brain: ollama install failed"
  ssh -i "$SSH_KEY_FILE" "$BRAIN_USER@$BRAIN_HOST" \
      "command -v ollama >/dev/null" \
    || die "brain: ollama not on PATH after install"
  log "brain: ollama installed"
}

ensure_model_brain() {
  step "Brain: model"
  [ -n "$MODEL_NAME" ] || { warn "no model.name in config"; return 0; }
  local has
  has=$(ssh -i "$SSH_KEY_FILE" "$BRAIN_USER@$BRAIN_HOST" \
        "ollama list 2>/dev/null | awk 'NR>1 {print \$1}' | grep -Fx '$MODEL_NAME' || true")
  if [ -n "$has" ]; then
    log "brain: $MODEL_NAME present"
    return 0
  fi
  info "brain: pulling $MODEL_NAME (may take many minutes)"
  ssh -i "$SSH_KEY_FILE" "$BRAIN_USER@$BRAIN_HOST" "ollama pull '$MODEL_NAME'" \
    || die "brain: model pull failed"
  log "brain: $MODEL_NAME pulled"
}

# ---------- control ----------
ensure_control_deps() {
  step "Control: deps"

  # 1. Qué falta
  local missing
  missing=$(ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" '
    M=""
    python3 -c "import requests" 2>/dev/null || M="$M python3-requests"
    command -v pdftotext >/dev/null 2>&1 || M="$M poppler-utils"
    echo "$M"
  ' 2>/dev/null || true)

  if [ -z "$missing" ]; then
    log "control: python3-requests + poppler-utils present"
    return 0
  fi
  info "control: missing packages:$missing"

  # 2. Lock de dpkg
  if ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
       "sudo -n fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1"; then
    err "control: dpkg is locked by another process"
    info "  Wait or: ssh $CONTROL_USER@$CONTROL_HOST 'sudo pkill apt-get'"
    return 1
  fi

  # 3. Detectar si sudo necesita password
  local sudo_mode
  sudo_mode=$(ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
    "sudo -n true 2>/dev/null && echo PASSWORDLESS || echo NEEDS_PW")

  # 4. Resolver la password de sudo (solo para esta sesión del installer)
  local sudo_pw=""
  if [ "$sudo_mode" = "PASSWORDLESS" ]; then
    info "control: sudo is passwordless"
  else
    # Preferir la del config si existe, si no, prompt
    if [ -n "${CONTROL_PASSWORD:-}" ]; then
      sudo_pw="$CONTROL_PASSWORD"
      info "control: sudo password provided via config"
    else
      info "control: sudo requires a password (will not be stored anywhere)"
      printf "  Enter sudo password for %s@%s: " "$CONTROL_USER" "$CONTROL_HOST" >&2
      read -rs sudo_pw; echo >&2
      [ -n "$sudo_pw" ] || { err "empty sudo password"; return 1; }
    fi
    # Validar que funciona antes de hacer nada más
    if ! ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
           "echo '$sudo_pw' | sudo -S -v 2>/dev/null"; then
      err "control: sudo password rejected"
      return 1
    fi
    info "control: sudo password accepted (sudo valid for this session)"
  fi

  # 5. apt update
  info "control: apt-get update (max 120s)"
  local rc=0
  if [ "$sudo_mode" = "PASSWORDLESS" ]; then
    ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
      "timeout 120 sudo -n apt-get update 2>&1 | tail -5" || rc=$?
  else
    ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
      "echo '$sudo_pw' | timeout 120 sudo -S apt-get update 2>&1 | tail -5" || rc=$?
  fi
  [ "$rc" -ne 0 ] && warn "apt-get update warnings (continuing)"

  # 6. apt install
  info "control: apt-get install$missing (max 300s)"
  rc=0
  if [ "$sudo_mode" = "PASSWORDLESS" ]; then
    ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
      "timeout 300 sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y $missing 2>&1 | tail -20" || rc=$?
  else
    ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
      "echo '$sudo_pw' | timeout 300 sudo -S DEBIAN_FRONTEND=noninteractive apt-get install -y $missing 2>&1 | tail -20" || rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    err "control: install failed (rc=$rc)"
    return 1
  fi

  # 7. Verificar
  local still
  still=$(ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" '
    M=""
    python3 -c "import requests" 2>/dev/null || M="$M requests"
    command -v pdftotext >/dev/null 2>&1 || M="$M pdftotext"
    echo "$M"
  ' 2>/dev/null || true)
  if [ -n "$still" ]; then
    err "control: still missing after install:$still"
    return 1
  fi

  log "control: deps installed"
}

sync_analyzer() {
  # [disabled in v4: analyzer lives on MAIN]
  step "Control: analyzer (skipped — lives on MAIN)"
  return 0
  # ---- original code below, kept for reference ----
  step "Control: analyzer"
  [ -f "$ANALYZER_SRC" ] || { warn "analyzer.py missing locally — skipped"; return 0; }

  local local_sha remote_sha
  local_sha=$(sha256sum "$ANALYZER_SRC" | awk '{print $1}')
  remote_sha=$(ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
    "sha256sum $REMOTE_ANALYZER 2>/dev/null | awk '{print \$1}'" 2>/dev/null || echo "")

  if [ "$local_sha" = "$remote_sha" ]; then
    log "control: analyzer up to date (${local_sha:0:12})"
    return 0
  fi

  info "control: copying analyzer (${local_sha:0:12})"

  # 1. scp a /tmp (no requiere permisos elevados)
  local tmp="/tmp/analyzer.py.new.$$"
  if ! scp -q -i "$SSH_KEY_FILE" "$ANALYZER_SRC" \
       "$CONTROL_USER@$CONTROL_HOST:$tmp"; then
    err "control: scp to $tmp failed"
    return 1
  fi
  log "control: uploaded to $tmp"

  # 2. Resolver el sudo password (misma lógica que ensure_control_deps)
  local sudo_pw=""
  local sudo_mode
  sudo_mode=$(ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
    "sudo -n true 2>/dev/null && echo PASSWORDLESS || echo NEEDS_PW")

  if [ "$sudo_mode" = "NEEDS_PW" ]; then
    if [ -n "${CONTROL_PASSWORD:-}" ]; then
      sudo_pw="$CONTROL_PASSWORD"
    else
      # Intentar sudo sin password primero (por si cache de ensure_control_deps)
      if ! ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" "sudo -n true 2>/dev/null"; then
        info "control: sudo password needed to install analyzer to $REMOTE_ANALYZER"
        printf "  Enter sudo password for %s@%s: " "$CONTROL_USER" "$CONTROL_HOST" >&2
        read -rs sudo_pw; echo >&2
        [ -n "$sudo_pw" ] || { err "empty sudo password"; return 1; }
      fi
    fi
  fi

  # 3. Mover con sudo (o instalar en ~/.local/bin si no hay sudo)
  local install_rc=0
  if [ "$sudo_mode" = "PASSWORDLESS" ] || [ -n "$sudo_pw" ]; then
    # Opción A: instalar en /usr/local/bin con sudo
    if [ -n "$sudo_pw" ]; then
      ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
        "echo '$sudo_pw' | sudo -S install -m 0755 '$tmp' '$REMOTE_ANALYZER' 2>&1" \
        || install_rc=$?
    else
      ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
        "sudo -n install -m 0755 '$tmp' '$REMOTE_ANALYZER' 2>&1" \
        || install_rc=$?
    fi
    if [ "$install_rc" -ne 0 ]; then
      err "control: sudo install failed (rc=$install_rc); falling back to ~/.local/bin"
      sudo_pw=""   # force fallback
    fi
  fi

  if [ "$install_rc" -ne 0 ] || { [ "$sudo_mode" = "NEEDS_PW" ] && [ -z "$sudo_pw" ]; }; then
    # Opción B: instalar en ~/.local/bin (no requiere sudo)
    local user_bin="$HOME/.local/bin"
    info "control: installing to \$HOME/.local/bin/analyzer.py (no sudo needed)"
    ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" "
      mkdir -p ~/.local/bin && \
      cp '$tmp' ~/.local/bin/analyzer.py && \
      chmod 0755 ~/.local/bin/analyzer.py && \
      rm -f '$tmp'
    " || { err "control: fallback install failed"; return 1; }

    # Verificar que ~/.local/bin está en PATH
    local in_path
    in_path=$(ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
      'case ":$PATH:" in *":$HOME/.local/bin:"*) echo yes;; *) echo no;; esac')
    if [ "$in_path" = "no" ]; then
      warn "control: ~/.local/bin is NOT in PATH"
      info "  Add to ~/.bashrc: export PATH=\"\$HOME/.local/bin:\$PATH\""
      ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
        'grep -q "HOME/.local/bin" ~/.bashrc || echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> ~/.bashrc'
      log "control: added ~/.local/bin to PATH in ~/.bashrc (new sessions only)"
    fi

    log "control: analyzer installed to ~/.local/bin/analyzer.py"
    return 0
  fi

  # 4. Verificar instalación en /usr/local/bin
  local remote_sha_new
  remote_sha_new=$(ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
    "sha256sum $REMOTE_ANALYZER 2>/dev/null | awk '{print \$1}'" 2>/dev/null || echo "")
  if [ "$remote_sha_new" != "$local_sha" ]; then
    err "control: post-install sha mismatch ($remote_sha_new vs $local_sha)"
    return 1
  fi

  # 5. Limpiar el archivo temporal
  ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" "rm -f '$tmp'"

  log "control: analyzer installed at $REMOTE_ANALYZER (${local_sha:0:12})"
}

# ---------- verify ----------
verify_all() {
  step "Verification"
  local failed=0

  if ssh -i "$SSH_KEY_FILE" "$BRAIN_USER@$BRAIN_HOST" \
        "curl -fsS --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null"; then
    log "brain: ollama API reachable"
  else err "brain: ollama API not reachable"; failed=$((failed+1)); fi

  if [ -n "$MODEL_NAME" ]; then
    if ssh -i "$SSH_KEY_FILE" "$BRAIN_USER@$BRAIN_HOST" \
          "ollama list 2>/dev/null | awk 'NR>1 {print \$1}' | grep -Fx '$MODEL_NAME' >/dev/null"; then
      log "brain: model '$MODEL_NAME' present"
    else err "brain: model '$MODEL_NAME' MISSING"; failed=$((failed+1)); fi
  fi

  if ssh -i "$SSH_KEY_FILE" "$CONTROL_USER@$CONTROL_HOST" \
        "test -x $REMOTE_ANALYZER"; then
    log "control: analyzer installed"
  else warn "control: analyzer not installed"; fi

  if [ "$failed" -eq 0 ]; then log "all critical checks passed"
  else err "$failed critical check(s) failed"; fi
  return $failed
}

# ---------- cleanup config ----------
cleanup_config_passwords() {
  [ "$MODE" = "full" ] || return 0
  if [ "${BRAIN_PASS_FROM_CONFIG:-0}" = "0" ] && \
     [ "${CONTROL_PASS_FROM_CONFIG:-0}" = "0" ]; then
    # Both passwords came from stdin; config was already null. Nothing to do.
    log "config: passwords already null, nothing to clean"
    return 0
  fi
  echo ""
  info "SSH key auth is working. You can now remove passwords from config.yaml."
  read -p "  Remove passwords from config.yaml? [Y/n] " ans
  case "${ans:-Y}" in
    y|Y|yes|YES|"")
      python3 - "$CONFIG" <<'PY'
import sys, yaml
p = sys.argv[1]
cfg = yaml.safe_load(open(p)) or {}
for h in ("brain", "control"):
    if h in cfg and cfg[h] is not None:
        cfg[h]["password"] = None
class D(yaml.SafeDumper): pass
def _str(d, x):
    if "\n" in x and len(x) > 40:
        return d.represent_scalar("tag:yaml.org,2002:str", x, style="|")
    return d.represent_scalar("tag:yaml.org,2002:str", x)
D.add_representer(str, _str)
yaml.dump(cfg, open(p, "w"), Dumper=D, sort_keys=False,
          allow_unicode=True, default_flow_style=False)
print("  [+] passwords removed from config.yaml")
PY
      ;;
    *) info "keeping passwords in config.yaml" ;;
  esac
}

# ---------- main ----------
main() {
  preflight
  load_config
  ensure_ssh_key

  if [ "$MODE" = "verify" ]; then
    verify_all
    exit $?
  fi

  ensure_passwords_available
  ensure_key_access

  if [ "$MODE" = "repair" ]; then
    ensure_model_brain
    sync_analyzer
    verify_all
    exit $?
  fi

  ensure_ollama_brain
  ensure_model_brain
  ensure_control_deps
  sync_analyzer
  verify_all
  cleanup_config_passwords

  echo ""
  log "Install/update complete."
  log "Next: python3 $SCRIPT_DIR/main_agent.py"
}

main "$@"
