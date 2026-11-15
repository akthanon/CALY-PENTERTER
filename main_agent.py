#!/usr/bin/env python3
"""
HIVEPLUS agent — configuration-driven.

All tunables (IPs, credentials, model, prompts, patterns, escapes,
timeouts, setup, heuristics) live in config.yaml. Nothing target- or
host-specific is hardcoded here.

Run:    python main_agent.py [-c config.yaml]
"""
import paramiko, requests, socketserver, threading, select
import subprocess, shlex
import socket, sys, os, re, time, json, argparse
from collections import defaultdict
import yaml
try:
    from output_filter import OutputFilter
except ImportError:
    OutputFilter = None

# --- SIGINT: enter interactive mode instead of killing the process ---
import signal

_request_interactive = False
_in_interactive     = False

def _sigint_handler(signum, frame):
    global _request_interactive, _in_interactive
    if _in_interactive:
        # Ctrl+C during interactive input -> resume autonomous mode
        raise KeyboardInterrupt
    _request_interactive = True
    print("\n[!] Ctrl+C — interactive mode will start after the current step.")
    print("    Type a message, /continue, or /exit.\n")

signal.signal(signal.SIGINT, _sigint_handler)

# ---------------- Load config ----------------
ap = argparse.ArgumentParser()
ap.add_argument("-c", "--config",
                default=os.environ.get("AGENT_CONFIG", "config.yaml"))
args = ap.parse_args()
if not os.path.exists(args.config):
    print(f"[!] Config not found: {args.config}"); sys.exit(1)
with open(args.config, encoding="utf-8") as f:
    CFG = yaml.safe_load(f)
MEM = CFG.get("memory", {}) or {}
print(f"[+] Loaded config: {args.config}")

# ---------------- Extract ----------------
BRAIN    = CFG["brain"];    CONTROL = CFG["control"];  TARGET = CFG["target"]
MCFG     = CFG["model"];    MKR     = CFG["markers"];  FLT    = CFG["filters"]
TMO      = CFG["timeouts"]; HEU     = CFG["heuristic"]; SU     = CFG["setup"]
PR       = CFG["prompts"]

BRAIN_IP,   BRAIN_USER,   BRAIN_PASS   = BRAIN["host"],   BRAIN["user"],   BRAIN["password"]
CONTROL_IP, CONTROL_USER, CONTROL_PASS = CONTROL["host"], CONTROL["user"], CONTROL["password"]
TARGET_IP                              = TARGET["host"]

MODEL        = MCFG["name"]
STREAM       = bool(MCFG.get("stream", True))
MAX_ITERS    = int(MCFG["max_iterations"])
REQ_TIMEOUT  = int(MCFG.get("request_timeout", 900))

# Per-read timeout: if Ollama sends no bytes for this long, abort.
# Total request can still take REQ_TIMEOUT seconds, but a stalled stream
# will be interrupted so Ctrl+C can take effect.
READ_TIMEOUT = int(MCFG.get("read_timeout", 60))

# Inference parameters — filter out None values
MODEL_OPTS = {k: v for k, v in MCFG.get("params", {}).items() if v is not None}
if MODEL_OPTS:
    print(f"[+] Model params: {MODEL_OPTS}")

SSH_KEY_FILE = ((CFG.get("ssh") or {}).get("key_file")
                or os.environ.get("SSH_KEY_FILE"))
if SSH_KEY_FILE and not SSH_KEY_FILE.startswith("/"):
    SSH_KEY_FILE = os.path.expanduser(SSH_KEY_FILE)

PROMPT_MARK  = MKR["kali"]
REMOTE_MARK  = MKR["remote"]

DUPLICATE_THRESHOLD = int(FLT["duplicate_threshold"])
SLOW_TOOLS          = tuple(FLT["slow_tools"])
INTERACTIVE_TOOLS   = tuple(FLT["interactive_tools"])
EXIT_CMDS           = re.compile(FLT["exit_cmds_regex"], re.I)
SENTINEL_RE         = re.compile(FLT["sentinel_regex"])

LISTENER_PATTERNS = [re.compile(p) for p in FLT.get("listener_patterns", [])]

FORBIDDEN_CMD_PATTERNS = [re.compile(p, re.I)
                          for p in FLT.get("forbidden_cmd_patterns", [])]

def is_forbidden_cmd(cmd_line):
    """True if cmd_line matches a pattern we know produces hangs/waste."""
    return any(p.search(cmd_line) for p in FORBIDDEN_CMD_PATTERNS)


CHATTY_PATTERNS = [p.lower() for p in FLT.get("chatty_patterns", [])]

def is_chatty_response(content):
    """True if the model replied like a chatbot instead of acting."""
    if not content: return False
    # If it emitted a real action, it's fine
    if '<cmd>' in content or '<done>' in content:
        return False
    # Short outputs might be preamble; only flag if long or has chatty phrases
    lowered = content.lower()
    for p in CHATTY_PATTERNS:
        if p in lowered:
            return True
    # Very long prose with no tag is almost certainly a monologue
    if len(content) > 500 and '<' not in content:
        return True
    return False


def is_listener_cmd(cmd_line):
    return any(p.search(cmd_line) for p in LISTENER_PATTERNS)

# Commands that CONTAIN a listener-looking string but are NOT listeners
# (they control processes that own listeners, or inspect them).
_CONTROL_COMMANDS = ("pkill", "kill", "killall", "ps", "grep", "lsof",
                     "netstat", "ss", "fuser", "pgrep", "pstree", "top",
                     "htop", "bg", "fg", "jobs", "wait")

def is_foreground_listener(cmd_line):
    """A listener that will block the PTY if we let it run."""
    if not is_listener_cmd(cmd_line):
        return False
    s = cmd_line.strip()
    # control commands are never listeners — they just reference them
    first = s.split()[0].lower() if s.split() else ""
    if first in _CONTROL_COMMANDS:
        return False
    # already backgrounded
    if s.endswith('&') or '&' in s.split('#', 1)[0]:
        return False
    return True


# ---------------- Prompts ----------------
def _read_prompt(section):
    if isinstance(section, str):
        return section
    if isinstance(section, dict):
        if "file" in section:
            with open(section["file"], encoding="utf-8") as f:
                return f.read()
        if "inline" in section:
            return section["inline"]
    raise ValueError(f"Bad prompt config: {section!r}")

def _sub(text):
    return (text.replace("__CONTROL_IP__",  CONTROL_IP)
                .replace("__TARGET_IP__",   TARGET_IP)
                .replace("__PROMPT_MARK__", PROMPT_MARK)
                .replace("__REMOTE_MARK__", REMOTE_MARK))

USER_PROMPT   = _sub(_read_prompt(PR["user"]).strip())
SYSTEM_PROMPT = _sub(_read_prompt(PR["system"]))
print(f"[+] User prompt:   {len(USER_PROMPT)} chars")
print(f"[+] System prompt: {len(SYSTEM_PROMPT)} chars")

# ---------------- Compile patterns / escapes ----------------
PROMPT_PATTERNS = []
for p in CFG["prompt_patterns"]:
    flags = re.I if p.get("ignore_case") else 0
    PROMPT_PATTERNS.append((re.compile(p["regex"], flags), p["name"]))

ESCAPE_FOR = {k: (v.encode() if isinstance(v, str) else bytes(v))
              for k, v in CFG["escape_sequences"].items()}

SSH_FAIL_MARKERS = tuple(CFG["ssh_fail_markers"])

ANSI_RE          = re.compile(HEU["ansi_strip_regex"])
PROMPT_TERMINALS = re.compile(HEU["prompt_terminals_regex"])

if OutputFilter and CFG.get("output_filtering", {}).get("enabled", False):
    _OF_CFG = CFG["output_filtering"]
    filter_output = OutputFilter(_OF_CFG, ANSI_RE)
    print(f"[+] Output filter: enabled "
          f"(max {_OF_CFG.get('max_bytes',8000)}B / {_OF_CFG.get('max_lines',300)}L)")
else:
    filter_output = lambda x: x
    print("[+] Output filter: disabled")

def looks_like_pending_prompt(output):
    if not output: return False
    cleaned = ANSI_RE.sub('', output)
    if not cleaned or cleaned.endswith('\n'): return False
    last_line = cleaned.rstrip().split('\n')[-1].strip()
    if not last_line: return False
    if PROMPT_MARK in last_line or REMOTE_MARK in last_line: return False
    return bool(PROMPT_TERMINALS.search(last_line))

# ---------------- SSH chain ----------------
def _load_pkey():
    """Load the SSH private key (ed25519, RSA, or ECDSA)."""
    if not SSH_KEY_FILE:
        return None
    p = os.path.expanduser(SSH_KEY_FILE)
    if not os.path.exists(p):
        return None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key_file(p)
        except Exception:
            continue
    return None


def _auth(transport, user, password):
    """Try key first; fall back to password if configured."""
    key = _load_pkey()
    if key is not None:
        try:
            transport.auth_publickey(user, key)
            return
        except Exception as e:
            if password:
                print(f"  [ssh] key rejected for {user} ({e}); trying password")
            else:
                raise
    if password:
        transport.auth_password(user, password)
        return
    raise RuntimeError(
        f"no auth method for {user}: key="
        f"{'yes' if key else 'no'} password="
        f"{'yes' if password else 'no'}")


def _mk(h, u, p):
    t = paramiko.Transport((h, 22))
    t.start_client()
    _auth(t, u, p)
    return t


def _mk_via(j, h, u, p):
    ch = j.open_channel('direct-tcpip', (h, 22), ('127.0.0.1', 0))
    t = paramiko.Transport(ch)
    t.start_client()
    _auth(t, u, p)
    return t


print("[*] BRAIN...")
brain = _mk(BRAIN_IP, BRAIN_USER, BRAIN_PASS); print("[+] BRAIN OK")
print("[*] CONTROL...")
control = _mk_via(brain, CONTROL_IP, CONTROL_USER, CONTROL_PASS); print("[+] CONTROL OK")

# ---------------- Ollama tunnel ----------------
class _FH(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            ch = self.server.brain.open_channel(
                'direct-tcpip', ('127.0.0.1', 11434), self.request.getpeername())
        except Exception: return
        try:
            while True:
                r, _, _ = select.select([self.request, ch], [], [], 0.5)
                if self.request in r:
                    d = self.request.recv(4096)
                    if not d: break
                    ch.send(d)
                if ch in r:
                    d = ch.recv(4096)
                    if not d: break
                    self.request.send(d)
        except Exception: pass
        try: ch.close()
        except Exception: pass

class _FS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True
_FS.brain = brain
_proxy = _FS(('127.0.0.1', 0), _FH)
OLLAMA_PORT = _proxy.server_address[1]
threading.Thread(target=_proxy.serve_forever, daemon=True).start()
OLLAMA_URL = f"http://127.0.0.1:{OLLAMA_PORT}"
print(f"[+] Ollama tunnel: {OLLAMA_URL} -> BRAIN:11434")

# ---------------- Persistent PTY ----------------


print("[*] Opening persistent PTY shell on Control...")
shell = control.open_session()
shell.get_pty(term="xterm", width=220, height=50)
shell.invoke_shell()
time.sleep(0.8)
while shell.recv_ready(): shell.recv(65535)

setup_cmds = _sub(SU["kali_commands"]).replace("__SETUP_SENTINEL__", SU["sentinel"])
shell.send(setup_cmds)

_buf = b""; _t0 = time.time()
while time.time() - _t0 < TMO["setup_maxt"]:
    if shell.recv_ready():
        _buf += shell.recv(65535)
        if SU["sentinel"].encode() in _buf: break
    else: time.sleep(0.05)
time.sleep(TMO["setup_settle"])
while shell.recv_ready(): shell.recv(65535)
print("[+] Persistent shell ready")

# ---------------- State ----------------
current_state = None

# ---------------- Helpers ----------------
def is_interactive_cmd(cmd_line):
    first = re.split(r'[\s;|&]', cmd_line.strip(), 1)[0].lower()
    return first in INTERACTIVE_TOOLS

def is_slow(cmd_line):
    if is_interactive_cmd(cmd_line): return False
    s = cmd_line.strip().lower()
    # analyzer.py: always slow (30s-5min). Match anywhere in the command,
    # so "curl ... && analyzer.py ..." also gets the longer timeout.
    if re.search(r'\banalyzer(?:\.py)?\b', s):
        return True
    tokens = re.split(r'[\s;|&]+', s)
    return any(t in SLOW_TOOLS for t in tokens[:3])

def _safe_send(data, context=""):
    """Send to PTY, swallow errors if socket is dead."""
    try:
        shell.send(data)
        return True
    except Exception as e:
        print(f"[!] send failed ({context}): {e}")
        return False


def _read_until(idle=None, maxt=None, allow_idle_exit=True):
    idle = TMO["default_idle"] if idle is None else idle
    maxt = TMO["default_maxt"] if maxt is None else maxt
    out = b""
    last = time.time(); start = time.time()
    while True:
        if _request_interactive:
            try:
                shell.send(b"\x03")
            except Exception:
                pass
            out += b"\n[INTERRUPTED by user]\n"
            break
        if shell.recv_ready():
            out += shell.recv(65535); last = time.time()
        else:
            ei = time.time() - last
            et = time.time() - start
            if (PROMPT_MARK.encode() in out or REMOTE_MARK.encode() in out) \
                    and ei > TMO["read_quiet_window"]:
                break
            if allow_idle_exit and ei > idle: break
            if et > maxt: out += b"\n[TIMEOUT]\n"; break
            time.sleep(0.03)
    return out

def _is_clean_prompt_line(line):
    """True if the line is a clean Kali prompt with nothing meaningful after."""
    if PROMPT_MARK not in line:
        return False
    pm = line.rfind(PROMPT_MARK)
    after = line[pm + len(PROMPT_MARK):]
    # Strip null bytes, CR, ANSI leftovers, and other control chars
    after = ''.join(c for c in after if c.isprintable() or c == ' ')
    after = after.strip()
    if not after:
        return True
    # Allow [cwd] with any printable content
    return bool(re.fullmatch(r'\[[^\]]*\]', after))



def _strip_control_chars(text):
    """Remove non-printable control chars (but keep \n and \t)."""
    return ''.join(c for c in text if c.isprintable() or c in '\n\t')


def classify_output(output, prev_cmd):
    if not output: return False
    cleaned = ANSI_RE.sub('', output)
    cleaned = _strip_control_chars(cleaned)
    lines = [l.rstrip() for l in cleaned.split('\n') if l.strip()]
    if not lines: return False
    last = lines[-1].strip()

    if REMOTE_MARK in last: return 'remote'
    if _is_clean_prompt_line(last): return None

    for pattern, name in PROMPT_PATTERNS:
        if pattern.search(last):
            return name

    joined = '\n'.join(lines[-40:])

    # nc / ncat / socat: raw socket, BUT only if foreground.
    # `nc ... &` runs in background → still on Kali.
    if prev_cmd and re.match(r'^\s*(?:sudo\s+)?(nc|ncat|netcat|socat)\b',
                             prev_cmd, re.I):
        s = prev_cmd.strip()
        is_backgrounded = s.endswith('&') or '&' in s.split('#', 1)[0]
        if not is_backgrounded:
            return 'raw_socket'

    if prev_cmd and re.match(r'^\s*telnet\b', prev_cmd, re.I):
        if re.search(r'\blogin\s*:\s*$', last, re.I):
            return '__user__'
        return 'raw_socket'

    if prev_cmd and prev_cmd.lstrip().startswith('ssh'):
        if any(m in joined for m in SSH_FAIL_MARKERS):
            return None
        if re.search(r'[\$#>%]\s*$', last) and '~' in last:
            return 'remote'
        if re.search(r'^[\w.-]+@[\w.-]+[:~][^\n]*[\$#>]\s*$', last):
            return 'remote'

    # UNIVERSAL FALLBACK: any "user@host:" followed by a shell terminator
    # on the last line means we ARE inside a shell, regardless of how we
    # got there. This catches prompts like "root@Meow:~#", "www-data@box:/var$",
    # "admin@10.0.0.1:/#", etc.
    if re.search(r'[\w.-]+@[\w.-]+[:~][^\s]*[#\$>%]\s*$', last):
        return 'remote'

    # Kali prompt with cwd but no plain ###PROMPT### (e.g. after cd)
    if PROMPT_MARK in last and not looks_like_pending_prompt(output):
        return None

    if looks_like_pending_prompt(output):
        return '__input__'
    return False

def update_state(output, prev_cmd):
    global current_state
    ns = classify_output(output, prev_cmd)
    if ns is not False and ns != current_state:
        print(f"  [state] {current_state} -> {ns}")
        current_state = ns
    elif ns is not False:
        current_state = ns

def _normalize_bg_nc(cmd_line):
    """nc/ncat in background MUST redirect stdin to avoid SIGTTIN suspension."""
    s = cmd_line.strip()
    # Only applies to nc/ncat/netcat, backgrounded with &, no stdin redirect
    if not re.match(r'^\s*(nc|ncat|netcat)\b', s, re.I):
        return cmd_line
    if not s.endswith('&'):
        return cmd_line
    if any(r in s for r in ('<', '<<<', '<<')):
        return cmd_line   # already redirects stdin
    # Add </dev/null before the &
    return s[:-1].rstrip() + ' </dev/null &'


def _wait_quiescent(timeout=3.0, quiet=0.25):
    """Drain stale bytes (leftover prompts, late output from prev cmd)
    until PTY is quiet for `quiet` seconds. Prevents prompt-offset bug."""
    end = time.time() + timeout
    last = time.time()
    drained = 0
    while time.time() < end:
        if shell.recv_ready():
            try:
                n = len(shell.recv(65535))
                drained += n
                last = time.time()
            except Exception:
                return drained
        else:
            if time.time() - last > quiet:
                return drained
            time.sleep(0.03)
    return drained


def _intercept_tmux_capture(cmd_line, max_wait=25.0, poll=2.0):
    """If cmd is a bare 'tmux capture-pane ...', poll until non-empty
    or timeout. Keeps the model from spinning on empty panes."""
    if not re.match(r'^\s*tmux\s+capture-pane\b', cmd_line.strip()):
        return None
    # Extract the target from the command (work:rsh, work, etc.)
    m = re.search(r'\s-t\s+(\S+)', cmd_line)
    target = m.group(1) if m else ""
    if not target:
        return None
    start = time.time()
    last_out = ""
    while time.time() - start < max_wait:
        # Run capture-pane directly on the shell, discard stale first
        _wait_quiescent(timeout=0.5, quiet=0.1)
        payload = f"tmux capture-pane -pt {target} | tail -50"
        shell.send(payload.encode() + b"\n")
        out = b""
        wait_start = time.time()
        while time.time() - wait_start < 4.0:
            if shell.recv_ready():
                out += shell.recv(65535)
                if b"###PROMPT###" in out:
                    break
            else:
                time.sleep(0.05)
        text = out.decode(errors="replace")
        # Strip the echo of the command and the prompt
        text = re.sub(r'^[^\n]*\n', '', text, count=1)  # drop echo line
        text = text.split("###PROMPT###")[0]
        text = text.strip()
        if text:
            return text
        last_out = text
        time.sleep(poll)
    return last_out if last_out else "[no output after %.0fs — listener may be dead]" % max_wait


def type_line(line):
    line = _normalize_bg_nc(line)
    stripped = line.strip()
    if stripped == "^C":
        _wait_quiescent(timeout=1.5, quiet=0.2)
        if not _safe_send(b"\x03", "^C"):
            raise SystemExit(2)
        out = _read_until(idle=TMO["ctrl_idle"], maxt=TMO["ctrl_maxt"]).decode(errors='replace')
        update_state(out, '^C')

        # If still inside an auth prompt after ^C, retry with newline+^C
        if current_state in ('__password__', '__user__', '__yesno__', '__input__'):
            _safe_send(b'\n\x03', "^C-retry")
            out2 = _read_until(idle=TMO["ctrl_probe_idle"],
                               maxt=TMO["ctrl_probe_maxt"]).decode(errors='replace')
            update_state(out2, '^C2'); out += out2

        # If still not on Kali, send another newline + ^C
        if current_state is not None and PROMPT_MARK not in out:
            _safe_send(b'\n', "probe")
            out3 = _read_until(idle=TMO["ctrl_probe_idle"],
                               maxt=TMO["ctrl_probe_maxt"]).decode(errors='replace')
            update_state(out3, ''); out += out3
        return out
    if stripped == "^D":
        shell.send(b"\x04")
        out = _read_until(idle=TMO["ctrl_idle"], maxt=TMO["ctrl_maxt"]).decode(errors='replace')
        update_state(out, '^D'); return out

    if is_foreground_listener(stripped):
        # Run briefly, then kill it and teach the model to background it.
        print("  [listener] foreground listener detected; auto-killing")
        if not line.endswith('\n'): line += '\n'
        shell.send(line)
        out = _read_until(idle=2.0, maxt=5).decode(errors='replace')
        shell.send(b'\x03'); time.sleep(0.4)
        out += _read_until(idle=1.5, maxt=5).decode(errors='replace')
        update_state(out, stripped)
        hint = ("\n[SYSTEM NOTICE] Foreground listener was killed to avoid "
                "blocking the shell. Re-run it in the background:\n"
                "  COMMAND > /tmp/agent_<name>.log 2>&1 &\n"
                "Or use tmux:\n"
                "  tmux new-window -d -t work -n <name>\n"
                "  tmux send-keys -t work:<name> 'COMMAND' Enter")
        return out + hint

    if not line.endswith('\n'): line += '\n'
    # CRITICAL: drain stale buffer BEFORE sending. Without this, a slow
    # command (mysql, nmap short scans) leaves its output in the buffer
    # and the NEXT command's _read_until matches the previous prompt,
    # causing an offset where each iteration shows the PREVIOUS output.
    drained = _wait_quiescent(timeout=2.0, quiet=0.2)
    if drained > 5:
        print(f"  [drain] discarded {drained} stale bytes before send")
    if not _safe_send(line.encode() if isinstance(line, str) else line, "cmd"):
        raise SystemExit(2)

    if current_state in ('ftp','smbclient','mysql','msfconsole','python',
                         'irb','redis','r2','gdb','pager',
                         '__password__','__user__','__yesno__','__input__',
                         'remote'):
        out = _read_until(idle=TMO["interactive_idle"],
                          maxt=TMO["default_maxt"]).decode(errors='replace')
    elif is_slow(stripped):
        out = _read_until(idle=9999.0, maxt=TMO["slow_maxt"],
                          allow_idle_exit=False).decode(errors='replace')
    elif is_interactive_cmd(stripped):
        out = _read_until(idle=TMO["interactive_launch_idle"],
                          maxt=TMO["default_maxt"]).decode(errors='replace')
    else:
        out = _read_until(idle=TMO["default_idle"],
                          maxt=TMO["default_maxt"]).decode(errors='replace')

    update_state(out, stripped)
    return out

# ---------------- Auto-escape ----------------
def force_escape_to_kali(max_attempts=10):
    global current_state
    if current_state == '__input__':
        max_attempts = 3
    for attempt in range(max_attempts):
        if current_state is None: return True
        esc = ESCAPE_FOR.get(current_state, b'\x03\n')
        print(f"  [escape {attempt+1}] state={current_state} -> {esc!r}")
        if not _safe_send(esc, "escape"):
            print("  [!] Shell is dead — aborting escape, will exit agent.")
            raise SystemExit(2)
        time.sleep(0.6)
        out = _read_until(idle=TMO["ctrl_idle"],
                          maxt=TMO["setup_maxt"]).decode(errors='replace')
        # NEW: if the escape output contains a remote shell prompt,
        # recognize it and STOP trying to escape — we're already in a shell.
        if re.search(r'[\w.-]+@[\w.-]+[:~][^\s]*[#\$>%]\s*$', out):
            print("  [escape] detected remote shell prompt — aborting escape")
            current_state = 'remote'
            return True
        update_state(out, '')
        if current_state in ('__password__', '__user__', 'raw_socket') and attempt >= 2:
            if not _safe_send(b'\n\x03\x03', "escape-probe"):
                print("  [!] Shell is dead — aborting escape.")
                raise SystemExit(2)
            time.sleep(0.6)
            out = _read_until(idle=TMO["ctrl_idle"],
                              maxt=TMO["setup_maxt"]).decode(errors='replace')
            update_state(out, '')
    return current_state is None

_TOOL_HEADS = (
    "mysql", "mariadb", "psql", "sqlplus", "sqlite3",
    "ssh", "sshpass", "sftp", "scp",
    "telnet", "nc", "ncat", "netcat", "socat",
    "curl", "wget", "nmap", "nikto", "gobuster", "ffuf", "dirb",
    "hydra", "john", "hashcat", "searchsploit",
    "python", "python3", "perl", "ruby", "php",
    "msfconsole", "msf6", "smbclient", "rpcclient",
    "sudo", "su", "ftp",
)

def _looks_like_full_tool_cmd(cmd_line):
    """True if the command is a self-contained invocation of a tool,
    i.e., a complete command to be run on Kali, not a response to a prompt."""
    first = cmd_line.strip().split()[0].lower() if cmd_line.strip() else ""
    if first not in _TOOL_HEADS:
        return False
    # If it has any flag (-x, --xxx) or an explicit host (-h host or @host),
    # treat as a complete command.
    if re.search(r'\s(-|--)[a-zA-Z]', cmd_line):
        return True
    if re.search(r'@[\w.-]+', cmd_line):       # user@host
        return True
    if re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', cmd_line):  # IP
        return True
    if re.search(r'\s[\w.-]+\.[a-zA-Z]{2,}\b', cmd_line):   # hostname
        return True
    # Otherwise, it might be a short answer that just happens to start
    # with the tool name (unlikely). Treat as prompt response.
    return False


def escape_needed(cmd_line):
    if current_state is None: return False
    s = cmd_line.strip()
    if not s: return False
    if EXIT_CMDS.match(s): return False
    if s in ('^C', '^D'): return False

    # Complete tool commands are ALWAYS meant for Kali. If we are inside
    # an interactive state, escape first.
    if current_state in ('__password__', '__user__', '__yesno__', '__input__'):
        # Short single-token responses are prompt answers (keep them)
        if ' ' not in s and '\t' not in s and len(s) <= 120:
            return False
        # Long commands that start with a tool are clearly for Kali
        return True

    if current_state == 'raw_socket':
        first = s.split()[0].lower() if s.split() else ''
        kali_like = SLOW_TOOLS + INTERACTIVE_TOOLS + (
            'curl', 'wget', 'ls', 'cd', 'cat', 'pwd', 'whoami', 'id',
            'find', 'grep', 'echo', 'ps', 'kill', 'pkill', 'mkdir', 'rm',
            'cp', 'mv', 'chmod', 'chown', 'python', 'python3', 'bash', 'sh',
        )
        if first in kali_like:
            return True
        return False

    if current_state in ('ftp','smbclient','mysql','msfconsole','python',
                         'irb','redis','r2','gdb','pager'):
        first = s.split()[0].lower()
        return first in SLOW_TOOLS or first in INTERACTIVE_TOOLS
    return False


# ---------------- Sanity ----------------
print("\n[*] Sanity: shell on Control")
print(type_line("hostname; whoami; pwd; which nmap hydra ssh"))

# ---------------- Guard ----------------
def guard(cmd_line):
    s = cmd_line.strip()
    if not s:
        return (False, "Empty command. Emit a real shell command inside <cmd>...</cmd>.")
    if SENTINEL_RE.match(s):
        return (False, "Invalid command. Emit a real shell command.")

    # Never export the REMOTE marker on Kali. This marker is only valid
    # AFTER logging into a remote shell via SSH/telnet. Exporting it on
    # Kali makes the state classifier think we are inside Target.
    if re.match(r"^export\s+PS1\s*=\s*['\"]?###REMOTE###", s) and current_state is None:
        return (False,
                "You are on Kali. Do NOT export ###REMOTE### here. That marker is "
                "only valid AFTER logging into a remote shell via SSH or telnet. "
                "If you are on Kali, leave the prompt as-is (###PROMPT###[cwd]).")
    if EXIT_CMDS.match(s):
        # Only allow exit from known shell states, not from raw_socket
        # (which may already be dead) and not from None (Kali prompt).
        if current_state in ('remote','ftp','smbclient','mysql','msfconsole',
                             'python','irb','redis','r2','gdb','pager'):
            return (True, None)
        if current_state is not None:
            # raw_socket, __password__, etc: it's ambiguous — send ^C instead
            return (False, f"You are in '{current_state}'. To return to Kali "
                           f"emit <cmd>^C</cmd>. Do not use `exit` here.")
        return (False, "You are on Kali. `exit` would close the shell. "
                       "Emit a real command, or <done> if finished.")
    if current_state == 'remote' and s.startswith('ssh '):
        return (False, "You are inside a remote shell. Emit `exit` first, "
                       "or run plain commands on the remote host.")

    # Forbidden patterns (nc pipe, nc background, tmux+nc)
    if is_forbidden_cmd(s):
        return (False, "FORBIDDEN pattern. `nc | head`, `nc ... &`, and "
                       "`tmux send-keys ... nc` on telnet services lead to "
                       "hangs. Use `telnet <host>` in the FOREGROUND, wait "
                       "for the login prompt, then send the username.")

    return (True, None)

# ---------------- Duplicate filter ----------------
def normalize(cmd): return ' '.join(cmd.split()).strip().lower()
cmd_attempts = defaultdict(int)
filter_streak = 0

def escalation_nudge(streak, rejected_cmd=None, reason='duplicate', guard_msg=None):
    def _hint():
        return f" You emitted: {rejected_cmd}." if rejected_cmd else ""
    if current_state == '__password__':
        return (f"[SYSTEM NOTICE] You are at a PASSWORD prompt (streak: {streak})."
                f"{_hint()} Do NOT launch shell tools here. Emit a single-token "
                f"password, OR <cmd>^C</cmd> to abort and return to Kali.")
    if current_state == '__user__':
        return (f"[SYSTEM NOTICE] You are at a USERNAME prompt (streak: {streak})."
                f"{_hint()} Emit a single-token username, OR <cmd>^C</cmd>.")
    if current_state == '__yesno__':
        return (f"[SYSTEM NOTICE] You are at a YES/NO confirmation (streak: {streak})."
                f"{_hint()} Emit <cmd>yes</cmd> or <cmd>no</cmd>, OR "
                f"<cmd>^C</cmd> to abort.")
    if current_state == '__input__':
        return (f"[SYSTEM NOTICE] The shell is waiting for INPUT (streak: {streak})."
                f"{_hint()} Emit a short single-token answer, OR <cmd>^C</cmd>.")
    lines = [f"[SYSTEM NOTICE] Your last command was REJECTED (streak: {streak})."]
    if rejected_cmd:
        lines.append(f"The rejected command was: {rejected_cmd}")
    if reason == 'duplicate' and rejected_cmd:
        lines.append("Reason: DUPLICATE — you already emitted this exact command "
                     "earlier in this session. Its output is still in your history. "
                     "Re-read it instead of re-running. Do NOT re-emit this command.")
    elif reason == 'guard' and guard_msg:
        lines.append(f"Reason: {guard_msg}")
    elif reason == 'both' and guard_msg:
        lines.append(f"Reason: {guard_msg} AND it is a DUPLICATE.")
    lines.append("Pick a genuinely DIFFERENT command: different tool, different "
                 "service, different protocol, or a different technique on the "
                 "same service.")
    if streak >= 3:
        if current_state and current_state in ESCAPE_FOR:
            esc = ESCAPE_FOR[current_state].decode(errors='ignore').strip()
            lines.append(f"You are inside {current_state}. Leave it first with: {esc}")
        else:
            lines.append("Re-read everything you have collected. Investigate a "
                         "service, port, or protocol you have NOT touched yet.")
    return "\n".join(lines)

_SPECIAL_KEYS = ('^C', '^D', 'enter', '')

_recent_cmds = []   # deque of last N normalized commands
_LOOP_WINDOW     = 8    # how many recent commands to consider
_LOOP_THRESHOLD  = 5    # N consecutive identical commands -> loop

def apply_duplicate_filter(cmd_line):
    # Control keys and bare Enter never count as duplicates.
    if cmd_line.strip().lower() in ("^c", "^d", "enter", ""):
        return (False, 0)

    norm = normalize(cmd_line)

    # Track recent commands (bounded deque)
    _recent_cmds.append(norm)
    if len(_recent_cmds) > _LOOP_WINDOW:
        _recent_cmds.pop(0)

    # Count consecutive identical commands at the tail
    consecutive = 0
    for c in reversed(_recent_cmds):
        if c == norm:
            consecutive += 1
        else:
            break

    # Loop detected only if the SAME command was emitted N times in a row
    if consecutive >= _LOOP_THRESHOLD:
        return (True, consecutive)

    return (False, consecutive)


def reset_loop_tracker():
    """Called when a command produces new output (breaks the loop)."""
    _recent_cmds.clear()


# ---------------- Memory / context compaction ----------------
def estimate_chars(msgs):
    return sum(len(str(m.get("content", ""))) for m in msgs)

def _is_noise(msg):
    c = msg.get("content", "")
    return any(c.startswith(p) for p in MEM.get("skip_noise_prefixes", []))

def compact_history(msgs, original_task):
    """Deterministic truncation-based compaction — NO LLM call.

    Keeps head (system+task), tail (last N), and a truncated subset of the
    middle. Instant, 100% reliable. The old LLM-summary approach burned
    180s per turn when it timed out and never reduced context on failure.
    """
    keep_recent = int(MEM.get("keep_recent_messages", 8))
    if len(msgs) < keep_recent + 4:
        return msgs

    head = msgs[:2]
    middle = msgs[2:-keep_recent]
    tail = msgs[-keep_recent:]

    middle_clean = [m for m in middle if not _is_noise(m)]
    if not middle_clean:
        return msgs

    K = int(MEM.get("keep_middle_messages", 25))
    selected = middle_clean[-K:]
    dropped = len(middle) - len(selected)

    MAX_CHARS = int(MEM.get("truncate_chars_per_msg", 400))
    truncated = []
    for mm in selected:
        c = mm.get("content", "")
        if len(c) > MAX_CHARS:
            c = c[:MAX_CHARS].rstrip() + " …[truncated]"
        truncated.append({"role": mm.get("role", "user"), "content": c})

    marker = {
        "role": "user",
        "content": (
            f"[CONTEXT COMPACTED — {dropped} older messages dropped, "
            f"{len(selected)} recent messages kept with truncated content. "
            f"Continue from the last shell output shown.]"
        ),
    }
    return head + [marker] + truncated + tail


def maybe_compact(msgs, original_task):
    if not MEM.get("enabled", False):
        return msgs, False
    window = int(MEM.get("context_window_chars", 160000))
    threshold = int(window * float(MEM.get("trigger_at_percent", 0.80)))
    current = estimate_chars(msgs)
    if current <= threshold:
        return msgs, False
    print(f"  [memory] compacting: {current} chars > {threshold} chars threshold")
    before_msgs = len(msgs)
    new_msgs = compact_history(msgs, original_task)
    after_chars = estimate_chars(new_msgs)
    if len(new_msgs) == before_msgs and after_chars == current:
        MEM["enabled"] = False
        print(f"  [memory] compaction produced no change — disabling "
              f"for this run")
        return msgs, False
    print(f"  [memory] {before_msgs} msgs -> {len(new_msgs)} msgs, "
          f"{current} -> {after_chars} chars "
          f"({100*after_chars//max(current,1)}% of previous)")
    return new_msgs, (len(new_msgs) != before_msgs)

compaction_count = 0


def run_llm_turn(messages):
    """Send messages to Ollama, stream thinking+content, return (content, thinking_seen, err)."""
    global _request_interactive
    content = ""
    thinking_seen = False
    try:
        if STREAM:
            with requests.post(OLLAMA_URL + "/api/chat",
                               json=build_payload(True),
                               stream=True,
                               timeout=(30, READ_TIMEOUT)) as resp:
                resp.raise_for_status()
                print("\n🤖 MODEL:\n", end="", flush=True)
                in_thinking = False
                for raw in resp.iter_lines():
                    # Abort on Ctrl+C
                    if _request_interactive:
                        print("\n[!] LLM stream aborted by user.")
                        return content, thinking_seen, "interrupted"
                    if not raw: continue
                    try:
                        obj = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                    except Exception: continue
                    msg = obj.get("message", {}) or {}
                    think_tok = msg.get("thinking", "") or ""
                    tok       = msg.get("content", "")  or ""
                    if think_tok:
                        if not in_thinking:
                            print("\n\033[90m[thinking] ", end="", flush=True)
                            in_thinking = True
                        print(think_tok, end="", flush=True)
                        thinking_seen = True
                    if tok:
                        if in_thinking:
                            print("\033[0m\n", end="", flush=True)
                            in_thinking = False
                        print(tok, end="", flush=True)
                        content += tok
                    if obj.get("done"): break
                if in_thinking:
                    print("\033[0m", end="", flush=True)
                print("\n")
        else:
            resp = requests.post(OLLAMA_URL + "/api/chat",
                                 json=build_payload(False),
                                 timeout=REQ_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            msg = data.get("message", {}) or {}
            reasoning = msg.get("thinking", "") or ""
            content   = msg.get("content", "")  or ""
            if reasoning:
                thinking_seen = True
                print(f"\n💭 THINKING:\n\033[90m{reasoning}\033[0m")
            print(f"\n🤖 MODEL:\n{content}\n")
    except KeyboardInterrupt:
        _request_interactive = True
        print("\n[!] LLM stream interrupted by Ctrl+C.")
        return content, thinking_seen, "interrupted"
    except Exception as e:
        return content, thinking_seen, f"error: {e}"
    return content, thinking_seen, None


def _post_exec_truncation_hint(cmd_line, output_raw, output):
    """Return an actionable hint if the raw output was large/truncated."""
    raw_len = len(output_raw)
    sent_len = len(output)

    was_cut = ("[... " in output and
               (" bytes truncated " in output or " lines truncated " in output))

    if not was_cut and (raw_len < 5000 or raw_len == sent_len):
        return ""
    reduction = 1 - sent_len / max(raw_len, 1)

    s = cmd_line.strip()
    hints = []

    # ---- Detect tool type and whether it saved output ----
    tool_save_hints = [
        # (regex, "does it save?", suggestion when it doesn't)
        (r'\bnmap\b', r'-o[NAX]\b',
         'nmap ... -oN /tmp/nmap_full.txt  (or -oA /tmp/nmap_full)'),
        (r'\bffuf\b', r'-o\b',
         'ffuf ... -o /tmp/ffuf.json -of json'),
        (r'\bgobuster\b', r'-o\b',
         'gobuster ... -o /tmp/gobuster.txt'),
        (r'\bdirb\b', r'-o\b',
         'dirb <url> -o /tmp/dirb.txt'),
        (r'\bnikto\b', r'-o\b',
         'nikto -h <url> -o /tmp/nikto.txt'),
        (r'\bwhatweb\b', r'--log',
         'whatweb <url> --log-brief=/tmp/whatweb.txt'),
        (r'\bwpscan\b', r'-o\b',
         'wpscan ... -o /tmp/wpscan.txt'),
        (r'\bnuclei\b', r'-o\b',
         'nuclei ... -o /tmp/nuclei.txt'),
    ]

    tool_hint = None
    for tool_re, save_re, suggestion in tool_save_hints:
        if re.search(tool_re, s, re.I):
            # Did the user pass the save flag?
            if not re.search(save_re, s, re.I):
                tool_hint = suggestion
            break

    # ---- Detect file/URL targets in the command ----
    target = None
    m = re.search(r'\bcurl\b[^\n]*?(https?://\S+)', s)
    if m:
        target = m.group(1)
    m2 = re.search(r'\b(?:cat|head|tail|less|more)\s+(?:-\S+\s+)*([^\s-]\S*)', s)
    if m2 and not target:
        target = m2.group(1)

    # ---- Banner ----
    if was_cut or reduction > 0.4:
        if was_cut:
            hints.append(
                f"[!] Output was TRUNCATED (raw {raw_len}B -> sent {sent_len}B). "
                f"You are NOT seeing everything.")
        else:
            hints.append(
                f"[!] The raw output was {raw_len} bytes; only {sent_len} "
                f"reached you ({int(reduction*100)}% smaller). You are NOT "
                f"seeing everything.")

        # ---- Specific advice per command type ----

        # Case A: curl to a URL (target is URL)
        if target and target.startswith("http"):
            hints.append(
                f"    Download and analyze with AI:\n"
                f"      curl -s -o /tmp/_full {target} && "
                f"analyzer.py -q /tmp/_full && cat /tmp/_full.analysis")
            hints.append(
                f"    Or targeted grep without AI:\n"
                f"      curl -s {target} | grep -nE '<pattern>'")

        # Case B: file-reading command (target is local file)
        elif target:
            hints.append(
                f"    Analyze the full file with AI:\n"
                f"      analyzer.py -q {target} && cat {target}.analysis")
            hints.append(
                f"    Or targeted grep without AI:\n"
                f"      grep -nE '<pattern>' {target}")

        # Case C: scanning tool that didn't save → tell to re-run with save flag
        elif tool_hint:
            hints.append(
                f"    Re-run with save flag, then analyze:\n"
                f"      {tool_hint}\n"
                f"      analyzer.py -q <saved-file> && cat <saved-file>.analysis")
            hints.append(
                f"    Or targeted grep on the re-run output:\n"
                f"      {tool_hint} && grep -nE '<pattern>' <saved-file>")

        # Case D: unknown command, no target, no save flag detected
        else:
            hints.append(
                "    Re-run saving the output first:\n"
                "      <same-command> > /tmp/_full.txt\n"
                "      analyzer.py -q /tmp/_full.txt && cat /tmp/_full.txt.analysis")

    return "\n".join(hints)

def execute_cmd(cmd_line, check_guards=True, check_loop=True):
    """Run cmd_line through optional filters, execute on PTY, return (output, executed)."""
    global filter_streak

    if check_loop:
        filtered, count = apply_duplicate_filter(cmd_line)
    else:
        filtered, count = False, 0
    if check_guards:
        allow, err = guard(cmd_line)
    else:
        allow, err = True, None

    if filtered or not allow:
        filter_streak += 1
        if filtered and not allow:
            msg = escalation_nudge(filter_streak, rejected_cmd=cmd_line,
                                   reason='both', guard_msg=err)
        elif filtered:
            msg = escalation_nudge(filter_streak, rejected_cmd=cmd_line,
                                   reason='duplicate')
        else:
            msg = escalation_nudge(filter_streak, rejected_cmd=cmd_line,
                                   reason='guard', guard_msg=err)
        print(f"⛔ FILTERED (count={count}, allow={allow}): {msg}")
        return msg, False

    if escape_needed(cmd_line):
        print(f"⏏️  [AUTO-ESCAPE] state={current_state}, command={cmd_line!r}")
        if not force_escape_to_kali():
            msg = (f"You are stuck inside {current_state} and the command was "
                   f"not executed. Emit <cmd>exit</cmd> or the appropriate "
                   f"quit command to leave it first.")
            print(f"  [!] {msg}")
            return msg, False

    filter_streak = 0
    print(f"💻 CONTROL $ {cmd_line}")

    # Special handling: tmux capture-pane — poll for content
    poll_out = _intercept_tmux_capture(cmd_line)
    if poll_out is not None:
        output_raw = poll_out
        output = poll_out
        print(f"\n📤 OUTPUT:\n{output}\n")
        return output, True

    output_raw = type_line(cmd_line)
    output = filter_output(output_raw)

    # Loop tracker reset on new output
    if output.strip() and cmd_line.strip() not in ('^C', '^D'):
        if not hasattr(apply_duplicate_filter, "_last_output"):
            apply_duplicate_filter._last_output = {}
        prev = apply_duplicate_filter._last_output.get(cmd_line.strip())
        if prev != output:
            try:
                reset_loop_tracker()
            except NameError:
                pass
        apply_duplicate_filter._last_output[cmd_line.strip()] = output

    if len(output) < len(output_raw):
        print(f"  [filter] {len(output_raw)} -> {len(output)} bytes")
    # Post-exec hint: if output was strongly reduced, tell the model
    hint = _post_exec_truncation_hint(cmd_line, output_raw, output)
    if hint:
        output += "\n\n" + hint
        print(f"  [hint] truncation notice appended ({len(hint)} chars)")
    print(f"\n📤 OUTPUT:\n{output}\n")
    return output, True


def enter_interactive_mode(messages):
    """Interactive chat loop. Returns 'continue' (back to autonomous) or 'exit'."""
    global _in_interactive
    _in_interactive = True
    try:
        print("\n" + "=" * 72)
        print("  INTERACTIVE MODE")
        print("  - type a message to send to the model")
        print("  - /continue  -> resume autonomous mode")
        print("  - /exit      -> quit the agent")
        print("  - Ctrl+C     -> same as /continue")
        print("=" * 72)
        while True:
            try:
                user_input = input("\nYou> ").strip()
            except KeyboardInterrupt:
                print("\n[+] Ctrl+C — resuming autonomous mode.")
                return "continue"
            except EOFError:
                print("\n[+] EOF — resuming autonomous mode.")
                return "continue"

            if not user_input:
                continue
            if user_input == "/continue":
                print("[+] Resuming autonomous mode.")
                return "continue"
            if user_input == "/exit":
                print("[+] Exiting.")
                return "exit"

            messages.append({"role": "user", "content": user_input})
            content, thinking_seen, err = run_llm_turn(messages)

            if err == "interrupted":
                if content.strip():
                    messages.append({"role": "assistant", "content": content})
                continue
            if err:
                print(f"[!] {err}")
                continue

            if thinking_seen:
                print("[i] (model produced internal reasoning this turn)")

            if "<done>" in content:
                messages.append({"role": "assistant", "content": content})
                print("✅ Agent declared DONE.")
                return "exit"

            cmds = re.findall(r"<cmd>(.*?)</cmd>", content, re.DOTALL)
            if not cmds:
                messages.append({"role": "assistant", "content": content})
                print("⚠️  Model did not emit <cmd>. Nothing executed.")
                continue

            cmd_line = cmds[0].strip()
            messages.append({"role": "assistant", "content": content})

            # Try interceptors FIRST (same as autonomous mode)
            handled_curl, curl_out = try_curl_interception(cmd_line)
            if handled_curl:
                output = curl_out
                print(f"💻 CONTROL $ {cmd_line}  [curl via MAIN]")
                print(f"\n📤 OUTPUT:\n{output}\n")
            else:
                handled_an, analyzer_out = try_analyzer_interception(cmd_line)
                if handled_an:
                    output = analyzer_out
                    print(f"💻 CONTROL $ {cmd_line}  [analyzer via MAIN]")
                    print(f"\n📤 OUTPUT:\n{output}\n")
                else:
                    output, _ = execute_cmd(cmd_line, check_guards=False,
                                            check_loop=False)

            prefix = HEU.get("output_prefix", "[SHELL OUTPUT]")
            suffix = HEU.get("output_suffix", "[End of shell output.]")
            messages.append({"role": "user",
                             "content": f"{prefix}\n{output if output else '(no output)'}\n{suffix}"})
    finally:
        _in_interactive = False

# ---------------- Analyzer interceptor (runs on MAIN) ----------------
ANALYZER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "analyzer.py")
ANALYZER_ENABLED = os.path.exists(ANALYZER_SCRIPT)
if ANALYZER_ENABLED:
    print(f"[+] analyzer: {ANALYZER_SCRIPT} (runs on MAIN via tunnel)")
else:
    print("[i] analyzer.py not found locally; analyzer cmds run on Kali")


def _extract_analyzer_paths(cmd_line):
    """Return positional file paths from an 'analyzer.py ...' command."""
    try:
        tokens = shlex.split(cmd_line)
    except ValueError:
        return []
    idx = None
    for i, t in enumerate(tokens):
        if t.endswith("analyzer.py") or t == "analyzer":
            idx = i
            break
    if idx is None:
        return []
    SKIP = {"-q", "--quiet", "-r", "--force", "-S", "--stream",
            "--stats", "--warmup", "--no-toc", "--toc",
            "--line-numbers", "--no-line-numbers",
            "--adaptive-ctx", "--skip-synthesis"}
    VALUE = {"-m", "--model", "--host", "--chunk-size", "--num-ctx",
             "--num-predict", "--timeout", "--parallel",
             "--keep-alive", "--hot-threshold", "--stream-mode",
             "--stream-dir"}
    paths, i = [], idx + 1
    while i < len(tokens):
        t = tokens[i]
        if t in ("&&", "||", ";", "|", "&", ">", ">>", "<", "2>", "2>&1"):
            break
        if t in SKIP:
            i += 1; continue
        if t in VALUE:
            i += 2; continue
        if t.startswith("-"):
            i += 1; continue
        paths.append(t)
        i += 1
    return paths


def _run_analyzer_streaming(argv, env, timeout):
    """Run analyzer.py with real-time streaming of chunk progress.
    Returns (returncode, full_stdout)."""
    import threading as _th
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            bufsize=1,
        )
    except Exception as e:
        return (-1, f"launch failed: {e}")
    lines = []
    def _rd():
        for ln in iter(proc.stdout.readline, ""):
            s = ln.rstrip()
            if s:
                print(f"  [analyzer] {s}", flush=True)
            lines.append(ln)
    t = _th.Thread(target=_rd, daemon=True)
    t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        print(f"  [analyzer] TIMEOUT after {timeout}s", flush=True)
    t.join(timeout=3)
    return (proc.returncode, "".join(lines))


def try_curl_interception(cmd_line, timeout=None):
    """Transparent curl interceptor (runs on MAIN, uses the tunnel to Brain).

    If the model emits `curl -s <url>` (no pipes, no body, no mutations),
    download the file on Kali via PTY with a hard timeout + sentinel, then:
      - size < 5 KB  -> return raw content
      - size >= 5 KB -> run analyzer.py --lite and return its output
    Falls back to Kali if any step fails.
    """
    if not ANALYZER_ENABLED:
        return (False, None)
    s = cmd_line.strip()
    if not re.match(r'^\s*curl\b', s):
        return (False, None)

    # NEW: if the model does `curl URL | analyzer.py -q -`, strip the pipe
    # and treat it as a pure curl. The interceptor will download+analyze
    # the URL and return the analysis directly (no stdin needed).
    if re.search(r'\|\s*analyzer(?:\.py)?\b', s):
        print("  [curl-interceptor] 'curl | analyzer' detected; "
              "treating as pure curl")
        s = re.sub(r'\s*\|.*$', '', s).strip()

    # Bail on remaining pipes/redirects (not analyzer)
    if re.search(r'[|><]', s):
        return (False, None)          # pipe, redirect (>, <, >>, 2>, 2>&1)
    if re.search(r'(&&|\|\||;)', s):
        return (False, None)          # chained commands
    if re.search(r'\s(-X|--request)\s+(POST|PUT|DELETE|PATCH)', s, re.I):
        return (False, None)
    if re.search(r'\s(-d|--data|--data-raw|-F|--form)\b', s):
        return (False, None)
    # If the model uses -o/--output/-O, it wants the file at a SPECIFIC path.
    # Do not intercept; let Kali write to that path so `cat <file>` works.

    urls = re.findall(r'https?://[^\s\'\"]+', s)
    if len(urls) != 1:
        return (False, None)
    url = urls[0]

    # Skip loopback (Kali itself)
    from urllib.parse import urlparse
    try:
        _host = (urlparse(url).hostname or "").lower()
    except Exception:
        _host = ""
    if (_host in ("", "localhost", "127.0.0.1", "0.0.0.0", "::1", "::")
            or _host.startswith("127.") or _host.endswith(".localhost")):
        return (False, None)

    import hashlib
    url_hash = hashlib.sha1(url.encode()).hexdigest()[:10]
    remote_tmp = f"/tmp/_hive_curl_{os.getpid()}_{url_hash}"
    local_tmp = remote_tmp

    print(f"  [curl-interceptor] {url}")

    # 1) Curl on Kali via PTY with timeout + sentinel (NO execute_cmd)
    curl_cmd = (
        f"timeout 60 curl -sS -L --max-time 45 -o {remote_tmp} "
        f"{shlex.quote(url)} 2>&1; echo __CURL_DONE__"
    )
    print(f"  [curl-interceptor] step 1: exec curl on Kali (timeout 60s)")
    try:
        _wait_quiescent(timeout=2.0, quiet=0.2)
        if not _safe_send((curl_cmd + "\n").encode(), "curl-interceptor"):
            return (False, None)
        buf = b""
        start = time.time()
        sentinel = b"__CURL_DONE__"
        while time.time() - start < 70.0:
            if shell.recv_ready():
                buf += shell.recv(65535)
                if sentinel in buf:
                    break
            else:
                time.sleep(0.05)
        exec_out = buf.decode(errors="replace")
        has_sentinel = "__CURL_DONE__" in exec_out
        print(f"  [curl-interceptor] step 1 OK (output_len={len(exec_out)}, "
              f"has_sentinel={has_sentinel})")
        if not has_sentinel:
            print("  [curl-interceptor] no sentinel — curl hung; fallback")
            return (False, None)
    except Exception as e:
        print(f"  [curl-interceptor] step 1 FAILED: {e}")
        return (False, None)

    # 2) SFTP: fresh client with timeout
    sftp = None
    try:
        print(f"  [curl-interceptor] step 2: open SFTP")
        sftp = paramiko.SFTPClient.from_transport(control)
        sftp.get_channel().settimeout(10.0)
        print(f"  [curl-interceptor] step 2 OK")

        print(f"  [curl-interceptor] step 3: stat {remote_tmp}")
        try:
            st = sftp.stat(remote_tmp)
            size = st.st_size
        except FileNotFoundError:
            print(f"  [curl-interceptor] file not created — fallback")
            return (False, None)
        except Exception as e:
            print(f"  [curl-interceptor] stat FAILED: {e} — fallback")
            return (False, None)
        print(f"  [curl-interceptor] step 3 OK (size={size}B)")

        if size == 0 or size > 50 * 1024 * 1024:
            print(f"  [curl-interceptor] size {size}B out of range — fallback")
            return (False, None)

        # Small: return raw
        if size < 5000:
            print(f"  [curl-interceptor] step 4: read raw ({size}B)")
            with sftp.open(remote_tmp, "r") as fh:
                fh.prefetch(size)
                raw = fh.read()
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", errors="replace")
            try: sftp.remove(remote_tmp)
            except Exception: pass
            print(f"  [curl-interceptor] step 4 OK (raw {len(raw)} chars)")
            return (True, raw)

        # Large: download + analyze
        print(f"  [curl-interceptor] step 5: GET {size}B to MAIN")
        sftp.get(remote_tmp, local_tmp)
        print(f"  [curl-interceptor] step 5 OK")

        env = os.environ.copy()
        env["ANALYZER_HOST"] = OLLAMA_URL
        env["ANALYZER_MODEL"] = MODEL
        env.setdefault("ANALYZER_TIMEOUT", str(REQ_TIMEOUT))
        env["ANALYZER_NUM_CTX"] = str(MODEL_OPTS.get("num_ctx", 32768))
        if "num_gpu" in MODEL_OPTS:
            env["ANALYZER_NUM_GPU"] = str(MODEL_OPTS["num_gpu"])
        env["ANALYZER_KEEP_ALIVE"] = "30m"
        if "stop" in MODEL_OPTS:
            env["ANALYZER_STOP"] = "\n".join(MODEL_OPTS["stop"])
        to = timeout or int(TMO.get("slow_maxt", 600))

        print(f"  [curl-interceptor] step 6: run analyzer --lite")
        try:
            rc, analyzer_stdout = _run_analyzer_streaming(

                ["python3", ANALYZER_SCRIPT, "-q", "--lite", "--parallel", "1", local_p, "-S", "--stream-mode", "raw", "--chunk-size", "25000"],

                env, to)

            r = type('R', (), {'returncode': rc, 'stdout': analyzer_stdout, 'stderr': ''})()
            if r.stdout.strip():
                print(f"  [analyzer stdout] {r.stdout.strip()[:200]}")
            if r.returncode != 0 and r.stderr.strip():
                print(f"  [analyzer stderr] {r.stderr.strip()[:300]}")
            print(f"  [curl-interceptor] step 6 OK (rc={r.returncode})")
            # If analysis failed, delete stale .analysis on Kali so the
            # model doesn't `cat` old data from a previous target.
            if r.returncode != 0:
                try:
                    sftp.remove(remote_tmp + ".analysis")
                    print(f"  [curl-interceptor] removed stale .analysis")
                except Exception:
                    pass
                return (True, f"[curl OK but analyzer failed rc={r.returncode}] "
                              f"Output saved at {remote_tmp}. Do not cat the .analysis "
                              f"(stale removed). Try: analyzer.py -q {remote_tmp}")
        except subprocess.TimeoutExpired:
            print(f"  [curl-interceptor] step 6 TIMEOUT")
            try: sftp.remove(remote_tmp + ".analysis")
            except Exception: pass
            return (True, f"[curl {url} -> {size}B, analyzer timeout]")
        except Exception as e:
            print(f"  [curl-interceptor] step 6 FAILED: {e}")
            try: sftp.remove(remote_tmp + ".analysis")
            except Exception: pass
            return (False, None)

        analysis_local = local_tmp + ".analysis"
        if not os.path.exists(analysis_local):
            print(f"  [curl-interceptor] no .analysis — fallback")
            return (False, None)

        with open(analysis_local, "r", encoding="utf-8") as fh:
            analysis_text = fh.read()

        try:
            sftp.put(analysis_local, remote_tmp + ".analysis")
            print(f"  [curl-interceptor] uploaded .analysis")
        except Exception as e:
            print(f"  [curl-interceptor] upload failed: {e}")

        for f in (local_tmp, analysis_local):
            try: os.unlink(f)
            except Exception: pass

        return (True,
                f"[curl {url} -> {size}B, analyzed via analyzer.py --lite]\n"
                f"[saved on Kali at {remote_tmp} and {remote_tmp}.analysis]\n\n"
                + analysis_text)
    except Exception as e:
        print(f"  [curl-interceptor] unexpected error: {e}")
        return (False, None)
    finally:
        if sftp:
            try: sftp.close()
            except Exception: pass


def try_analyzer_interception(cmd_line, timeout=None):
    """If cmd_line runs analyzer.py on files that exist on Kali, do a
    SFTP round-trip: copy files here, run analyzer locally (using the
    MAIN->Brain tunnel), copy .analysis back. Returns (handled, output).

    On any error, returns (False, None) so the Kali path executes normally.
    """
    # COMPOUND HANDLER: "curl -o FILE URL && analyzer.py ... FILE ..."
    # Pre-execute the curl on Kali to create the file, then intercept
    # the analyzer on the existing file. This makes the compound command
    # work in ONE turn instead of failing because the file doesn't exist yet.
    compound = re.search(
        r'^\s*curl\s+[^\n]*?-o\s+(\S+)\s+[^\n]*?(https?://\S+)'
        r'[^\n]*?&&\s*analyzer(?:\.py)?\s+(.+?)(?:\s*&&\s*.*)?$',
        cmd_line, re.DOTALL
    )
    if compound:
        target_file = compound.group(1)
        target_url = compound.group(2)
        analyzer_args = compound.group(3).strip()
        # Cut anything after the analyzer part (e.g. "&& cat F.analysis")
        if "&&" in analyzer_args:
            analyzer_args = analyzer_args.split("&&")[0].strip()
        print(f"  [analyzer-compound] curl {target_url} -> {target_file}")
        print(f"  [analyzer-compound] analyzer.py {analyzer_args}")

        # Step 1: execute the curl on Kali (creates the file)
        # `&&` (not `;`) so the sentinel only appears on success.
        # `sync` after curl to force kernel flush before we SFTP stat.
        # rm -f first: guarantees we analyze THIS target's content, not
        # leftovers from a previous target. Use `;` before the sentinel
        # echo so it always appears (success or failure).
        curl_cmd = (f"rm -f {target_file} {target_file}.analysis; "
                    f"timeout 60 curl -sS -L --max-time 45 "
                    f"-o {target_file} {shlex.quote(target_url)} 2>&1; "
                    f"sync; echo __CURL_DONE__")
        try:
            _wait_quiescent(timeout=2.0, quiet=0.2)
            if not _safe_send((curl_cmd + "\n").encode(), "compound-curl"):
                return (True, "[ERROR] could not send curl to Kali")
            buf = b""
            start = time.time()
            while time.time() - start < 70.0:
                if shell.recv_ready():
                    buf += shell.recv(65535)
                    if b"__CURL_DONE__" in buf:
                        break
                else:
                    time.sleep(0.05)
            exec_out = buf.decode(errors="replace")
            if "__CURL_DONE__" not in exec_out:
                # Strip the echo line and show the real error tail
                tail = exec_out[-300:].strip()
                return (True,
                        f"[ERROR] curl failed for {target_url}. "
                        f"Output:\n{tail}")
            print(f"  [analyzer-compound] step 1 OK ({len(exec_out)}B)")
        except Exception as e:
            return (True, f"[ERROR] curl failed: {e}")

        # Step 1b: verify the file exists with size > 0 on Kali
        # (defense against silent curl failures and FS flush lag)
        try:
            sftp_v = paramiko.SFTPClient.from_transport(control)
            sftp_v.get_channel().settimeout(10.0)
            st_v = None
            for _a in range(8):
                try:
                    st_v = sftp_v.stat(target_file)
                    break
                except FileNotFoundError:
                    time.sleep(0.4)
            sftp_v.close()
            if st_v is None:
                return (True,
                        f"[ERROR] curl did not create {target_file}. "
                        f"Target may be unreachable via HTTP or URL is wrong. "
                        f"Diagnose: curl -sS -I -m 10 {shlex.quote(target_url)}")
            size_v = st_v.st_size
            if size_v == 0:
                return (True,
                        f"[ERROR] curl produced a 0-byte file at "
                        f"{target_file}. Server returned an error. "
                        f"Check: curl -sS -I {shlex.quote(target_url)}")
            print(f"  [analyzer-compound] verified {target_file} ({size_v}B)")
        except Exception as e:
            print(f"  [analyzer-compound] verify warning: {e}")

        # Step 2: file now exists on Kali. Intercept the analyzer part.
        new_cmd = f"analyzer.py {analyzer_args}"
        handled, out = try_analyzer_interception(new_cmd, timeout)
        if handled:
            return (True, f"[curl OK: {target_url} -> {target_file}]\n\n{out}")
        return (True, f"[curl OK, analyzer not intercepted]\n{exec_out}")

    if not ANALYZER_ENABLED:
        return (False, None)
    if "analyzer.py" not in cmd_line and "analyzer " not in cmd_line:
        return (False, None)
    paths = _extract_analyzer_paths(cmd_line)
    if not paths:
        return (False, None)
    # Relative paths: skip (can't resolve reliably from MAIN)
    paths = [p for p in paths if p.startswith("/")]
    if not paths:
        return (False, None)

    print(f"  [analyzer-interceptor] {len(paths)} target(s): {paths}")
    sftp = None
    local_map = {}
    try:
        sftp = paramiko.SFTPClient.from_transport(control)

        # 1. GET each file from Kali
        for p in paths:
            local = f"/tmp/_hive_an_{os.getpid()}_{os.path.basename(p)}"
            # Retry stat: the caller may have JUST written this file via PTY,
            # and the kernel may not have flushed the inode yet.
            st = None
            last_err = None
            for attempt in range(8):
                try:
                    st = sftp.stat(p)
                    break
                except FileNotFoundError as e:
                    last_err = e
                    time.sleep(0.4)
                except Exception as e:
                    last_err = e
                    break
            try:
                if st is None:
                    raise last_err if last_err else FileNotFoundError(p)
                if st.st_size > 50 * 1024 * 1024:
                    print(f"  [analyzer] > 50 MB, falling back to Kali: {p}")
                    return (False, None)
                sftp.get(p, local)
                local_map[p] = local
                print(f"  [analyzer] GET {p} ({st.st_size}B) -> {local}")
            except FileNotFoundError:
                print(f"  [analyzer] not found on Kali after retries: {p}")
                return (True,
                        f"[ERROR] {p} does not exist on Kali (checked "
                        f"8 times over ~3.2s). The curl before it may have "
                        f"failed, or the file was never created.\n"
                        f"Try manually:\n"
                        f"  curl -sS -L -o {p} <url>\n"
                        f"  ls -la {p}\n"
                        f"  analyzer.py -q {p} && cat {p}.analysis")
            except Exception as e:
                print(f"  [analyzer] GET failed: {e}")
                return (True, f"[ERROR] Could not stat {p}: {e}")

        # 2. Run analyzer locally (uses the MAIN tunnel to Brain)
        env = os.environ.copy()
        env["ANALYZER_HOST"] = OLLAMA_URL
        env["ANALYZER_MODEL"] = MODEL
        env.setdefault("ANALYZER_TIMEOUT", str(REQ_TIMEOUT))
        # CRITICAL: match the agent's context/model config to avoid Ollama
        # reloading the model between analyzer and agent turns.
        env["ANALYZER_NUM_CTX"] = str(MODEL_OPTS.get("num_ctx", 32768))
        if "num_gpu" in MODEL_OPTS:
            env["ANALYZER_NUM_GPU"] = str(MODEL_OPTS["num_gpu"])
        # Keep the model hot between turns
        env["ANALYZER_KEEP_ALIVE"] = "30m"
        # Always include the agent's stop sequences so the analyzer
        # doesn't emit ###PROMPT### noise at the end
        if "stop" in MODEL_OPTS:
            env["ANALYZER_STOP"] = "\n".join(MODEL_OPTS["stop"])
        to = timeout or int(TMO.get("slow_maxt", 600))

        lines = []
        for kali_p, local_p in local_map.items():
            try:
                rc, analyzer_stdout = _run_analyzer_streaming(

                     ["python3", ANALYZER_SCRIPT, "-q", "--lite", "--parallel", "1", local_p, "-S", "--stream-mode", "raw", "--chunk-size", "25000"],

                    env, to)

                r = type('R', (), {'returncode': rc, 'stdout': analyzer_stdout, 'stderr': ''})()
                lines.append(f"$ analyzer.py -q {kali_p}")
                if r.stdout.strip():
                    lines.append(r.stdout.rstrip())
                if r.returncode != 0 and r.stderr.strip():
                    lines.append(f"[stderr] {r.stderr.strip()[:400]}")
            except subprocess.TimeoutExpired:
                lines.append(f"[TIMEOUT after {to}s: {kali_p}]")
            except Exception as e:
                lines.append(f"[ERROR: {e}]")

        # 3. PUT .analysis back to Kali
        for kali_p, local_p in local_map.items():
            la, ka = local_p + ".analysis", kali_p + ".analysis"
            if os.path.exists(la):
                try:
                    sftp.put(la, ka)
                    lines.append(f"[uploaded {ka}]")
                except Exception as e:
                    lines.append(f"[upload failed: {e}]")

        return (True, "\n".join(lines))

    except Exception as e:
        print(f"  [analyzer-interceptor] error: {e}; falling back to Kali")
        return (False, None)
    finally:
        if sftp:
            try: sftp.close()
            except Exception: pass
        for lp in local_map.values():
            for suf in ("", ".analysis"):
                try: os.unlink(lp + suf)
                except Exception: pass


# ---------------- Agent loop ----------------
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user",   "content": USER_PROMPT},
]

# Build the payload base once, reusing for every iteration.
def build_payload(stream):
    payload = {
        "model": MODEL,
        "messages": messages,
        "stream": stream,
        "options": MODEL_OPTS,
    }
    # Pass 'think' to Ollama if the config explicitly asks for it
    if "think" in MODEL_OPTS:
        payload["think"] = bool(MODEL_OPTS["think"])
    return payload

for i in range(MAX_ITERS):
    # Ctrl+C was pressed -> enter interactive mode
    if _request_interactive:
        _request_interactive = False
        result = enter_interactive_mode(messages)
        if result == "exit":
            break
        continue

    print("\n" + "=" * 72)
    print(f"  ITERATION {i+1}/{MAX_ITERS}   [state={current_state}, streak={filter_streak}]")
    print("=" * 72)

    messages, did_compact = maybe_compact(messages, USER_PROMPT)
    if did_compact:
        compaction_count += 1

    content, thinking_seen, err = run_llm_turn(messages)

    if err == "interrupted":
        if content.strip():
            messages.append({"role": "assistant", "content": content})
        _request_interactive = False
        result = enter_interactive_mode(messages)
        if result == "exit":
            break
        continue
    if err:
        print(f"[!] LLM error: {err}")
        break

    if thinking_seen:
        print("[i] (model produced internal reasoning this turn)")

    if "<done>" in content:
        messages.append({"role": "assistant", "content": content})
        print("✅ Agent declared DONE.")
        break

    cmds = re.findall(r"<cmd>(.*?)</cmd>", content, re.DOTALL)
    if not cmds:
        messages.append({"role": "assistant", "content": content})
        print("⚠️  No <cmd>. Reminding format.")
        if is_chatty_response(content):
            print("  [chatty] model wrote prose instead of acting; correcting")
            reminder = ("[STOP] You broke character. You are NOT a chatbot and "
                        "there is NO human reading this conversation. You are a "
                        "command-execution agent. Do NOT write explanations, "
                        "summaries, recommendations, or 'would you like' offers. "
                        "Do NOT use markdown headers or tables. Look at the last "
                        "shell output, decide the NEXT shell command, and emit "
                        "exactly ONE <cmd>...</cmd> line (or <done>...</done> if "
                        "the mission is complete).")
        else:
            reminder = "Format error: emit exactly one <cmd>line</cmd> or <done>summary</done>."
        messages.append({"role": "user", "content": reminder})
        continue

    cmd_line = cmds[0].strip()
    filtered, count = apply_duplicate_filter(cmd_line)
    allow, err2 = guard(cmd_line)

    if filtered or not allow:
        filter_streak += 1
        if filtered and not allow:
            msg = escalation_nudge(filter_streak, rejected_cmd=cmd_line,
                                   reason='both', guard_msg=err2)
        elif filtered:
            msg = escalation_nudge(filter_streak, rejected_cmd=cmd_line,
                                   reason='duplicate')
        else:
            msg = escalation_nudge(filter_streak, rejected_cmd=cmd_line,
                                   reason='guard', guard_msg=err2)
        print(f"⛔ FILTERED (count={count}, allow={allow}): {msg}")
        messages.append({"role": "user", "content": msg})
        continue

    if escape_needed(cmd_line):
        print(f"⏏️  [AUTO-ESCAPE] state={current_state}, command={cmd_line!r}")
        if not force_escape_to_kali():
            msg = (f"You are stuck inside {current_state} and the command was "
                   f"not executed. Emit <cmd>exit</cmd> or the appropriate "
                   f"quit command to leave it first.")
            print(f"  [!] {msg}")
            messages.append({"role": "user", "content": msg})
            continue

    filter_streak = 0
    messages.append({"role": "assistant", "content": content})

    # --- curl interceptor: transparent download+analyze ---
    handled, curl_out = try_curl_interception(cmd_line)
    if handled:
        output = curl_out
        print(f"💻 CONTROL $ {cmd_line}  [curl via MAIN]")
        print(f"\n📤 OUTPUT:\n{output}\n")
        prefix = HEU.get("output_prefix", "[SHELL OUTPUT]")
        suffix = HEU.get("output_suffix", "[End of shell output.]")
        messages.append({"role": "user",
                         "content": f"{prefix}\n{output if output else '(no output)'}\n{suffix}"})
        continue

    # --- Analyzer interceptor: run analyzer.py on MAIN when possible ---
    handled, analyzer_out = try_analyzer_interception(cmd_line)
    if handled:
        output = analyzer_out
        print(f"💻 CONTROL $ {cmd_line}  [analyzer via MAIN]")
        print(f"\n📤 OUTPUT:\n{output}\n")
        prefix = HEU.get("output_prefix", "[SHELL OUTPUT]")
        suffix = HEU.get("output_suffix", "[End of shell output.]")
        messages.append({"role": "user",
                         "content": f"{prefix}\n{output if output else '(no output)'}\n{suffix}"})
        continue
    # --- end analyzer interceptor ---

    output, _ = execute_cmd(cmd_line, check_guards=False, check_loop=False)
    prefix = HEU.get("output_prefix", "[SHELL OUTPUT]")
    suffix = HEU.get("output_suffix", "[End of shell output.]")
    messages.append({"role": "user",
                     "content": f"{prefix}\n{output if output else '(no output)'}\n{suffix}"})

    if _request_interactive:
        _request_interactive = False
        result = enter_interactive_mode(messages)
        if result == "exit":
            break

# ---------------- Cleanup ----------------
print("\n[*] Shutting down...")
try: shell.close()
except Exception: pass
try: _proxy.shutdown()
except Exception: pass
for t in (control, brain):
    try: t.close()
    except Exception: pass
if MEM.get("enabled", False):
    print(f"[*] Context compactions this run: {compaction_count}")
print("[*] Done.")