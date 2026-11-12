#!/usr/bin/env python3
"""
HIVEPLUS agent — configuration-driven.

All tunables (IPs, credentials, model, prompts, patterns, escapes,
timeouts, setup, heuristics) live in config.yaml. Nothing target- or
host-specific is hardcoded here.

Run:    python main_agent.py [-c config.yaml]
"""
import paramiko, requests, socketserver, threading, select
import socket, sys, os, re, time, json, argparse
from collections import defaultdict
import yaml
try:
    from output_filter import OutputFilter
except ImportError:
    OutputFilter = None

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

# Inference parameters — filter out None values
MODEL_OPTS = {k: v for k, v in MCFG.get("params", {}).items() if v is not None}
if MODEL_OPTS:
    print(f"[+] Model params: {MODEL_OPTS}")

PROMPT_MARK  = MKR["kali"]
REMOTE_MARK  = MKR["remote"]

DUPLICATE_THRESHOLD = int(FLT["duplicate_threshold"])
SLOW_TOOLS          = tuple(FLT["slow_tools"])
INTERACTIVE_TOOLS   = tuple(FLT["interactive_tools"])
EXIT_CMDS           = re.compile(FLT["exit_cmds_regex"], re.I)
SENTINEL_RE         = re.compile(FLT["sentinel_regex"])

LISTENER_PATTERNS = [re.compile(p) for p in FLT.get("listener_patterns", [])]

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
def _mk(h, u, p):
    t = paramiko.Transport((h, 22)); t.start_client(); t.auth_password(u, p); return t
def _mk_via(j, h, u, p):
    ch = j.open_channel('direct-tcpip', (h, 22), ('127.0.0.1', 0))
    t  = paramiko.Transport(ch); t.start_client(); t.auth_password(u, p); return t

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
    tokens = re.split(r'[\s;|&]+', cmd_line.strip().lower())
    return any(t in SLOW_TOOLS for t in tokens[:3])

def _read_until(idle=None, maxt=None, allow_idle_exit=True):
    idle = TMO["default_idle"] if idle is None else idle
    maxt = TMO["default_maxt"] if maxt is None else maxt
    out = b""
    last = time.time(); start = time.time()
    while True:
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

def classify_output(output, prev_cmd):
    if not output: return False
    cleaned = ANSI_RE.sub('', output)
    lines = [l.rstrip() for l in cleaned.split('\n') if l.strip()]
    if not lines: return False
    last = lines[-1].strip()

    if REMOTE_MARK in last: return 'remote'
    if PROMPT_MARK in last: return None

    for pattern, name in PROMPT_PATTERNS:
        if pattern.search(last):
            return name

    if prev_cmd and prev_cmd.lstrip().startswith('ssh'):
        joined = '\n'.join(lines[-40:])
        if any(m in joined for m in SSH_FAIL_MARKERS):
            return None
        if re.search(r'[\$#>%]\s*$', last) and '~' in last:
            return 'remote'
        if re.search(r'^[\w.-]+@[\w.-]+[:~][^\n]*[\$#>]\s*$', last):
            return 'remote'

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

def type_line(line):
    stripped = line.strip()
    if stripped == "^C":
        shell.send(b"\x03")
        out = _read_until(idle=TMO["ctrl_idle"], maxt=TMO["ctrl_maxt"]).decode(errors='replace')
        update_state(out, '^C')
        if current_state is not None and PROMPT_MARK not in out:
            shell.send(b'\n')
            out2 = _read_until(idle=TMO["ctrl_probe_idle"],
                               maxt=TMO["ctrl_probe_maxt"]).decode(errors='replace')
            update_state(out2, ''); out += out2
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
    shell.send(line)

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
        shell.send(esc); time.sleep(0.6)
        out = _read_until(idle=TMO["ctrl_idle"],
                          maxt=TMO["setup_maxt"]).decode(errors='replace')
        update_state(out, '')
        if current_state in ('__password__', '__user__') and attempt >= 2:
            shell.send(b'\n\x03\n'); time.sleep(0.6)
            out = _read_until(idle=TMO["ctrl_idle"],
                              maxt=TMO["setup_maxt"]).decode(errors='replace')
            update_state(out, '')
    return current_state is None

def escape_needed(cmd_line):
    if current_state is None: return False
    s = cmd_line.strip()
    if not s: return False
    if EXIT_CMDS.match(s): return False
    if s in ('^C', '^D'): return False
    if current_state in ('__password__','__user__','__yesno__','__input__'):
        return ' ' in s or '\t' in s or len(s) > 120
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
    if EXIT_CMDS.match(s):
        if current_state is not None: return (True, None)
        return (False, "You are on Kali. `exit` would close the shell. "
                       "Emit a real command, or <done> if finished.")
    if current_state == 'remote' and s.startswith('ssh '):
        return (False, "You are inside a remote shell. Emit `exit` first, "
                       "or run plain commands on the remote host.")
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

def apply_duplicate_filter(cmd_line):
    if cmd_line.strip() in ('^C', '^D'): return (False, 0)
    norm = normalize(cmd_line)
    cmd_attempts[norm] += 1
    count = cmd_attempts[norm]
    if current_state in ('__password__','__user__','__yesno__','__input__'):
        s = cmd_line.strip()
        if (' ' not in s and '\t' not in s and len(s) <= 120
                and not EXIT_CMDS.match(s)):
            return (False, count)
    return (count > DUPLICATE_THRESHOLD, count)

# ---------------- Memory / context compaction ----------------
def estimate_chars(msgs):
    return sum(len(str(m.get("content", ""))) for m in msgs)

def _is_noise(msg):
    c = msg.get("content", "")
    return any(c.startswith(p) for p in MEM.get("skip_noise_prefixes", []))

def compact_history(msgs, original_task):
    """Keep system+task+recent, summarize the middle into one message."""
    keep_recent = int(MEM.get("keep_recent_messages", 6))
    if len(msgs) < keep_recent + 4:
        return msgs
    head = msgs[:2]
    middle = msgs[2:-keep_recent]
    tail = msgs[-keep_recent:]
    middle_clean = [m for m in middle if not _is_noise(m)]
    if not middle_clean:
        return msgs

    conv = "\n\n".join(
        f"[{m['role'].upper()}]\n{m['content'][:2000]}"
        for m in middle_clean
    )
    summary_prompt = MEM.get("summary_prompt",
        "Summarize this pentest progress compactly.")
    summary_req = [
        {"role": "system", "content": summary_prompt},
        {"role": "user", "content":
            f"ORIGINAL OBJECTIVE:\n{original_task}\n\n"
            f"CONVERSATION TO SUMMARIZE (middle of session):\n{conv}"},
    ]
    model_for_summary = MEM.get("summary_model") or MODEL
    try:
        r = requests.post(
            OLLAMA_URL + "/api/chat",
            json={"model": model_for_summary,
                  "messages": summary_req,
                  "stream": False,
                  "options": {k: v for k, v in MODEL_OPTS.items()
                              if k in ("temperature","top_p","top_k","min_p",
                                       "repeat_penalty","repeat_last_n",
                                       "num_ctx","seed")}},  # no stop, no num_predict
            timeout=MEM.get("summary_timeout", 180),
        )
        r.raise_for_status()
        summary = r.json()["message"]["content"].strip()
    except Exception as e:
        print(f"  [memory] summary failed: {e} (keeping full history)")
        return msgs

    summary_msg = {
        "role": "user",
        "content": (
            "[PROGRESS SUMMARY — you are in the middle of a long session. "
            f"This summary REPLACES the previous {len(middle)} turns. Treat it "
            "as ground truth. Continue from here.]\n\n" + summary
        ),
    }
    return head + [summary_msg] + tail

def maybe_compact(msgs, original_task):
    if not MEM.get("enabled", False):
        return msgs, False
    window = int(MEM.get("context_window_chars", 120000))
    threshold = int(window * float(MEM.get("trigger_at_percent", 0.75)))
    current = estimate_chars(msgs)
    if current <= threshold:
        return msgs, False
    print(f"  [memory] compacting: {current} chars > {threshold} chars threshold")
    before_msgs = len(msgs)
    new_msgs = compact_history(msgs, original_task)
    after_chars = estimate_chars(new_msgs)
    print(f"  [memory] {before_msgs} msgs -> {len(new_msgs)} msgs, "
          f"{current} -> {after_chars} chars "
          f"({100*after_chars//max(current,1)}% of previous)")
    return new_msgs, (len(new_msgs) != before_msgs)

compaction_count = 0

# ---------------- Agent loop ----------------
messages = [
    {"role": "system", "content": SYSTEM_PROMPT},
    {"role": "user",   "content": USER_PROMPT},
]

for i in range(MAX_ITERS):
    print("\n" + "=" * 72)
    print(f"  ITERATION {i+1}/{MAX_ITERS}   [state={current_state}, streak={filter_streak}]")
    print("=" * 72)

    # --- context compaction ---
    messages, did_compact = maybe_compact(messages, USER_PROMPT)
    if did_compact:
        compaction_count += 1

    content = ""
    try:
        if STREAM:
            with requests.post(OLLAMA_URL + "/api/chat",
                               json={"model": MODEL, "messages": messages,
                                     "stream": True, "options": MODEL_OPTS},
                               stream=True, timeout=REQ_TIMEOUT) as resp:
                resp.raise_for_status()
                print("\n🤖 MODEL:\n", end="", flush=True)
                for raw in resp.iter_lines():
                    if not raw: continue
                    try:
                        obj = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                    except Exception: continue
                    tok = obj.get("message", {}).get("content", "")
                    if tok:
                        print(tok, end="", flush=True)
                        content += tok
                    if obj.get("done"): break
                print("\n")
        else:
            resp = requests.post(OLLAMA_URL + "/api/chat",
                                 json={"model": MODEL, "messages": messages,
                                       "stream": False, "options": MODEL_OPTS},
                                 timeout=REQ_TIMEOUT)
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
            print(f"\n🤖 MODEL:\n{content}\n")
    except Exception as e:
        print(f"[!] Ollama error: {e}"); break

    if "<done>" in content:
        messages.append({"role": "assistant", "content": content})
        print("✅ Agent declared DONE."); break

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
    allow, err = guard(cmd_line)

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
        messages.append({"role": "user", "content": msg})
        continue

    if escape_needed(cmd_line):
        print(f"⏏️  [AUTO-ESCAPE] state={current_state}, command={cmd_line!r}")
        if not force_escape_to_kali():
            msg = (f"You are stuck inside {current_state} and the command was "
                   f"not executed. Emit <cmd>exit</cmd> or the appropriate "
                   f"quit command to leave it first.")
            print(f"  [!] {msg}")
            messages.append({"role": "user", "content": msg}); continue

    filter_streak = 0
    messages.append({"role": "assistant", "content": content})

    print(f"💻 CONTROL $ {cmd_line}")
    output_raw = type_line(cmd_line)
    output = filter_output(output_raw)
    if len(output) < len(output_raw):
        print(f"  [filter] {len(output_raw)} -> {len(output)} bytes")
    print(f"\n📤 OUTPUT:\n{output}\n")
    prefix = HEU.get("output_prefix", "[SHELL OUTPUT]")
    suffix = HEU.get("output_suffix", "[End of shell output.]")
    messages.append({"role": "user",
        "content": f"{prefix}\n{output if output else '(no output)'}\n{suffix}"})

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
