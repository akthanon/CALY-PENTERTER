# CALY-PENTERTER

**Autonomous pentest agent driven by a local LLM.**

> ⚠️ For authorized penetration testing and lab environments only. No warranty.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Files](#files)
- [Install](#install)
- [Run](#run)
- [config.yaml in a nutshell](#configyaml-in-a-nutshell)
- [How the agent reads the model's mind](#how-the-agent-reads-the-models-mind)
- [Interactive state machine](#interactive-state-machine)
- [Safety / Scope](#safety--scope)
- [Troubleshooting](#troubleshooting)
- [Extending](#extending)
- [Design notes](#design-notes)
- [License / Disclaimer](#license--disclaimer)

---

## Overview

An autonomous pentesting agent that runs an LLM (via Ollama) and executes every command it decides on a remote Kali box. You watch the model reason, pick commands, and react to output, turn by turn. Nothing about the target is hardcoded in the agent's logic: the model receives only the target IP and a mission, and discovers everything else by itself.

The agent:

- Streams the LLM's reasoning token by token.
- Types each model command into **one persistent bash PTY** on Kali.
- Detects interactive prompts (password, username, yes/no, `ftp>`, `smb: >`, `mysql>`, `msfconsole>`, `python>>>`, and dozens more).
- Auto-escapes stuck interactive programs so the shell never blocks.
- Filters repeated commands and nudges the model to change approach (without ever showing the rejected command as something to imitate).
- Detects foreground listeners (`nc -lvnp`, `mitmdump`, `http.server`) and auto-kills them with a hint to background or use tmux.
- Detects when the model is inside a remote shell and stops treating its commands as Kali-local.

Everything configurable lives in `config.yaml`. `main_agent.py` is config-driven.

---

## Architecture

```text
  MAIN (you)         BRAIN (Ollama)        CONTROL (Kali, PTY here)
  ──────────         ──────────────        ───────────────────────
       │                    │                         │
       │──ssh──────────────▶│                         │
       │                    │──ssh───────────────────▶│
       │                    │                         │
       │                    │                         ├──ssh──▶ TARGET
       │                    │                         │        (opt)
       │
       └─ollama tunnel──────┘
         (local port)
```

- **MAIN** — your workstation. Runs `main_agent.py`.
- **BRAIN** — Ollama server. The LLM lives here.
- **CONTROL** — Kali Linux. Holds the one persistent PTY shell where every model command executes.
- **TARGET** — the machine the model must compromise. Reachable from CONTROL. The model decides how to get in.

---

## Files

| File | Description |
| --- | --- |
| `config.yaml` | All configuration (IPs, credentials, model, prompts, patterns, timeouts, escape sequences, filters). |
| `main_agent.py` | The agent. Reads `config.yaml`, connects, loops. |
| `requirements.txt` | Python dependencies (`paramiko`, `requests`, `PyYAML`). |
| `README.txt` | This file. |

**Optional** (alternate to inline prompts in `config.yaml`):

| File | Description |
| --- | --- |
| `prompts/user.txt` | Mission prompt, as a file. |
| `prompts/system.txt` | System prompt, as a file. |

Use in `config.yaml`:

```yaml
prompts:
  user:   { file: prompts/user.txt }
  system: { file: prompts/system.txt }
```

---

## Install

1. Python 3.10+ with `pip`.
2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. On **BRAIN**, ensure Ollama is running with the chosen model:

   ```bash
   ollama pull qwen2.5-coder:7b
   curl -s http://localhost:11434/api/tags
   ```

4. On **CONTROL**, ensure SSH access from BRAIN works, and that `tmux` is installed (`apt install tmux`) for parallel workflows.

No changes are needed on **TARGET**.

---

## Run

```bash
python main_agent.py
```

Optional:

```bash
python main_agent.py -c /path/to/config.yaml
AGENT_CONFIG=/path/to/config.yaml python main_agent.py
```

---

## config.yaml in a nutshell

| Key | Description |
| --- | --- |
| `brain.host` / `brain.user` / `brain.password` | SSH to the Ollama host. |
| `control.host` / `control.user` / `control.password` | SSH to Kali (where the PTY lives). |
| `target.host` | Only the IP reaches the model. |
| `model.name` | Ollama model tag. |
| `model.stream` | `true` = token-by-token; `false` = block. |
| `model.max_iterations` | Loop limit. |
| `model.request_timeout` | Seconds per LLM request. |
| `markers.kali` | Kali prompt marker. |
| `markers.remote` | Remote prompt marker (optional). |
| `filters.duplicate_threshold` | Retries allowed before filtering. |
| `filters.slow_tools` | Tools that need patience (`nmap`, ...). |
| `filters.interactive_tools` | Tools that park at a prompt. |
| `filters.exit_cmds_regex` | Patterns that mean "exit". |
| `filters.sentinel_regex` | Patterns that mean "garbage command". |
| `filters.listener_patterns` | Foreground listeners to auto-kill. |
| `timeouts.*` | Idle / max time per read. |
| `prompt_patterns` | List of `(name, regex, ignore_case)`. Matches **both** known and unknown interactive prompts (heuristic fallback covers the rest). |
| `escape_sequences` | How to leave each interactive state. `\n` and `\x03` are real escapes. |
| `ssh_fail_markers` | Substrings that mean "ssh failed". |
| `heuristic.ansi_strip_regex` | ANSI codes to strip before matching. |
| `heuristic.prompt_terminals_regex` | Terminals that hint at a prompt. |
| `setup.kali_commands` | Commands run once when the PTY opens. |
| `prompts.user` / `prompts.system` | Mission and rules for the model. Use `__TARGET_IP__`, `__CONTROL_IP__`, `__PROMPT_MARK__`, `__REMOTE_MARK__` as placeholders (substituted at startup). |

---

## How the agent reads the model's mind

- The model receives the full history of: its own responses, the commands it emitted, and the output of those commands.
- It receives a strict format:

  ```text
  <cmd>one shell line</cmd>       to run something
  <done>summary</done>            to finish
  ```

- Nothing else is expected of it. The agent extracts the command, runs it, and returns the output as the next user turn.

This means the model literally sees what happened after each of its commands, sees errors, sees prompts, and adapts on the next turn.

---

## Interactive state machine

States the agent tracks (visible in each iteration header):

| State | Meaning |
| --- | --- |
| `None` | On Kali, ready for any command. |
| `__user__` | Waiting for a username. |
| `__password__` | Waiting for a password / passphrase. |
| `__yesno__` | Waiting for y/n. |
| `__input__` | Unknown prompt (heuristic fallback). |
| `ftp`, `sftp` | Inside an FTP/SFTP client. |
| `smbclient` | Inside `smbclient`. |
| `mysql` | Inside `mysql` / `psql` / `sqlite`. |
| `msfconsole` | Inside `msfconsole` / `meterpreter`. |
| `python`, `irb` | Inside a language REPL. |
| `redis` | Inside `redis-cli` or similar. |
| `r2` | Inside radare2. |
| `gdb` | Inside gdb. |
| `pager` | Inside `less` / `more` / `man` / `vi` (`--More--`, `(END)`). |
| `remote` | Inside a remote shell (`ssh` / `telnet` / `rlogin`). Any `ssh` command is **blocked** while in this state. |

**Auto-escape:** if the model emits a Kali-level command while in an interactive state, the agent sends the appropriate exit sequence (`quit`, `exit`, `^C`, `q`), verifies it is back on Kali, and only then runs the model's command. If the escape fails, the command is **not** run; the model gets a nudge to exit by itself.

---

## Safety / Scope

This tool is intended for **authorized penetration testing and lab environments only**. Running it against systems you do not own or have explicit written permission to test is illegal.

The agent does not hide its traffic, does not persist across reboots, and does not alter the configuration of the target unless the model explicitly issues commands that do so.

---

## Troubleshooting

### `Incompatible ssh peer (no acceptable host key)`

Target uses `ssh-rsa` (SHA-1). Add to the model's `ssh` command:

```bash
-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa
```

The system prompt mentions this.

### Shell hangs on `nc -lvnp 4444` or `mitmproxy`

Foreground listeners are auto-killed with a hint to background them or use tmux. If the model repeats the foreground pattern, the duplicate filter eventually forces it to switch approach.

### Model loops on the same command

The duplicate filter rejects the second (or third, per `filters.duplicate_threshold`) occurrence. The nudge tells the model that the command is a duplicate and to pick a different technique. The rejected command is **not** added to the model's history, so it cannot imitate itself.

### Model is stuck inside a prompt

Check the iteration header: `[state=...]`. If it says `__password__`, `__user__`, or `__input__`, the model needs to send a short token or `^C`. The nudge on the next filter already says so.

### Prompts render with literal `\n` instead of newlines

Run the repair pass in the repo history (the one that rewrites `config.yaml` with block scalars for prompts). Or open `config.yaml` and rewrite the prompts section by hand using `|` block style.

---

## Extending

### Add a new interactive prompt

1. Add to `config.yaml` → `prompt_patterns`:

   ```yaml
   - { name: mytool, regex: '^mytool>\s*$', ignore_case: true }
   ```

2. Add its exit to `config.yaml` → `escape_sequences`:

   ```yaml
   mytool: "quit\n"
   ```

Nothing in `main_agent.py` needs to change.

### Add a new tool to the "slow" list

```yaml
filters.slow_tools: [..., mytool]
```

### Add a new tool to the "interactive" list

```yaml
filters.interactive_tools: [..., mytool]
```

### Add a new listener pattern

```yaml
filters.listener_patterns: [ ..., '\bmytool\s+.*--listen' ]
```

---

## Design notes

- **Only one PTY.** This is intentional: the model has to reason about parallelism (background jobs, tmux) instead of being handed multiple channels. For multi-window workflows the model is instructed to use `tmux` inside the single PTY.
- **The model's history is never contaminated with filtered commands.** When the agent rejects a command, it adds **only** a nudge to the next turn; the rejected command is not stored. This breaks self-mimicry loops.
- **All timeouts are configurable** because "how long nmap takes" depends on the network, not on the agent.
- **Markers (`###PROMPT###`, `###REMOTE###`) exist** because detecting a bash prompt via `$` / `#` / `>` is unreliable when programs print similar strings. The model is told to `export PS1='###REMOTE###'` after logging into a remote shell so the agent can tell Kali and Target apart reliably.

---

## License / Disclaimer

For authorized testing and lab use only. No warranty.
