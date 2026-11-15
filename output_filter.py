"""
Output filter for HIVEPLUS: strips HTML/CSS/JS noise, nmap fingerprints,
ANSI escapes, and caps per-output size before passing to the LLM.

Configuration lives in config.yaml → output_filtering.

Usage:
    from output_filter import OutputFilter
    filt = OutputFilter(cfg["output_filtering"], ansi_re)
    filtered = filt(raw_shell_output)
"""
import re


class OutputFilter:
    def __init__(self, cfg, ansi_re=None):
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled", False))
        self.strip_ansi = bool(self.cfg.get("strip_ansi", True))
        self.max_bytes = int(self.cfg.get("max_bytes", 8000))
        self.max_lines = int(self.cfg.get("max_lines", 300))
        self.head_ratio = float(self.cfg.get("head_ratio", 0.7))
        self.ansi_re = ansi_re

        h = self.cfg.get("html", {}) or {}
        self.html_enabled = bool(h.get("enabled", True))
        self.html_strip_style = bool(h.get("strip_style", True))
        self.html_strip_script = bool(h.get("strip_script", True))
        self.html_strip_comments = bool(h.get("strip_comments", True))
        self.html_collapse = bool(h.get("collapse_whitespace", True))
        self.html_extract_skeleton = bool(h.get("extract_skeleton", True))

        n = self.cfg.get("nmap", {}) or {}
        self.nmap_enabled = bool(n.get("enabled", True))
        self.nmap_strip_fp = bool(n.get("strip_fingerprints", True))

        self._style_re = re.compile(r"<style\b[^>]*>.*?</style>", re.DOTALL | re.I)
        self._script_re = re.compile(r"<script\b[^>]*>.*?</script>", re.DOTALL | re.I)
        self._comment_re = re.compile(r"<!--.*?-->", re.DOTALL)
        self._title_re = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.DOTALL)
        self._form_re = re.compile(r"<form\b([^>]*)>", re.I)
        self._input_re = re.compile(r"<input\b([^>]*)>", re.I)
        self._link_re = re.compile(r"<a\b[^>]*href=[\"']([^\"']+)[\"']", re.I)
        self._fetch_re = re.compile(
            r"""(?:fetch|\.post|\.get|ajax)\s*\(\s*['"]([^'"]+)['"]""", re.I)
        self._attr_re = re.compile(r"(\w+)\s*=\s*[\"']([^\"']*)[\"']")
        # JS / WebSocket / API signals
        self._script_src_re = re.compile(
            r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)
        self._ws_emit_re   = re.compile(
            r"\b(?:socket|io|sock)\.emit\s*\(\s*[\"']([^\"']+)[\"']", re.I)
        self._ws_on_re     = re.compile(
            r"\b(?:socket|io|sock)\.on\s*\(\s*[\"']([^\"']+)[\"']", re.I)
        self._ws_client_re = re.compile(
            r"(?:io\s*\(|new\s+WebSocket\s*\(|new\s+SockJS\s*\()", re.I)
        self._xhr_re       = re.compile(
            r"\b(?:XMLHttpRequest|axios\.(?:get|post|put|delete)|"
            r"\$\.(?:ajax|get|post))", re.I)
        self._url_in_js_re = re.compile(
            r"""[\"'](/[a-zA-Z0-9_./-]{2,})[\"']""")

    # ---------------- detection ----------------
    def _looks_like_html(self, text):
        head = text[:600].lower()
        return ("<!doctype html" in head or "<html" in head
                or "<body" in head or "<div" in head)

    def _looks_like_nmap(self, text):
        head = text[:800]
        return ("Nmap scan report" in head
                or "Starting Nmap" in head
                or "SF-Port-" in text)

    # ---------------- html ----------------
    def _extract_attrs(self, s):
        return dict(self._attr_re.findall(s or ""))

    def _extract_skeleton(self, html):
        parts = []
        m = self._title_re.search(html)
        if m:
            parts.append(f"title: {m.group(1).strip()}")
        for m in self._form_re.finditer(html):
            a = self._extract_attrs(m.group(1))
            parts.append(f"form: action={a.get('action','?')} "
                         f"method={a.get('method','get').upper()}")
        for m in self._input_re.finditer(html):
            a = self._extract_attrs(m.group(1))
            parts.append(f"input: name={a.get('name','?')} "
                         f"type={a.get('type','text')}")
        for link in sorted({m.group(1) for m in self._link_re.finditer(html)}):
            parts.append(f"link: {link}")
        for ep in sorted({m.group(1) for m in self._fetch_re.finditer(html)}):
            parts.append(f"js_endpoint: {ep}")
        # --- JS / WebSocket / API signals (NEW) ---
        for s in sorted({m.group(1) for m in self._script_src_re.finditer(html)}):
            parts.append(f"script_src: {s}")
        if self._ws_client_re.search(html):
            parts.append("websocket: detected (socket.io or WebSocket)")
        for ev in sorted({m.group(1) for m in self._ws_emit_re.finditer(html)}):
            parts.append(f"ws_emit: {ev}")
        for ev in sorted({m.group(1) for m in self._ws_on_re.finditer(html)}):
            parts.append(f"ws_listen: {ev}")
        if self._xhr_re.search(html):
            parts.append("xhr: detected (AJAX/XHR)")
        js_urls = set()
        for m in self._url_in_js_re.finditer(html):
            u = m.group(1)
            if not u.startswith("//") and "." not in u.split("/")[-1][:4]:
                js_urls.add(u)
        for u in sorted(js_urls)[:10]:
            parts.append(f"js_url: {u}")
        # --- HTML comments (often contain secrets / hints) ---
        comments = []
        for m in self._comment_re.finditer(html):
            c = m.group(0)
            c = c.replace("<!--", "").replace("-->", "").strip()
            c = " ".join(c.split())
            if c and len(c) < 400:
                comments.append(c)
        for c in comments[:10]:
            parts.append(f"comment: {c}")
        return "\n".join(parts)

    def _strip_html(self, text):
        if self.html_strip_style:
            text = self._style_re.sub("", text)
        # IMPORTANT: do NOT strip inline <script> content. In SPAs and
        # WebSocket apps the JS *is* the application. We only replace
        # external <script src=...> tags with a placeholder, and preserve
        # inline scripts verbatim. The skeleton above already surfaces
        # the important signals (endpoints, events).
        if self.html_strip_script:
            def _replace_script(m):
                tag = m.group(0)
                low = tag.lower()
                # external: keep a one-line marker
                if 'src=' in low:
                    src_m = self._script_src_re.search(tag)
                    url = src_m.group(1) if src_m else "?"
                    return f"<script src=\"{url}\"></script>  <!-- external -->"
                # inline: keep the content, just trim whitespace
                inner = re.sub(r"^<script\b[^>]*>", "", tag, flags=re.I)
                inner = re.sub(r"</script>\s*$", "", inner, flags=re.I)
                # collapse runs of blank lines inside JS
                inner = re.sub(r"\n\s*\n+", "\n", inner)
                return "<script>\n" + inner.strip() + "\n</script>"
            text = self._script_re.sub(_replace_script, text)
        # Comments are PRESERVED by default in pentesting context.
        # Only strip if explicitly requested (legacy "aggressive" mode).
        if self.html_strip_comments and self.cfg.get("aggressive_comments_strip", False):
            text = self._comment_re.sub("", text)
        if self.html_collapse:
            text = re.sub(r"[ \t]+", " ", text)
            text = re.sub(r"\n\s*\n+", "\n", text)
        return text.strip()

    # ---------------- nmap ----------------
    def _strip_nmap_fp(self, text):
        return "\n".join(
            line for line in text.split("\n")
            if not line.startswith("SF-") and not line.startswith("SF:")
        )

    def _extract_nmap_summary(self, text):
        """Build a compact summary: open ports + versions + notable headers."""
        summary = []
        target = None
        m = re.search(r"Nmap scan report for\s+(\S+)", text)
        if m:
            target = m.group(1)
        open_ports = []
        current = None
        for line in text.split("\n"):
            # PORT     STATE SERVICE VERSION
            m = re.match(r"^(\d+/tcp|\d+/udp)\s+(open|open\|filtered|filtered)\s+(\S+)\s*(.*)$", line)
            if m:
                current = {"port": m.group(1), "state": m.group(2),
                           "service": m.group(3), "version": m.group(4).strip(),
                           "extras": []}
                open_ports.append(current)
                continue
            # sub-lines like |_http-title: ..., | http-cors: ...
            if current is not None and line.startswith("|"):
                stripped = line.lstrip("|_ ").strip()
                if not stripped or ":" not in stripped:
                    continue
                k, v = stripped.split(":", 1)
                k, v = k.strip(), v.strip()
                # keep only meaningful keys, drop fingerprint noise
                if k in ("fingerprint-strings", "rpcinfo",
                         "GetRequest", "HTTPOptions", "RTSPRequest",
                         "Help", "Socks4", "Socks5", "beast2", "vp3",
                         "Kerberos", "SMBProgNeg"):
                    continue
                # Drop only raw fingerprint noise (SFATAL, hex dumps, etc.),
                # keep EVERYTHING else — NSE scripts are the pentester's gold.
                if k in ("SFATAL", "VFATAL", "C0A000", "unsupported",
                         "Fpostmaster.c", "RProcessStartupPacket",
                         "fingerprint-strings", "GetRequest", "HTTPOptions",
                         "RTSPRequest", "Help", "Socks4", "Socks5",
                         "beast2", "vp3", "Kerberos", "SMBProgNeg",
                         "rpcinfo"):
                    continue
                if k in ("M", "F", "L", "R") and len(v) < 40:
                    # SMTP/DB raw protocol fragments
                    continue
                # Keep EVERY other NSE key: ftp-anon, smtp-commands,
                # ssl-heartbleed, smb-vuln-ms17-010, http-shellshock,
                # rdp-vuln-ms12-020, vulners, distcc-cve*, ms-sql-info, ...
                current["extras"].append(f"{k}={v}")
        if target:
            summary.append(f"target: {target}")
        summary.append(f"open_ports: {len(open_ports)}")
        for p in open_ports:
            line = f"  {p['port']} {p['service']}"
            if p["version"]:
                line += f" {p['version']}"
            if p["extras"]:
                line += " | " + "; ".join(p["extras"][:3])
            summary.append(line)
        # Interesting hints the model should chase
        hints = []
        if "Juice Shop" in text or "juice" in text.lower():
            hints.append("Juice Shop detected (deliberately vulnerable web app - try XSS/SQLi)")
        if "Werkzeug" in text or "gunicorn" in text:
            hints.append("Python web app (check Flask routes, debug mode, SSTI, /admin)")
        if "CouchDB" in text:
            hints.append("CouchDB (check /_all_dbs, /_utils, auth bypass)")
        if "Chat IA" in text:
            hints.append("chat UI detected (test message input for XSS, SSTI, prompt injection)")
        if "postgresql" in text.lower():
            hints.append("PostgreSQL (try default creds, then \\l to list DBs)")
        if hints:
            summary.append("hints:")
            for h in hints:
                summary.append(f"  - {h}")
        return "\n".join(summary)

    # ---------------- caps ----------------
    def _strip_echo(self, text):
        """Remove PTY echo artifacts, including when the second copy is
        shorter than the first (PTY redraw drops a segment like the URL)."""
        # Normalize CR/LF and strip per-line trailing whitespace
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = "\n".join(ln.rstrip() for ln in text.split("\n"))
        lines = text.split("\n")

        # Drop two identical leading lines
        if len(lines) >= 2:
            a, b = lines[0].strip(), lines[1].strip()
            if a and b and (a == b or b.startswith(a) or a.startswith(b)):
                lines = lines[2:]

        # Roots that indicate the start of a shell command
        ROOTS = ("curl", "wget", "nmap", "nikto", "gobuster", "hydra",
                 "sqlmap", "cat", "ls", "grep", "sed", "awk", "find",
                 "python3", "python", "nc", "ncat", "telnet", "ssh",
                 "scp", "sleep", "echo", "export", "cd", "mkdir", "rm",
                 "mv", "cp", "chmod", "chown", "pwd", "id", "whoami",
                 "hostname", "ps", "kill", "pkill", "msfconsole",
                 "msf6", "mysql", "ftp", "analyzer.py", "analyzer")

        fixed = []
        for line in lines:
            s = line.rstrip()
            if not s:
                fixed.append(s)
                continue
            n = len(s)
            if n < 40:
                fixed.append(s)
                continue

            # Find the earliest root that appears at least twice
            best_cut = 0
            for root in ROOTS:
                pat = r'(?<![\w.-])' + re.escape(root) + r'(?![\w.-])'
                matches = [mm.start() for mm in re.finditer(pat, s)]
                if len(matches) < 2:
                    continue
                second_pos = matches[1]
                # Do NOT cut if the char before is a shell operator
                # (&&, ||, ;, |) — that means a legitimate compound command
                before = s[:second_pos].rstrip()
                if before and before[-1] in '&|;':
                    continue
                # Cut here (prefer the earliest such position)
                if best_cut == 0 or second_pos < best_cut:
                    best_cut = second_pos

            # Exact half-boundary glue (CMDCMD) for short commands
            if not best_cut and n >= 10 and n % 2 == 0 and n < 100:
                half = n // 2
                if s[:half] == s[half:]:
                    best_cut = half

            if best_cut > 0:
                s = s[:best_cut].rstrip()
            fixed.append(s)
        return "\n".join(fixed)

    def _strip_padding(self, text):
        """Remove PTY padding: spaces at end of every line, and lines that
        contain only whitespace (they add bytes but no info)."""
        out = []
        for line in text.split("\n"):
            # strip trailing spaces/tabs (PTY pads to terminal width)
            stripped = line.rstrip(" \t")
            # keep empty lines? only one blank line is useful; drop the rest
            out.append(stripped)
        # collapse 3+ consecutive blank lines into one
        result = []
        blanks = 0
        for line in out:
            if line == "":
                blanks += 1
                if blanks <= 1:
                    result.append(line)
            else:
                blanks = 0
                result.append(line)
        return "\n".join(result)

    def _cap(self, text):
        self._cap_truncated = False
        b = text.encode()
        limit = self.max_bytes
        # Optional HTML-specific limit. If not configured, use max_bytes.
        # (Older configs had max_html_bytes: 16000 here — that made HTML
        # bypass max_bytes entirely, which is confusing. We honor it only
        # if explicitly set in config.)
        if self._looks_like_html(text):
            html_override = self.cfg.get("max_html_bytes")
            if html_override is not None:
                limit = max(self.max_bytes, int(html_override))
        if len(b) > limit:
            head_n = int(limit * self.head_ratio)
            tail_n = limit - head_n - 80
            head = b[:head_n].decode(errors="replace")
            tail = b[-tail_n:].decode(errors="replace")
            removed = len(b) - head_n - tail_n
            text = (head
                    + f"\n\n[... {removed} bytes truncated — use "
                      f"`analyzer if you need the full "
                      f"content ...]\n\n"
                    + tail)
            self._cap_truncated = True
        lines = text.split("\n")
        if len(lines) > self.max_lines:
            head_n = int(self.max_lines * self.head_ratio)
            tail_n = self.max_lines - head_n - 3
            text = ("\n".join(lines[:head_n])
                    + f"\n\n[... {len(lines) - head_n - tail_n} lines truncated ...]\n\n"
                    + "\n".join(lines[-tail_n:]))
            self._cap_truncated = True
        return text

    def __call__(self, raw):
        if not raw or not self.enabled:
            return raw

        self._cap_truncated = False
        original_len = len(raw)

        if self.strip_ansi and self.ansi_re is not None:
            raw = self.ansi_re.sub("", raw)

        # Small outputs (< 5 KB) pass through untouched
        if len(raw) < 5000:
            return raw

        raw = self._strip_echo(raw)

        if self.html_enabled and self._looks_like_html(raw):
            skel = (self._extract_skeleton(raw)
                    if self.html_extract_skeleton else "")
            raw = self._strip_html(raw)
            if skel:
                raw = (f"[HTML SKELETON — auto-extracted]\n{skel}\n\n"
                       f"[CLEANED HTML]\n{raw}")

        if self.nmap_enabled and self._looks_like_nmap(raw):
            summary = self._extract_nmap_summary(raw)
            keep_full = self.cfg.get("nmap_keep_full_output", False)
            summary_lines = [ln for ln in (summary or "").split("\n")
                             if ln.strip()
                             and not ln.strip().startswith("target:")
                             and not ln.strip().startswith("open_ports:")]
            has_real_content = len(summary_lines) > 0
            if summary and has_real_content and not keep_full:
                raw = (f"[NMAP SUMMARY - auto-extracted]\n"
                       f"{summary}\n"
                       f"[full nmap output omitted to save context]")

        raw = self._strip_padding(raw)
        raw = self._cap(raw)
        # No external banner: the marker inside _cap already tells the model
        # what happened and how to recover (analyzer.py -q <file>).
        return raw
