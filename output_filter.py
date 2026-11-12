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
        return "\n".join(parts)

    def _strip_html(self, text):
        if self.html_strip_style:
            text = self._style_re.sub("", text)
        if self.html_strip_script:
            text = self._script_re.sub("", text)
        if self.html_strip_comments:
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
                if k in ("SFATAL", "VFATAL", "M", "F", "L", "R",
                         "C0A000", "unsupported"):
                    continue
                # keep http-*, ssl-*, ssh-*, smb-*, mysql-*, dns-*, etc.
                if not any(k.startswith(p) for p in (
                        "http-", "http_", "ssl-", "ssh-", "smb-", "smbv2-",
                        "mysql-", "dns-", "rpc", "vnc-", "irc-", "ajp-",
                        "clock-skew", "nbstat", "smb-os", "smb-security",
                        "ssl-cert", "ssl-date")):
                    # still keep a few short keys
                    if k not in ("http-cors", "vulners", "broadcast"):
                        continue
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
        """Remove the duplicated command echo the PTY sometimes prints."""
        # PTY echoes use \r\n sometimes, \r others; normalize to \n
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")

        # Case 1: two identical/near-identical leading lines
        if len(lines) >= 2:
            a, b = lines[0].strip(), lines[1].strip()
            if a and b and (a == b or b.startswith(a) or a.startswith(b)):
                lines = lines[2:]

        # Case 2: concatenated echo "CMDCMD" (no separator at all)
        if lines and lines[0]:
            line0 = lines[0]
            n = len(line0)
            if n >= 8 and n % 2 == 0:
                half = n // 2
                if line0[:half] == line0[half:]:
                    lines[0] = line0[:half]

        # Case 3: "CMD + first-word-of-CMD" (partial echo)
        if lines and lines[0]:
            line0 = lines[0]
            first_space = line0.find(' ')
            if first_space > 0:
                first_word = line0[:first_space]
                # if line ends with first_word again, truncate
                if line0.endswith(first_word) and len(line0) > 2*first_space:
                    lines[0] = line0[:-len(first_word)]

        return "\n".join(lines)

    def _cap(self, text):
        b = text.encode()
        if len(b) > self.max_bytes:
            head_n = int(self.max_bytes * self.head_ratio)
            tail_n = self.max_bytes - head_n - 80
            head = b[:head_n].decode(errors="replace")
            tail = b[-tail_n:].decode(errors="replace")
            removed = len(b) - head_n - tail_n
            text = head + f"\n\n[... {removed} bytes truncated ...]\n\n" + tail
        lines = text.split("\n")
        if len(lines) > self.max_lines:
            head_n = int(self.max_lines * self.head_ratio)
            tail_n = self.max_lines - head_n - 3
            text = ("\n".join(lines[:head_n])
                    + f"\n\n[... {len(lines) - head_n - tail_n} lines truncated ...]\n\n"
                    + "\n".join(lines[-tail_n:]))
        return text

    # ---------------- public ----------------
    def __call__(self, raw):
        if not raw or not self.enabled:
            return raw
        original_len = len(raw)

        if self.strip_ansi and self.ansi_re is not None:
            raw = self.ansi_re.sub("", raw)

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
            if summary:
                # replace the entire nmap dump with the compact summary.
                # the model has the port list, versions, and hints; the
                # full output is noise. If it needs more, it can re-run a
                # targeted scan with a specific script.
                raw = (f"[NMAP SUMMARY - auto-extracted]\n"
                       f"{summary}\n"
                       f"[full nmap output omitted to save context]")

        raw = self._cap(raw)

        if len(raw) < original_len:
            raw += f"\n[filtered: {original_len} -> {len(raw)} bytes]"
        return raw
