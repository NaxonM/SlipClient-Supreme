"""
core.py  —  slipstream-tunnel engine
All state, I/O, processes, proxies, watchdog.
No print() calls except progress feedback from dnscan passthrough.
Import this from ui.py; never run directly.
"""

import base64, ipaddress, json, os, platform, random, re, signal, socket, struct
import subprocess, sys, threading, time, atexit
if platform.system() == "Windows":
    try:
        import winreg as _winreg
    except ImportError:
        _winreg = None
else:
    _winreg = None
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from datetime import datetime
from pathlib import Path

from core_dns import burst_dns_success, scan_resolver_dns_tunnel
from core_pool import merge_new_with_existing, surviving_resolvers

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent.resolve()
BIN_DIR      = BASE_DIR / "bin"
DNSCAN_DATA  = BIN_DIR / "dnscan" / "data"
APP_RES_DIR  = BASE_DIR / "resources"
APP_DNS_DIR  = APP_RES_DIR / "dns"
APP_GEO_DIR  = APP_RES_DIR / "geo"

def _ensure_executable(path: Path):
    """On macOS/Linux, binaries extracted from .tar.gz need chmod +x."""
    if platform.system() != "Windows" and path.exists():
        import stat
        current = path.stat().st_mode
        path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

def _detect_arch() -> str:
    """Returns one of: windows-amd64, darwin-amd64, darwin-arm64, linux-amd64, linux-arm64"""
    import platform as _pl
    sys  = _pl.system().lower()
    mach = _pl.machine().lower()
    if sys == "windows":
        return "windows-amd64"
    arch = "arm64" if mach in ("arm64", "aarch64") else "amd64"
    return f"{sys}-{arch}"

_ARCH = _detect_arch()
_IS_WIN = platform.system() == "Windows"

def _dnscan_exe() -> Path:
    if _IS_WIN:
        return BIN_DIR / "dnscan" / "dnscan.exe"
    # On macOS/Linux the binary is just named "dnscan" (extracted from .tar.gz)
    return BIN_DIR / "dnscan" / "dnscan"

def _client_exe() -> Path:
    if _IS_WIN:
        return BIN_DIR / "slipstream-client" / "slipstream-client-windows-amd64.exe"
    # e.g. slipstream-client-darwin-arm64  or  slipstream-client-darwin-amd64
    return BIN_DIR / "slipstream-client" / f"slipstream-client-{_ARCH}"

DNSCAN_EXE = _dnscan_exe()
CLIENT_EXE = _client_exe()
_CLIENT_HELP_CACHE: set[str] | None = None

def _client_supported_flags() -> set[str]:
    """Best-effort detection of supported CLI flags for the current client binary."""
    global _CLIENT_HELP_CACHE
    if _CLIENT_HELP_CACHE is not None:
        return _CLIENT_HELP_CACHE
    flags: set[str] = set()
    if not CLIENT_EXE.exists():
        _CLIENT_HELP_CACHE = flags
        return flags
    try:
        _ensure_executable(CLIENT_EXE)
        out = subprocess.check_output([str(CLIENT_EXE), "--help"], stderr=subprocess.STDOUT, text=True, timeout=4)
        flags = set(re.findall(r"--[a-z0-9-]+", out.lower()))
    except Exception:
        flags = set()
    _CLIENT_HELP_CACHE = flags
    return flags




def diagnose_client_binary() -> tuple[bool, str]:
    """Return (ok, detail). Detect common runtime dependency failures early."""
    if not CLIENT_EXE.exists():
        return False, f"missing client binary: {CLIENT_EXE}"
    try:
        _ensure_executable(CLIENT_EXE)
        out = subprocess.check_output([str(CLIENT_EXE), "--help"], stderr=subprocess.STDOUT, text=True, timeout=5)
        return True, out.splitlines()[0] if out else "ok"
    except subprocess.CalledProcessError as e:
        txt = (e.output or "").lower()
        if "libcrypto-3" in txt or "libssl-3" in txt:
            return False, ("client runtime dependency missing (OpenSSL 3 DLL). "
                           "Windows builds may require libcrypto-3-x64.dll/libssl-3-x64.dll beside the client exe.")
        return False, (e.output or str(e)).strip()
    except Exception as e:
        return False, str(e)

def build_client_cmd(cfg: dict, resolvers: list[str], listen_port: int) -> list[str]:
    """Build slipstream-client command with feature flags only when supported."""
    cmd = [str(CLIENT_EXE)]
    for ip in resolvers:
        cmd += ["--resolver", f"{ip}:53"]
    cmd += [
        "--domain", cfg["domain"],
        "--tcp-listen-port", str(listen_port),
        "--keep-alive-interval", str(cfg.get("keep_alive_ms", 400)),
    ]
    if cfg.get("cert_path"):
        cmd += ["--cert", cfg["cert_path"]]

    sup = _client_supported_flags()

    if cfg.get("authoritative_mode"):
        if "--authoritative" in sup:
            cmd += ["--authoritative"]
        elif "--authoritative-mode" in sup:
            cmd += ["--authoritative-mode"]

    return cmd


def _download_file(url: str, dst: Path, timeout: int = 20) -> bool:
    try:
        import urllib.request
        dst.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=timeout) as r:
            dst.write_bytes(r.read())
        return True
    except Exception:
        return False


def _install_dnscan_from_tar(tgz: Path) -> bool:
    """Extract dnscan tarball and normalize expected bin/data layout."""
    import tarfile, tempfile, shutil
    try:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            with tarfile.open(tgz, "r:gz") as tf:
                tf.extractall(tdp)

            # Find executable candidate
            exe_candidates = [
                p for p in tdp.rglob("*")
                if p.is_file() and p.name in ("dnscan", "dnscan-linux-amd64", "dnscan-linux-arm64", "dnscan-macos-amd64", "dnscan-macos-arm64")
            ]
            if not exe_candidates:
                return False
            exe = exe_candidates[0]

            dest_exe = DNSCAN_EXE
            dest_exe.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(exe, dest_exe)
            _ensure_executable(dest_exe)

            # Copy data dir if present
            data_dirs = [d for d in tdp.rglob("data") if d.is_dir()]
            if data_dirs:
                dst_data = BIN_DIR / "dnscan" / "data"
                if dst_data.exists():
                    shutil.rmtree(dst_data)
                shutil.copytree(data_dirs[0], dst_data)
        return True
    except Exception:
        return False


def bootstrap_binaries() -> list[str]:
    """Best-effort download/build of missing binaries. Returns status lines."""
    msgs = []
    osys = platform.system().lower()

    # slipstream-client from Fox-Fig release naming used in docs
    if not CLIENT_EXE.exists():
        c_url = f"https://github.com/Fox-Fig/slipstream-rust-plus-deploy/releases/latest/download/{CLIENT_EXE.name}"
        if _download_file(c_url, CLIENT_EXE):
            _ensure_executable(CLIENT_EXE)
            msgs.append(f"downloaded client: {CLIENT_EXE.name}")
        else:
            msgs.append(f"could not download client: {CLIENT_EXE.name}")

    # dnscan: no official mac release in upstream docs; build fallback on macOS
    if not DNSCAN_EXE.exists():
        dn_name = {
            "windows": "dnscan.exe",
            "linux": "dnscan-linux-amd64.tar.gz" if "amd64" in _ARCH else "dnscan-linux-arm64.tar.gz",
            "darwin": "dnscan-macos-amd64.tar.gz" if "amd64" in _ARCH else "dnscan-macos-arm64.tar.gz",
        }.get(osys, "")

        if osys in ("windows", "linux"):
            if osys == "windows":
                u = "https://github.com/nightowlnerd/dnscan/releases/latest/download/dnscan-windows-amd64.exe"
                if _download_file(u, DNSCAN_EXE):
                    msgs.append("downloaded dnscan exe")
                else:
                    msgs.append("could not download dnscan exe")
            else:
                import tempfile
                tar_url = f"https://github.com/nightowlnerd/dnscan/releases/latest/download/{dn_name}"
                with tempfile.TemporaryDirectory() as td:
                    tgz = Path(td) / "dnscan.tgz"
                    if _download_file(tar_url, tgz):
                        if _install_dnscan_from_tar(tgz):
                            msgs.append("downloaded dnscan tarball")
                        else:
                            msgs.append("dnscan tar extract failed")
                    else:
                        msgs.append("could not download dnscan tarball")

        elif osys == "darwin":
            # build from source if Go exists
            try:
                go_ok = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=5)
                if go_ok.returncode == 0:
                    import tempfile
                    with tempfile.TemporaryDirectory() as td:
                        subprocess.run(["git", "clone", "--depth", "1", "https://github.com/nightowlnerd/dnscan.git", td], check=True, timeout=40)
                        out = BIN_DIR / "dnscan" / "dnscan"
                        subprocess.run(["go", "build", "-o", str(out), "."], cwd=td, check=True, timeout=120)
                        _ensure_executable(out)
                        src_data = Path(td) / "data"
                        if src_data.exists():
                            import shutil
                            dst_data = BIN_DIR / "dnscan" / "data"
                            if dst_data.exists():
                                shutil.rmtree(dst_data)
                            shutil.copytree(src_data, dst_data)
                        msgs.append("built dnscan from source for macOS")
                else:
                    msgs.append("dnscan missing on macOS and Go toolchain not available")
            except Exception:
                msgs.append("failed to build dnscan from source on macOS")

    return msgs

STATE_DIR    = BASE_DIR / "state"
PROFILES_DIR = STATE_DIR / "profiles"
ACTIVE_FILE  = STATE_DIR / "active_profile"
PID_FILE     = STATE_DIR / "slipstream.pid"
_PROXY_GUARD_FILE = STATE_DIR / "system_proxy_backup.json"

STATE_DIR.mkdir(parents=True, exist_ok=True)
PROFILES_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# PROFILE SCHEMA
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_CFG = {
    "domain":                   "t.example.com",
    "listen_port":              1080,      # base port for slipstream-client(s)
    "http_proxy_port":          8080,      # our HTTP→SOCKS bridge
    "cert_path":                "",
    "keep_alive_ms":            400,
    "authoritative_mode":       False,
    # Python-side socket tuning (applies regardless of client binary flags)
    "low_latency_mode":         True,
    # SOCKS5 auth (tunnel server side)
    "socks_auth":               False,
    "socks_user":               "",
    "socks_pass":               "",
    # System proxy
    "system_proxy":             False,
    "enable_http_proxy":        True,
    "domestic_bypass_enabled":  True,
    # Multi-instance
    "multi_instance":           1,
    # Scan
    "country":                  "ir",
    "scan_mode":                "fast",
    "scan_workers":             1200,
    "scan_timeout":             "1s",
    "scan_threshold":           50,
    "scan_burst_count":         6,
    "scan_burst_timeout":       0.8,
    "scan_burst_workers":       64,
    "scan_burst_min_pass":      0.35,
    "scan_target_count":        7000,
    "monitor_refresh_sec":      2,
    # Watchdog
    "watchdog_enabled":         False,
    "watchdog_check_interval":  60,
    "watchdog_scan_interval":   21600,
    "watchdog_fail_threshold":  3,
    "watchdog_probe_url":       "http://1.1.1.1",
    "watchdog_probe_timeout":   12,
    "watchdog_probe_mode":      "auto",   # auto/http/socks
    "watchdog_prune_dead":      3,     # remove resolver after N consecutive DEAD checks
    # Pool management  (#4, #5)
    "resolver_max_age_days":    7,     # flag resolvers older than this for replacement
    "resolver_max_pool":        12,    # cap pool at this many IPs
    # Adaptive keep-alive  (#6)
    "keep_alive_adaptive":      True,
    "keep_alive_min_ms":        200,
    "keep_alive_max_ms":        2000,
    # Verification parallelism  (#3)
    "verify_workers":           4,
    "verify_timeout":           10,
    "verify_sample_count":      20,
    "verify_all_candidates":    True,
    "verify_strict_required":   True,
    "verify_relaxed_retry":     True,
    "verify_relaxed_count":     6,
    "verify_probe_host":        "example.com",
    "verify_probe_port":        80,
    "dns_precheck_mode":        "quick",
    # Multi-instance failover depth (extra resolvers after the primary)
    "instance_failover_count":  1,
}


def _tune_tcp_socket(sock: socket.socket, cfg: dict):
    """Best-effort Python-side latency/stability tuning for local proxy sockets."""
    if not cfg.get("low_latency_mode", True):
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# PROFILE I/O
# ─────────────────────────────────────────────────────────────────────────────

def pdir(name: str) -> Path:
    return PROFILES_DIR / name

def list_profiles() -> list[str]:
    return sorted(p.name for p in PROFILES_DIR.iterdir() if p.is_dir())

def profile_exists(name: str) -> bool:
    return (PROFILES_DIR / name).is_dir()

def load_cfg(name: str) -> dict:
    f = pdir(name) / "config.json"
    if f.exists():
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        for k, v in DEFAULT_CFG.items():
            data.setdefault(k, v)
        return data
    return deepcopy(DEFAULT_CFG)

def save_cfg(name: str, cfg: dict):
    pdir(name).mkdir(parents=True, exist_ok=True)
    with open(pdir(name) / "config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def create_profile(name: str, base: dict = None) -> dict:
    cfg = deepcopy(base or DEFAULT_CFG)
    save_cfg(name, cfg)
    return cfg

def delete_profile(name: str):
    import shutil
    shutil.rmtree(pdir(name), ignore_errors=True)

def get_active() -> str:
    if ACTIVE_FILE.exists():
        n = ACTIVE_FILE.read_text(encoding="utf-8").strip()
        if profile_exists(n):
            return n
    ps = list_profiles()
    if ps:
        set_active(ps[0])
        return ps[0]
    create_profile("default")
    set_active("default")
    return "default"

def set_active(name: str):
    ACTIVE_FILE.write_text(name, encoding="utf-8")

def srvfile(name: str) -> Path:
    return pdir(name) / "servers.txt"

def load_servers(name: str) -> list[str]:
    f = srvfile(name)
    if f.exists():
        return [l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
    return []

def save_servers(name: str, servers: list[str]):
    srvfile(name).write_text(
        "\n".join(servers) + ("\n" if servers else ""),
        encoding="utf-8"
    )

def logfile(name: str, kind: str) -> Path:
    return pdir(name) / f"{kind}.log"

# ── #13: Log rotation at 500 KB ──────────────────────────────────────────────
_LOG_MAX_BYTES = 500 * 1024

def flog(name: str, kind: str, msg: str):
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lf  = logfile(name, kind)
    try:
        if lf.exists() and lf.stat().st_size > _LOG_MAX_BYTES:
            bak = lf.with_suffix(".log.1")
            if bak.exists():
                bak.unlink()
            lf.rename(bak)
    except Exception:
        pass
    with open(lf, "a", encoding="utf-8") as f:
        f.write(f"{ts}  {msg}\n")

def is_first_run() -> bool:
    """True if no real profile has been configured yet."""
    ps = list_profiles()
    if not ps:
        return True
    if ps == ["default"] and not load_servers("default"):
        cfg = load_cfg("default")
        if cfg["domain"] == DEFAULT_CFG["domain"]:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# #1  RESOLVER SCORE STORE
# ─────────────────────────────────────────────────────────────────────────────
# Per-profile JSON:  { "ip": { "ewma_ms": float, "qps_rate": float,
#                              "found_at": iso_str, "verified_at": iso_str|null,
#                              "consecutive_dead": int, "hijacked": bool } }
#
# Composite score (higher = better):
#   score(ip) = qps_rate × (1000 / max(ewma_ms, 1))
#
# ewma_ms  is updated via: new = alpha*sample + (1-alpha)*old  (alpha=0.25)
# qps_rate is updated via: new = alpha*sample + (1-alpha)*old  (alpha=0.3)
# ─────────────────────────────────────────────────────────────────────────────

_EWMA_ALPHA_LAT = 0.25
_EWMA_ALPHA_QPS = 0.30
_SCORE_FILE     = "resolver_scores.json"

def _scorefile(profile_name: str) -> Path:
    return pdir(profile_name) / _SCORE_FILE

def load_scores(profile_name: str) -> dict:
    f = _scorefile(profile_name)
    if f.exists():
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_scores(profile_name: str, scores: dict):
    _scorefile(profile_name).write_text(
        json.dumps(scores, indent=2), encoding="utf-8")

def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _default_score_entry() -> dict:
    return {
        "ewma_ms":         500.0,
        "qps_rate":        0.5,
        "found_at":        _now_iso(),
        "verified_at":     None,
        "consecutive_dead": 0,
        "hijacked":        False,
    }

def score_of(entry: dict) -> float:
    """Composite score: higher is better."""
    if entry.get("hijacked"):
        return 0.0
    return entry["qps_rate"] * (1000.0 / max(entry["ewma_ms"], 1.0))

def update_latency(profile_name: str, ip: str, ms: int):
    """Update EWMA latency for one resolver. Creates entry if missing."""
    scores = load_scores(profile_name)
    e = scores.setdefault(ip, _default_score_entry())
    if ms >= 9999:
        e["consecutive_dead"] = e.get("consecutive_dead", 0) + 1
    else:
        e["consecutive_dead"] = 0
        e["ewma_ms"] = _EWMA_ALPHA_LAT * ms + (1 - _EWMA_ALPHA_LAT) * e["ewma_ms"]
    save_scores(profile_name, scores)

def update_qps(profile_name: str, ip: str, rate: float):
    """Update EWMA QPS pass-rate (0.0–1.0) for one resolver."""
    scores = load_scores(profile_name)
    e = scores.setdefault(ip, _default_score_entry())
    e["qps_rate"] = _EWMA_ALPHA_QPS * rate + (1 - _EWMA_ALPHA_QPS) * e["qps_rate"]
    save_scores(profile_name, scores)

def mark_verified(profile_name: str, ip: str, passed: bool):
    """Record result of a full tunnel verify pass."""
    scores = load_scores(profile_name)
    e = scores.setdefault(ip, _default_score_entry())
    e["verified_at"] = _now_iso()
    if passed:
        e["qps_rate"] = _EWMA_ALPHA_QPS * 1.0 + (1 - _EWMA_ALPHA_QPS) * e["qps_rate"]
        e["consecutive_dead"] = 0
    else:
        e["qps_rate"] = _EWMA_ALPHA_QPS * 0.0 + (1 - _EWMA_ALPHA_QPS) * e["qps_rate"]
    save_scores(profile_name, scores)

def mark_hijacked(profile_name: str, ip: str):
    scores = load_scores(profile_name)
    e = scores.setdefault(ip, _default_score_entry())
    e["hijacked"] = True
    save_scores(profile_name, scores)

def sort_by_score(profile_name: str, servers: list[str]) -> list[str]:
    """Return servers sorted best-first by composite score."""
    scores = load_scores(profile_name)
    def key(ip):
        e = scores.get(ip, _default_score_entry())
        return -score_of(e)   # negative so sorted() gives descending
    return sorted(servers, key=key)

def get_score_summary(profile_name: str, servers: list[str]) -> list[dict]:
    """Returns list of dicts with ip, ewma_ms, qps_rate, score, age_days, hijacked."""
    scores = load_scores(profile_name)
    now    = datetime.now()
    out    = []
    for ip in servers:
        e = scores.get(ip, _default_score_entry())
        try:
            age = (now - datetime.fromisoformat(e["found_at"])).days
        except Exception:
            age = 0
        out.append({
            "ip":       ip,
            "ewma_ms":  int(e["ewma_ms"]),
            "qps_rate": e["qps_rate"],
            "score":    score_of(e),
            "age_days": age,
            "hijacked": e.get("hijacked", False),
            "verified_at": e.get("verified_at"),
        })
    out.sort(key=lambda x: -x["score"])
    return out

# ─────────────────────────────────────────────────────────────────────────────
# #4  RESOLVER FRESHNESS / POOL CAPPING
# ─────────────────────────────────────────────────────────────────────────────

def _stale_ips(profile_name: str, servers: list[str], max_age_days: int) -> list[str]:
    """Return IPs older than max_age_days that also have below-median score."""
    if max_age_days <= 0:
        return []
    scores  = load_scores(profile_name)
    now     = datetime.now()
    all_scores = [score_of(scores.get(ip, _default_score_entry())) for ip in servers]
    median_score = sorted(all_scores)[len(all_scores) // 2] if all_scores else 0
    stale = []
    for ip in servers:
        e = scores.get(ip, _default_score_entry())
        try:
            age = (now - datetime.fromisoformat(e["found_at"])).days
        except Exception:
            age = 0
        if age > max_age_days and score_of(e) < median_score:
            stale.append(ip)
    return stale

def enforce_pool_cap(profile_name: str, servers: list[str], max_pool: int) -> list[str]:
    """Keep only the top max_pool resolvers by score. Returns trimmed list."""
    if max_pool <= 0 or len(servers) <= max_pool:
        return servers
    ranked = sort_by_score(profile_name, servers)
    return ranked[:max_pool]

def needs_background_refresh(profile_name: str, servers: list[str],
                              max_age_days: int) -> bool:
    """True if >50% of the pool is stale — trigger a silent background scan."""
    if not servers or max_age_days <= 0:
        return False
    stale = _stale_ips(profile_name, servers, max_age_days)
    return len(stale) > len(servers) / 2

# ─────────────────────────────────────────────────────────────────────────────
# SLIPNET IMPORT / EXPORT  (#12)
# ─────────────────────────────────────────────────────────────────────────────
# Decoded format (pipe-separated):
#   [0] version  [1] type  [2] name  [3] domain
#   [4] resolvers (ip:port:flag,...)
#   [8] socks_port  [12] username  [13] password

def parse_slipnet(uri: str) -> dict:
    """
    Returns one of:
      {"ok": True,  "cfg": dict, "name": str, "resolvers": [ip, ...]}
      {"ok": False, "reason": "encrypted" | "invalid" | str}
    """
    b64 = uri[len("slipnet://"):] if uri.startswith("slipnet://") else uri.strip()
    try:
        decoded = base64.b64decode(b64 + "==").decode("utf-8")
    except Exception:
        return {"ok": False, "reason": "encrypted"}

    if not re.match(r"^[\x20-\x7E|]+$", decoded):
        return {"ok": False, "reason": "encrypted"}

    parts = decoded.split("|")
    if len(parts) < 14:
        return {"ok": False, "reason": "invalid (too few fields)"}

    try:
        name    = parts[2].strip() or "slipnet"
        domain  = parts[3].strip()
        raw_res = parts[4].strip()

        resolvers = []
        for r in raw_res.split(","):
            segs = r.strip().split(":")
            if len(segs) >= 1 and re.match(r"^\d+\.\d+\.\d+\.\d+$", segs[0]):
                resolvers.append(segs[0])

        socks_port = int(parts[8]) if parts[8].strip().isdigit() else 1080
        username   = parts[12].strip()
        password   = parts[13].strip()

        cfg = deepcopy(DEFAULT_CFG)
        cfg["domain"]          = domain
        cfg["listen_port"]     = socks_port
        cfg["http_proxy_port"] = socks_port + 1
        if username:
            cfg["socks_auth"] = True
            cfg["socks_user"] = username
            cfg["socks_pass"] = password

        return {"ok": True, "cfg": cfg, "name": name, "resolvers": resolvers}
    except Exception as e:
        return {"ok": False, "reason": f"parse error: {e}"}


def build_slipnet(profile_name: str, cfg: dict, max_resolvers: int = 10) -> str:
    """
    Export current profile as a slipnet:// URI.
    Encodes top-N resolvers by score so recipients get the best ones.
    """
    servers = sort_by_score(profile_name, load_servers(profile_name))[:max_resolvers]
    resolver_str = ",".join(f"{ip}:53:0" for ip in servers)
    socks_port   = cfg.get("listen_port", 7000)
    username     = cfg.get("socks_user", "") if cfg.get("socks_auth") else ""
    password     = cfg.get("socks_pass", "") if cfg.get("socks_auth") else ""

    # Build 14-field pipe-separated payload
    fields = [
        "1",            # [0] version
        "0",            # [1] type
        profile_name,   # [2] name
        cfg["domain"],  # [3] domain
        resolver_str,   # [4] resolvers
        "", "", "",     # [5][6][7] unused
        str(socks_port),# [8] socks_port
        "", "", "",     # [9][10][11] unused
        username,       # [12] username
        password,       # [13] password
    ]
    payload = "|".join(fields)
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return f"slipnet://{encoded}"

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROXY  (Windows registry / macOS networksetup / Linux: manual only)
# ─────────────────────────────────────────────────────────────────────────────
_WININET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

def _active_network_service() -> str:
    """macOS: return the first active network service name (e.g. 'Wi-Fi')."""
    try:
        out = subprocess.check_output(
            ["networksetup", "-listallnetworkservices"],
            stderr=subprocess.DEVNULL, text=True)
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("*") or "denotes" in line.lower():
                continue
            return line
    except Exception:
        pass
    return "Wi-Fi"




def _save_proxy_backup(enabled: bool, server: str):
    try:
        _PROXY_GUARD_FILE.write_text(json.dumps({"enabled": bool(enabled), "server": server or ""}), encoding="utf-8")
    except Exception:
        pass


def _load_proxy_backup() -> dict | None:
    try:
        if not _PROXY_GUARD_FILE.exists():
            return None
        return json.loads(_PROXY_GUARD_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def _clear_proxy_backup():
    try:
        _PROXY_GUARD_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def restore_system_proxy_defaults() -> bool:
    """Restore previously captured system proxy settings (best effort)."""
    bak = _load_proxy_backup()
    if not bak:
        return set_system_proxy(False)
    if not bak.get("enabled"):
        ok = set_system_proxy(False)
        if ok:
            _clear_proxy_backup()
        return ok
    srv = (bak.get("server") or "").strip()
    m = re.match(r"^(?:https?://)?([^:]+):(\d+)$", srv)
    if not m:
        return False
    host, port = m.group(1), int(m.group(2))
    _sys = platform.system()
    try:
        if _sys == "Windows" and _winreg:
            key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _WININET_KEY, 0, _winreg.KEY_SET_VALUE)
            _winreg.SetValueEx(key, "ProxyEnable", 0, _winreg.REG_DWORD, 1)
            _winreg.SetValueEx(key, "ProxyServer", 0, _winreg.REG_SZ, f"http://{host}:{port}")
            _winreg.CloseKey(key)
            try:
                import ctypes
                ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
                ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
            except Exception:
                pass
            _clear_proxy_backup()
            return True
        if _sys == "Darwin":
            svc = _active_network_service()
            subprocess.run(["networksetup", "-setwebproxy", svc, host, str(port)], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["networksetup", "-setsecurewebproxy", svc, host, str(port)], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["networksetup", "-setwebproxystate", svc, "on"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "on"], check=True, stderr=subprocess.DEVNULL)
            _clear_proxy_backup()
            return True
    except Exception:
        return False
    return False


def toggle_system_proxy_runtime(cfg: dict) -> tuple[bool, str]:
    """Toggle system proxy on/off without stopping tunnel."""
    if platform.system() == "Linux":
        return False, "Linux system proxy is manual-only in this app."
    enabled, _ = get_system_proxy()
    if enabled:
        ok = set_system_proxy(False)
        return ok, "disabled" if ok else "failed"
    if not cfg.get("enable_http_proxy", True):
        return False, "HTTP proxy bridge is disabled."
    ok = set_system_proxy(True, int(cfg.get("http_proxy_port", 8080)))
    return ok, "enabled" if ok else "failed"


def _register_proxy_guard():
    """Ensure OS proxy is restored on abnormal exits (best effort)."""
    def _cleanup(*_):
        try:
            restore_system_proxy_defaults()
        except Exception:
            pass
    atexit.register(_cleanup)
    if platform.system() != "Windows":
        for sig in (signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(sig, lambda a, b: (_cleanup(), sys.exit(0)))
            except Exception:
                pass

def set_system_proxy(enable: bool, port: int = 0) -> bool:
    _sys = platform.system()
    try:
        if enable and not _load_proxy_backup():
            prev_enabled, prev_server = get_system_proxy()
            _save_proxy_backup(prev_enabled, prev_server)
        if _sys == "Windows" and _winreg:
            key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _WININET_KEY,
                                  0, _winreg.KEY_SET_VALUE)
            _winreg.SetValueEx(key, "ProxyEnable", 0, _winreg.REG_DWORD, 1 if enable else 0)
            if enable and port:
                _winreg.SetValueEx(key, "ProxyServer", 0, _winreg.REG_SZ,
                                   f"http://127.0.0.1:{port}")
            _winreg.CloseKey(key)
            try:
                import ctypes
                ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
                ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
            except Exception:
                pass
            if not enable:
                _clear_proxy_backup()
            return True

        elif _sys == "Darwin":
            svc  = _active_network_service()
            addr = "127.0.0.1"
            if enable and port:
                subprocess.run(["networksetup", "-setwebproxy",
                                 svc, addr, str(port)], check=True,
                                stderr=subprocess.DEVNULL)
                subprocess.run(["networksetup", "-setsecurewebproxy",
                                 svc, addr, str(port)], check=True,
                                stderr=subprocess.DEVNULL)
                subprocess.run(["networksetup", "-setwebproxystate",
                                 svc, "on"], check=True, stderr=subprocess.DEVNULL)
                subprocess.run(["networksetup", "-setsecurewebproxystate",
                                 svc, "on"], check=True, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["networksetup", "-setwebproxystate",
                                 svc, "off"], check=False, stderr=subprocess.DEVNULL)
                subprocess.run(["networksetup", "-setsecurewebproxystate",
                                 svc, "off"], check=False, stderr=subprocess.DEVNULL)
            if not enable:
                _clear_proxy_backup()
            return True

        # Linux: no universal system-proxy API; caller will show manual instructions
        return False

    except Exception:
        return False


def get_system_proxy() -> tuple[bool, str]:
    """Returns (enabled, server_string)."""
    _sys = platform.system()
    try:
        if _sys == "Windows" and _winreg:
            key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, _WININET_KEY)
            enabled, _ = _winreg.QueryValueEx(key, "ProxyEnable")
            try:
                server, _ = _winreg.QueryValueEx(key, "ProxyServer")
            except Exception:
                server = ""
            _winreg.CloseKey(key)
            return bool(enabled), server

        elif _sys == "Darwin":
            svc = _active_network_service()
            out = subprocess.check_output(
                ["networksetup", "-getwebproxy", svc],
                stderr=subprocess.DEVNULL, text=True)
            enabled = False
            server  = ""
            port_s  = ""
            for line in out.splitlines():
                if line.startswith("Enabled:"):
                    enabled = "yes" in line.lower()
                elif line.startswith("Server:"):
                    server = line.split(":", 1)[1].strip()
                elif line.startswith("Port:"):
                    port_s = line.split(":", 1)[1].strip()
            srv_str = f"http://{server}:{port_s}" if server else ""
            return enabled, srv_str

    except Exception:
        pass
    return False, ""

# ─────────────────────────────────────────────────────────────────────────────
# TUNNEL VERIFICATION  (#1 #3 #7 #9)
# ─────────────────────────────────────────────────────────────────────────────

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def _socks5_probe(host, port, target_host, target_port,
                  user=None, passwd=None, timeout=6.0) -> bool:
    """Open SOCKS5 connection and send a small HTTP GET. Returns True on any HTTP reply."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
        r = s.recv(2)
        if len(r) < 2 or r[0] != 5:
            s.close(); return False
        if r[1] == 0x02:
            if not user: s.close(); return False
            u, p = user.encode(), (passwd or "").encode()
            s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
            ar = s.recv(2)
            if len(ar) < 2 or ar[1] != 0: s.close(); return False
        elif r[1] != 0x00:
            s.close(); return False
        hb = target_host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
                  + target_port.to_bytes(2, "big"))
        r = s.recv(10)
        if len(r) < 2 or r[1] != 0x00: s.close(); return False
        s.sendall(b"GET / HTTP/1.0\r\nHost: " + hb + b"\r\nConnection: close\r\n\r\n")
        data = s.recv(96)
        s.close()
        return data.startswith(b"HTTP/") or len(data) > 0
    except Exception:
        return False





# ── #9: DNS integrity check — detect hijacking transparent proxies ────────────
# Cloudflare's one.one.one.one resolves to 1.1.1.1 or 1.0.0.1.
# A hijacking resolver returns a private/RFC1918 address instead.
_CLOUDFLARE_VALID = {"1.1.1.1", "1.0.0.1"}

def _dns_integrity_check(socks_host: str, socks_port: int,
                          user=None, passwd=None, timeout=8.0) -> bool:
    """
    Connect through the tunnel's SOCKS5 port and ask for one.one.one.one's A record.
    Returns True if the response looks legitimate (Cloudflare IP, not hijacked).
    A False result flags the resolver as a transparent proxy.
    """
    try:
        # Build a DNS A query for "one.one.one.one" with a random TXID
        txid   = random.randint(1, 65534)
        labels = b"one.one.one.one".split(b".")
        qname  = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
        query  = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + b"\x00\x01\x00\x01"

        # Wrap in a 2-byte length prefix for TCP DNS (RFC 1035 §4.2.2)
        tcp_query = struct.pack(">H", len(query)) + query

        # Open SOCKS5 tunnel to 1.1.1.1:53 (TCP DNS)
        s = socket.create_connection((socks_host, socks_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
        r = s.recv(2)
        if len(r) < 2 or r[0] != 5: s.close(); return True  # can't check, pass
        if r[1] == 0x02:
            if not user: s.close(); return True
            u, p = user.encode(), (passwd or "").encode()
            s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
            ar = s.recv(2)
            if len(ar) < 2 or ar[1] != 0: s.close(); return True
        elif r[1] != 0x00: s.close(); return True

        # SOCKS5 CONNECT to 1.1.1.1:53
        target = b"1.1.1.1"
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("1.1.1.1")
                  + (53).to_bytes(2, "big"))
        r = s.recv(10)
        if len(r) < 2 or r[1] != 0x00: s.close(); return True

        s.sendall(tcp_query)
        # Read response length prefix
        ln = s.recv(2)
        if len(ln) < 2: s.close(); return True
        resp_len = struct.unpack(">H", ln)[0]
        resp = b""
        while len(resp) < resp_len:
            chunk = s.recv(resp_len - len(resp))
            if not chunk: break
            resp += chunk
        s.close()

        if len(resp) < 12: return True  # too short to parse
        # Check TXID matches
        resp_txid = struct.unpack(">H", resp[:2])[0]
        if resp_txid != txid: return True  # mismatch, can't trust
        # Parse answer section IPs
        # Simple scan: look for A records (type 0x0001, class 0x0001, 4-byte rdata)
        # Walk past the question section
        pos = 12
        qdcount = struct.unpack(">H", resp[4:6])[0]
        for _ in range(qdcount):
            while pos < len(resp):
                ln = resp[pos]; pos += 1
                if ln == 0: break
                pos += ln
            pos += 4  # qtype + qclass
        # Parse answers
        ancount = struct.unpack(">H", resp[6:8])[0]
        found_ips = set()
        for _ in range(ancount):
            if pos + 10 > len(resp): break
            pos += 2   # name (assume pointer or label, skip 2)
            rtype  = struct.unpack(">H", resp[pos:pos+2])[0]; pos += 2
            pos    += 2  # class
            pos    += 4  # ttl
            rdlen  = struct.unpack(">H", resp[pos:pos+2])[0]; pos += 2
            rdata  = resp[pos:pos+rdlen]; pos += rdlen
            if rtype == 1 and rdlen == 4:  # A record
                found_ips.add(socket.inet_ntoa(rdata))

        if not found_ips:
            return True  # no A records, can't judge

        # Flag as hijacked if any returned IP is RFC1918 / private
        private = re.compile(
            r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)")
        for ip in found_ips:
            if private.match(ip):
                return False  # hijacked
        # Optionally: also flag if none of the IPs match known-good Cloudflare
        # (too strict for general use — ISPs may return other valid IPs)
        return True

    except Exception:
        return True  # on any error, give benefit of the doubt


def verify_resolver(ip: str, cfg: dict, timeout: float = 12.0,
                    profile_name: str = None,
                    check_integrity: bool = True,
                    dns_precheck: bool = True) -> bool:
    """
    Spawn a temporary client, wait for it to be ready, probe via SOCKS5.
    Also performs DNS integrity check (#9) to detect hijacking transparent proxies.
    Updates resolver scores (#1) if profile_name is provided.
    Returns True if the resolver can actually tunnel traffic.
    """
    if not CLIENT_EXE.exists():
        return True  # can't test, assume ok

    # SlipNet-style DNS tunnel compatibility pre-check before full E2E run.
    if dns_precheck:
        compatible, _ = scan_resolver_dns_tunnel(
            ip,
            cfg["domain"],
            timeout=min(timeout, 2.0),
            mode=str(cfg.get("dns_precheck_mode", "quick")).lower(),
        )
        if not compatible:
            if profile_name:
                mark_verified(profile_name, ip, False)
            return False
    port = _free_port()
    cmd = build_client_cmd(cfg, [ip], port)

    _VERIFY_STARTUP_MAX = 6.0
    _VERIFY_POLL_INT    = 0.4

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait until the client's SOCKS5 port accepts connections (or process exits)
        deadline = time.monotonic() + _VERIFY_STARTUP_MAX
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                if profile_name: mark_verified(profile_name, ip, False)
                return False
            try:
                test_sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                test_sock.close()
                ready = True
                break
            except OSError:
                time.sleep(_VERIFY_POLL_INT)

        if not ready:
            if profile_name: mark_verified(profile_name, ip, False)
            return False

        user   = cfg["socks_user"] if cfg.get("socks_auth") else None
        passwd = cfg["socks_pass"] if cfg.get("socks_auth") else None

        # Basic E2E SOCKS5 connectivity probe against an actual HTTP host
        probe_host = cfg.get("verify_probe_host", "example.com")
        probe_port = int(cfg.get("verify_probe_port", 80))
        if not _socks5_probe("127.0.0.1", port, probe_host, probe_port,
                             user=user, passwd=passwd, timeout=timeout):
            if profile_name: mark_verified(profile_name, ip, False)
            return False

        # DNS integrity check — detect hijacking transparent proxies (#9)
        if check_integrity:
            if not _dns_integrity_check("127.0.0.1", port, user=user,
                                        passwd=passwd, timeout=timeout):
                if profile_name:
                    mark_hijacked(profile_name, ip)
                    flog(profile_name, "scan",
                         f"[hijack] {ip} returned private IP for one.one.one.one — excluded")
                return False

        if profile_name: mark_verified(profile_name, ip, True)
        return True

    except Exception:
        if profile_name: mark_verified(profile_name, ip, False)
        return False
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=3)
            except Exception: proc.kill()


# ── #3: Parallel verification with streaming callbacks ────────────────────────

def verify_resolvers_parallel(
        ips: list[str],
        cfg: dict,
        profile_name: str = None,
        max_workers: int = 4,
        result_cb=None,          # cb(ip: str, passed: bool)  called as each finishes
) -> list[str]:
    """
    Verify a list of IPs in parallel.  Returns list of passing IPs in original order.
    result_cb is called from worker threads — keep it thread-safe (just print/append).
    """
    results: dict[str, bool] = {}
    lock = threading.Lock()

    def _do(ip):
        passed = verify_resolver(
            ip,
            cfg,
            timeout=float(cfg.get("verify_timeout", 14)),
            profile_name=profile_name,
            check_integrity=True,
        )
        with lock:
            results[ip] = passed
        if result_cb:
            result_cb(ip, passed)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_do, ip): ip for ip in ips}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception:
                pass

    passed = [ip for ip in ips if results.get(ip, False)]

    # Fallback: strict DNS pre-check can be too aggressive on some paths;
    # retry a small subset with relaxed mode to reduce false negatives.
    if not passed and cfg.get("verify_relaxed_retry", True):
        retry_n = max(1, int(cfg.get("verify_relaxed_count", 6)))
        retry_ips = ips[:retry_n]
        def _do_relaxed(ip):
            ok = verify_resolver(
                ip,
                cfg,
                timeout=float(cfg.get("verify_timeout", 14)) + 4.0,
                profile_name=profile_name,
                check_integrity=True,
                dns_precheck=False,
            )
            with lock:
                results[ip] = ok
            if result_cb:
                result_cb(ip, ok)

        with ThreadPoolExecutor(max_workers=min(max_workers, len(retry_ips))) as ex:
            futs = [ex.submit(_do_relaxed, ip) for ip in retry_ips]
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception:
                    pass
        passed = [ip for ip in ips if results.get(ip, False)]

    return passed

# ─────────────────────────────────────────────────────────────────────────────
# #7  DNS LATENCY WITH RANDOM TXID + QUERY-TYPE DIVERSITY
# ─────────────────────────────────────────────────────────────────────────────

_QTYPE_CYCLE = [0x0001, 0x001C]   # A, AAAA — alternate to reduce fingerprint
_qtype_idx   = 0
_qtype_lock  = threading.Lock()

def _dns_latency(ip: str, domain: str, timeout: float = 2.0) -> int:
    """
    Returns ms latency, or 9999 on failure.
    Uses a random TXID (security + correctness) and alternates query types
    (A / AAAA) to reduce ISP fingerprinting of DNS tunnel health checks.
    """
    global _qtype_idx
    try:
        with _qtype_lock:
            qtype = _QTYPE_CYCLE[_qtype_idx % len(_QTYPE_CYCLE)]
            _qtype_idx += 1

        txid   = random.randint(1, 65534)
        labels = domain.encode().split(b".")
        qname  = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
        pkt    = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname \
                 + struct.pack(">HH", qtype, 0x0001)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        t0 = time.monotonic()
        s.sendto(pkt, (ip, 53))
        resp, _ = s.recvfrom(512)
        ms = int((time.monotonic() - t0) * 1000)
        s.close()
        resp_txid = struct.unpack(">H", resp[:2])[0]
        rcode     = struct.unpack(">H", resp[2:4])[0] & 0xF
        # Accept NOERROR (0) or NXDOMAIN (3) — both mean resolver is reachable
        return ms if resp_txid == txid and rcode in (0, 3) else 9999
    except Exception:
        return 9999


def check_resolvers(domain: str, servers: list[str],
                    profile_name: str = None) -> dict[str, int]:
    """
    Parallel DNS latency check. Returns {ip: ms}.
    Updates resolver score store if profile_name is given (#1).
    """
    results: dict[str, int] = {}
    lock = threading.Lock()

    def _probe(ip):
        ms = _dns_latency(ip, domain)
        with lock:
            results[ip] = ms
        if profile_name:
            update_latency(profile_name, ip, ms)

    threads = [threading.Thread(target=_probe, args=(ip,), daemon=True)
               for ip in servers]
    for t in threads: t.start()
    for t in threads: t.join(timeout=5)
    return results

# ─────────────────────────────────────────────────────────────────────────────
# DNS SCAN
# ─────────────────────────────────────────────────────────────────────────────

# ── #11: Auto-escalate scan mode based on pool state ─────────────────────────

def auto_scan_mode(profile_name: str, reason: str = "manual") -> str:
    """
    Pick an appropriate scan mode based on current pool state and reason.
      emergency → medium  (be thorough when things are broken)
      periodic  → list    (fast refresh, least disruptive)
      manual with empty pool → list first, caller escalates if needed
      manual with small pool → fast
    """
    servers = load_servers(profile_name)
    if reason == "emergency":
        return "medium"
    if reason == "periodic":
        return "list"
    if not servers:
        return "list"
    if len(servers) < 5:
        return "fast"
    return "fast"






def run_dnscan(cfg: dict, profile_name: str,
               mode: str = None,
               output: Path = None,
               progress_cb=None) -> list[str]:
    """
    Run dnscan.exe. progress_cb(line: str) is called for each output line if set.
    Returns list of IPs that passed the benchmark.
    Auto-selects scan mode if not specified (#11).
    """
    out = output or (pdir(profile_name) / "scan_out.txt")
    m = (mode or cfg["scan_mode"] or "fast").lower()

    def _timeout_to_seconds(v: str) -> float:
        try:
            s = str(v).strip().lower()
            if s.endswith("ms"):
                return max(0.2, float(s[:-2]) / 1000.0)
            if s.endswith("s"):
                return max(0.2, float(s[:-1]))
            return max(0.2, float(s))
        except Exception:
            return 1.0

    def _load_ip_file(path: Path) -> list[str]:
        if not path.exists():
            return []
        out_ips = []
        for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            ip = ln.strip()
            if not ip or ip.startswith("#"):
                continue
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                out_ips.append(ip)
        return out_ips

    def _candidate_pool(country: str, target: int) -> list[str]:
        # Requested behavior: use resolver corpus from resolvers.txt, not random IP sampling.
        known = _load_ip_file(APP_DNS_DIR / "resolvers.txt")
        if not known:
            known = _load_ip_file(DNSCAN_DATA / "dns" / f"{country.lower()}.txt")
        # Keep file order (famous resolvers are intentionally prioritized).
        dedup = list(dict.fromkeys(known))
        return dedup[:max(target, 1)]

    target = max(300, int(cfg.get("scan_target_count", 7000)))
    if m == "list":
        target = min(target, 900)
    elif m == "medium":
        target = min(target, 3000)
    elif m == "fast":
        target = min(target, 7000)

    probe_timeout = _timeout_to_seconds(cfg.get("scan_timeout", "1s"))
    workers = max(16, min(1024, int(cfg.get("scan_workers", 1200))))
    ips = _candidate_pool(cfg.get("country", "ir"), target)
    if progress_cb:
        progress_cb(f"[scan] scanner=python target={len(ips)} mode={m} workers={workers}")
    if not ips:
        return []

    results: list[str] = []
    scored: list[tuple[str, float]] = []
    verify_mode = "full" if m in ("medium", "full") else "quick"

    def _probe(ip: str):
        ok, _ = scan_resolver_dns_tunnel(ip, cfg["domain"], timeout=probe_timeout, mode=verify_mode)
        if not ok:
            return ip, 0.0
        ratio = burst_dns_success(ip, cfg["domain"], timeout=min(1.2, probe_timeout), count=int(cfg.get("scan_burst_count", 6)))
        return ip, ratio

    done = 0
    min_ratio = float(cfg.get("scan_burst_min_pass", 0.35))
    with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as ex:
        futures = {ex.submit(_probe, ip): ip for ip in ips}
        for fut in as_completed(futures):
            done += 1
            ip, ratio = fut.result()
            if ratio >= min_ratio:
                results.append(ip)
                scored.append((ip, ratio))
                if progress_cb:
                    progress_cb(f"[ok] {ip} qps={ratio:.2f}")
            elif progress_cb and done % 250 == 0:
                progress_cb(f"[scan] checked={done}/{len(ips)} found={len(results)}")

    scored.sort(key=lambda x: x[1], reverse=True)
    results = [ip for ip, _ in scored]

    out.write_text("\n".join(results) + ("\n" if results else ""), encoding="utf-8")

    # Post-filter with parallel burst sampling to reduce false positives quickly.
    burst_n = int(cfg.get("scan_burst_count", 6) or 0)
    burst_to = float(cfg.get("scan_burst_timeout", 0.8) or 0.8)
    burst_workers = max(1, int(cfg.get("scan_burst_workers", 64) or 64))
    min_pass = float(cfg.get("scan_burst_min_pass", 0.35) or 0.35)
    if results and burst_n > 0:
        kept = []
        rates: dict[str, float] = {}

        def _rate(ip):
            return ip, burst_dns_success(ip, cfg["domain"], timeout=burst_to, count=burst_n)

        with ThreadPoolExecutor(max_workers=min(burst_workers, len(results))) as ex:
            futs = [ex.submit(_rate, ip) for ip in results]
            for fut in as_completed(futs):
                try:
                    ip, rate = fut.result()
                    rates[ip] = rate
                except Exception:
                    pass

        for ip in results:
            rate = rates.get(ip, 0.0)
            update_qps(profile_name, ip, rate)
            if rate >= min_pass:
                kept.append(ip)
            elif progress_cb:
                progress_cb(f"[burst-filter] reject {ip} ({int(rate*100)}%)")
        results = kept

    return results


def restart_dead_instances(cfg: dict, profile_name: str) -> int:
    """Restart only dead tunnel instances, preserving healthy ones."""
    restarted = 0
    with _inst_lock:
        for i, inst in enumerate(list(_instances)):
            if inst.alive():
                continue
            repl = _Instance(inst.index, inst.port, list(inst.resolvers), cfg)
            ok, detail = repl.start(profile_name=profile_name)
            if ok:
                _instances[i] = repl
                restarted += 1
                flog(profile_name, "watchdog", f"Restarted dead instance {inst.index+1} on port {inst.port}")
            else:
                flog(profile_name, "watchdog", f"Dead instance {inst.index+1} restart failed: {detail}")
    return restarted

# ─────────────────────────────────────────────────────────────────────────────
# #6  ADAPTIVE KEEP-ALIVE
# ─────────────────────────────────────────────────────────────────────────────

def compute_adaptive_keepalive(profile_name: str, servers: list[str],
                                cfg: dict) -> int:
    """
    Compute an adjusted keep-alive interval (ms) based on observed pool health.

    Logic:
      - If average EWMA latency is rising (>600ms): send faster (floor at min_ms)
        to keep the tunnel warm despite slow resolvers.
      - If average QPS pass-rate is falling (<0.6): back off (approach max_ms)
        to reduce load on throttled resolvers.
      - Otherwise: drift back toward the configured baseline.

    Returns the new keep_alive_ms to use.  Caller should restart instances
    if the value changes significantly (>20% from current).
    """
    if not cfg.get("keep_alive_adaptive", True):
        return cfg.get("keep_alive_ms", 400)

    ka_min  = cfg.get("keep_alive_min_ms",  200)
    ka_max  = cfg.get("keep_alive_max_ms",  2000)
    ka_base = cfg.get("keep_alive_ms",       400)

    if not servers:
        return ka_base

    scores   = load_scores(profile_name)
    entries  = [scores.get(ip, _default_score_entry()) for ip in servers]
    avg_lat  = sum(e["ewma_ms"]  for e in entries) / len(entries)
    avg_qps  = sum(e["qps_rate"] for e in entries) / len(entries)

    if avg_lat > 600:
        # Latency high → speed up keep-alive to keep tunnel warm
        new_ka = max(ka_min, int(ka_base * 0.7))
    elif avg_qps < 0.6:
        # QPS rate poor → back off to reduce resolver load
        new_ka = min(ka_max, int(ka_base * 1.4))
    else:
        # Healthy → drift toward baseline
        new_ka = ka_base

    return new_ka

# ─────────────────────────────────────────────────────────────────────────────
# MULTI-INSTANCE TUNNEL CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class _Instance:
    def __init__(self, index: int, port: int, resolvers: list, cfg: dict):
        self.index     = index
        self.port      = port
        self.resolvers = resolvers
        self.cfg       = cfg
        self.proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        # #2: connection counter for QPS budget awareness
        self._conn_count   = 0
        self._conn_window  = deque()   # timestamps of recent connections
        self._conn_lock    = threading.Lock()

    def start(self, profile_name: str = "") -> tuple[bool, str]:
        """
        Start the client process.
        Returns (success: bool, error_detail: str).
        Captures stderr to a log file AND returns it on failure so the UI can show it.
        """
        with self._lock:
            self._kill()
            if not CLIENT_EXE.exists():
                return False, f"client binary not found: {CLIENT_EXE}"
            _ensure_executable(CLIENT_EXE)
            if not self.resolvers:
                return False, "no resolvers assigned to instance"
            cmd = build_client_cmd(self.cfg, self.resolvers, self.port)
            try:
                self.proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                time.sleep(1.2)
                if self.proc.poll() is not None:
                    # Process exited — capture its output for diagnosis
                    try:
                        out = self.proc.stdout.read().decode("utf-8", errors="replace").strip()
                    except Exception:
                        out = "(no output)"
                    self.proc = None
                    return False, out or "(process exited immediately with no output)"
                # Still running — redirect output to log in background
                if profile_name:
                    def _drain():
                        try:
                            lf = logfile(profile_name, "tunnel")
                            for line in self.proc.stdout:
                                try:
                                    with open(lf, "a", encoding="utf-8") as f:
                                        f.write(line if isinstance(line, str)
                                                else line.decode("utf-8", errors="replace"))
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    threading.Thread(target=_drain, daemon=True).start()
                else:
                    # No profile — just discard stdout to avoid blocking
                    threading.Thread(
                        target=lambda: self.proc.stdout.read(),
                        daemon=True).start()
                return True, ""
            except Exception as e:
                self.proc = None
                return False, str(e)

    def stop(self):
        with self._lock:
            self._kill()

    def _kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:   self.proc.wait(timeout=5)
            except Exception: self.proc.kill()
        self.proc = None

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def pid(self) -> int | None:
        return self.proc.pid if self.proc else None

    # ── #2: QPS budget tracking ───────────────────────────────────────────────
    def record_connection(self):
        """Called by proxy each time a connection is dispatched to this instance."""
        now = time.monotonic()
        with self._conn_lock:
            self._conn_window.append(now)
            # Keep only the last 10 seconds
            cutoff = now - 10.0
            while self._conn_window and self._conn_window[0] < cutoff:
                self._conn_window.popleft()

    def connections_per_second(self) -> float:
        """Rolling 10-second CPS estimate."""
        now = time.monotonic()
        with self._conn_lock:
            cutoff = now - 10.0
            while self._conn_window and self._conn_window[0] < cutoff:
                self._conn_window.popleft()
            return len(self._conn_window) / 10.0

    def estimated_qps_budget(self) -> float:
        """
        Estimate remaining QPS budget for this instance's primary resolver.
        Based on the resolver's known QPS rate from scores.
        Returns a float 0–∞; values <1.0 mean we're near/over budget.
        """
        # We don't have profile_name here, so we return a simple load factor.
        # _pick_instance uses this to prefer less-loaded instances.
        return 1.0 / max(self.connections_per_second(), 0.1)


# ── Globals ──────────────────────────────────────────────────────────────────
_instances:    list[_Instance]    = []
_inst_lock     = threading.Lock()
_running_prof: str                = ""

# Runtime traffic telemetry (for terminal live monitor)
_stats_lock = threading.Lock()
_stats_events = deque(maxlen=5000)   # (ts, up_bytes, down_bytes)
_stats_tot_up = 0
_stats_tot_down = 0
_stats_total_conns = 0
_stats_active_port = 0


def _stats_record_bytes(up: int, down: int):
    global _stats_tot_up, _stats_tot_down
    ts = time.monotonic()
    with _stats_lock:
        _stats_tot_up += up
        _stats_tot_down += down
        _stats_events.append((ts, up, down))


def _stats_record_connection(port: int):
    global _stats_total_conns, _stats_active_port
    with _stats_lock:
        _stats_total_conns += 1
        _stats_active_port = port


def tunnel_runtime_stats(profile_name: str) -> dict:
    """Aggregated runtime metrics for UI dashboards."""
    now = time.monotonic()
    with _stats_lock:
        while _stats_events and (now - _stats_events[0][0]) > 10.0:
            _stats_events.popleft()
        up_10 = sum(e[1] for e in _stats_events)
        down_10 = sum(e[2] for e in _stats_events)
        tot_up = _stats_tot_up
        tot_down = _stats_tot_down
        total_conns = _stats_total_conns
        active_port = _stats_active_port

    up_bps = up_10 / 10.0
    down_bps = down_10 / 10.0

    active_resolver = "-"
    active_latency = None
    with _inst_lock:
        for inst in _instances:
            if inst.port == active_port and inst.resolvers:
                active_resolver = inst.resolvers[0]
                break

    if active_resolver != "-" and profile_name:
        scores = load_scores(profile_name)
        entry = scores.get(active_resolver, {})
        active_latency = entry.get("ewma_ms")

    return {
        "connected": tunnel_running() and proxy_running(),
        "up_bps": up_bps,
        "down_bps": down_bps,
        "total_up": tot_up,
        "total_down": tot_down,
        "total_conns": total_conns,
        "active_port": active_port,
        "active_resolver": active_resolver,
        "active_latency_ms": active_latency,
    }


def _split_resolvers(servers: list, n: int, failover_count: int = 1) -> list[list]:
    """
    Assign each instance a specific primary resolver plus optional failovers.
    Example: n=3, failover_count=1 => [r1,r2], [r2,r3], [r3,r1]
    """
    if not servers:
        return [[] for _ in range(max(1, n))]
    n = max(1, n)
    depth = max(0, int(failover_count))
    groups = []
    for i in range(n):
        primary_idx = i % len(servers)
        group = [servers[primary_idx]]
        for j in range(depth):
            group.append(servers[(primary_idx + j + 1) % len(servers)])
        dedup = []
        seen = set()
        for ip in group:
            if ip not in seen:
                seen.add(ip)
                dedup.append(ip)
        groups.append(dedup)
    return groups


def start_tunnel(cfg: dict, profile_name: str) -> dict:
    """
    Start N slipstream-client instances.
    Returns {"started": int, "total": int, "instances": [{"port":p,"pid":n,"resolvers":k}]}
    """
    global _instances, _running_prof
    servers = load_servers(profile_name)
    if not servers:
        return {"started": 0, "total": 0, "error": "no_resolvers"}
    if not CLIENT_EXE.exists():
        return {"started": 0, "total": 0, "error": "no_client"}

    with _inst_lock:
        for inst in _instances:
            inst.stop()
        _instances.clear()

        n      = max(1, cfg.get("multi_instance", 1))
        base   = cfg.get("listen_port", 7000)
        # Sort by score before splitting so best resolvers are spread across instances
        ranked = sort_by_score(profile_name, servers)
        groups = _split_resolvers(ranked, n, cfg.get("instance_failover_count", 1))
        info   = []

        errors = []
        for i, group in enumerate(groups):
            port = base + i
            inst = _Instance(i, port, group, cfg)
            ok, detail = inst.start(profile_name=profile_name)
            if ok:
                _instances.append(inst)
                info.append({"index": i, "port": port, "pid": inst.pid, "resolvers": len(group)})
            else:
                errors.append(f"instance {i+1} (port {port}): {detail}")
                flog(profile_name, "tunnel", f"Instance {i+1} failed to start: {detail}")

        _running_prof = profile_name if _instances else ""
        result = {"started": len(_instances), "total": n, "instances": info}
        if errors:
            result["instance_errors"] = errors
        return result


def stop_tunnel():
    global _instances, _running_prof
    with _inst_lock:
        for inst in _instances:
            inst.stop()
        _instances.clear()
    _running_prof = ""


def restart_tunnel(cfg: dict, profile_name: str) -> dict:
    stop_tunnel()
    return start_tunnel(cfg, profile_name)


def tunnel_running() -> bool:
    return any(i.alive() for i in _instances)


def tunnel_counts() -> tuple[int, int]:
    """Returns (alive, total_configured)."""
    with _inst_lock:
        return sum(1 for i in _instances if i.alive()), len(_instances)


def live_ports() -> list[int]:
    with _inst_lock:
        return [i.port for i in _instances if i.alive()]


def tunnel_instance_info() -> list[dict]:
    with _inst_lock:
        return [{"index": i.index, "port": i.port, "pid": i.pid,
                 "alive": i.alive(), "resolvers": len(i.resolvers),
                 "cps": round(i.connections_per_second(), 2)}
                for i in _instances]

# ─────────────────────────────────────────────────────────────────────────────
# HTTP → SOCKS5 PROXY  (#2 QPS-aware port selection)
# ─────────────────────────────────────────────────────────────────────────────

_proxy_thread: threading.Thread | None = None
_proxy_stop    = threading.Event()
_proxy_srv     = None
_rr_idx        = 0
_rr_lock       = threading.Lock()
_domestic_domains_cache: set[str] | None = None
_domestic_cidrs_cache: list[ipaddress.IPv4Network] | None = None


def _load_domestic_domains() -> set[str]:
    global _domestic_domains_cache
    if _domestic_domains_cache is not None:
        return _domestic_domains_cache
    path = APP_GEO_DIR / "ir.domains"
    out: set[str] = set()
    if path.exists():
        for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            d = ln.strip().lower().lstrip(".")
            if not d or d.startswith("#"):
                continue
            out.add(d)
    _domestic_domains_cache = out
    return out


def _load_domestic_cidrs() -> list[ipaddress.IPv4Network]:
    global _domestic_cidrs_cache
    if _domestic_cidrs_cache is not None:
        return _domestic_cidrs_cache
    path = APP_GEO_DIR / "ir.cidr"
    nets: list[ipaddress.IPv4Network] = []
    if path.exists():
        for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            cidr = ln.strip()
            if not cidr or cidr.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    nets.append(net)
            except Exception:
                continue
    _domestic_cidrs_cache = nets
    return nets


def _is_domestic_target(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    try:
        ip = ipaddress.ip_address(h)
        if isinstance(ip, ipaddress.IPv4Address):
            return any(ip in n for n in _load_domestic_cidrs())
        return False
    except Exception:
        pass
    if h.endswith(".ir"):
        return True
    for d in _load_domestic_domains():
        if h == d or h.endswith("." + d):
            return True
    return False


def _normalize_http_proxy_request(buf: bytes, url: str) -> bytes:
    """Convert absolute-form proxy request to origin-form for direct upstream."""
    try:
        head, rest = (buf.split(b"\r\n\r\n", 1) + [b""])[:2]
        lines = head.split(b"\r\n")
        if not lines:
            return buf
        first = lines[0].decode("latin1", errors="replace")
        parts = first.split(" ", 2)
        if len(parts) < 3:
            return buf
        method, _orig_url, version = parts
        m = re.match(r"https?://[^/]+(/.*)?$", url)
        path = m.group(1) if m else "/"
        path = path or "/"
        lines[0] = f"{method} {path} {version}".encode("latin1", errors="replace")
        return b"\r\n".join(lines) + b"\r\n\r\n" + rest
    except Exception:
        return buf


def _pick_instance() -> "_Instance | None":
    """
    #2: QPS-budget-aware instance selection.
    Prefer instances with the most remaining budget (fewest recent connections).
    Falls back to round-robin if all instances are equally loaded.
    """
    with _inst_lock:
        alive = [i for i in _instances if i.alive()]
    if not alive:
        return None
    # Pick instance with highest remaining budget (lowest CPS)
    return min(alive, key=lambda i: i.connections_per_second())


def _pick_port(base: int) -> int:
    """Select best port via QPS-aware instance selection."""
    inst = _pick_instance()
    if inst is None:
        return base
    inst.record_connection()
    _stats_record_connection(inst.port)
    return inst.port


def _socks5_open(sp, tp, th, tprt, user=None, passwd=None, timeout=10):
    s = socket.create_connection((sp, tp), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[0] != 5:
        s.close(); raise ConnectionError("Bad SOCKS5 greeting")
    if r[1] == 0x02:
        if not user: s.close(); raise ConnectionError("Server requires auth")
        u, p = user.encode(), (passwd or "").encode()
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        ar = s.recv(2)
        if len(ar) < 2 or ar[1] != 0:
            s.close(); raise ConnectionError("SOCKS5 auth failed")
    elif r[1] != 0x00:
        s.close(); raise ConnectionError("No usable SOCKS5 method")
    hb = th.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + tprt.to_bytes(2, "big"))
    r = s.recv(10)
    if len(r) < 2 or r[1] != 0x00:
        s.close(); raise ConnectionError(f"SOCKS5 CONNECT refused: {r[1] if len(r)>1 else '?'}")
    return s


def _relay(a, b, active_port=0):
    import select
    a.settimeout(None); b.settimeout(None)
    try:
        while True:
            rd, _, err = select.select([a, b], [], [a, b], 30)
            if err or not rd: break
            for s in rd:
                other = b if s is a else a
                try:
                    d = s.recv(65536)
                    if not d: return
                    other.sendall(d)
                    if s is a:
                        _stats_record_bytes(len(d), 0)
                    else:
                        _stats_record_bytes(0, len(d))
                except Exception: return
    except Exception: pass
    finally:
        for s in (a, b):
            try: s.close()
            except Exception: pass


def _proxy_handle(sock, base_port, user, passwd, connect_timeout=20, cfg: dict | None = None):
    try:
        sock.settimeout(10)
        if cfg:
            _tune_tcp_socket(sock, cfg)
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = sock.recv(4096)
            if not c: return
            buf += c
        parts = buf.split(b"\r\n")[0].decode(errors="replace").split()
        if len(parts) < 2: return
        method, url = parts[0], parts[1]
        sp = _pick_port(base_port)
        if method == "CONNECT":
            host, port = url.rsplit(":", 1); port = int(port)
            bypass_domestic = bool((cfg or {}).get("domestic_bypass_enabled", True))
            direct = bypass_domestic and _is_domestic_target(host)
            try:
                if direct:
                    up = socket.create_connection((host, port), timeout=connect_timeout)
                else:
                    up = _socks5_open("127.0.0.1", sp, host, port,
                                      user or None, passwd,
                                      timeout=connect_timeout)
                if cfg:
                    _tune_tcp_socket(up, cfg)
            except Exception as e:
                sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\nX-Err: {e}\r\n\r\n".encode())
                return
            sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _relay(sock, up, sp)
        else:
            m = re.match(r"https?://([^/:]+)(?::(\d+))?", url)
            if not m:
                sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"); return
            host = m.group(1); port = int(m.group(2) or 80)
            bypass_domestic = bool((cfg or {}).get("domestic_bypass_enabled", True))
            direct = bypass_domestic and _is_domestic_target(host)
            try:
                if direct:
                    up = socket.create_connection((host, port), timeout=connect_timeout)
                    buf = _normalize_http_proxy_request(buf, url)
                else:
                    up = _socks5_open("127.0.0.1", sp, host, port,
                                      user or None, passwd,
                                      timeout=connect_timeout)
                if cfg:
                    _tune_tcp_socket(up, cfg)
            except Exception:
                sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); return
            up.sendall(buf)
            _relay(sock, up, sp)
    except Exception: pass
    finally:
        try: sock.close()
        except Exception: pass


def _proxy_loop(http_port, base_port, user, passwd, connect_timeout, cfg):
    global _proxy_srv
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", http_port))
    except OSError:
        return
    srv.listen(256); srv.settimeout(1)
    _proxy_srv = srv
    while not _proxy_stop.is_set():
        try:
            c, _ = srv.accept()
            threading.Thread(target=_proxy_handle,
                             args=(c, base_port, user, passwd, connect_timeout, cfg),
                             daemon=True).start()
        except socket.timeout: continue
        except Exception: break
    srv.close()


def start_proxy(cfg: dict):
    global _proxy_thread, _proxy_stop
    _proxy_stop.clear()
    user   = cfg["socks_user"] if cfg.get("socks_auth") else ""
    passwd = cfg["socks_pass"] if cfg.get("socks_auth") else ""
    base   = cfg.get("listen_port", 7000)
    ct     = cfg.get("watchdog_probe_timeout", 12) + 5
    _proxy_thread = threading.Thread(
        target=_proxy_loop,
        args=(cfg["http_proxy_port"], base, user, passwd, ct, cfg),
        daemon=True,
    )
    _proxy_thread.start()


def stop_proxy():
    global _proxy_srv
    _proxy_stop.set()
    if _proxy_srv:
        try: _proxy_srv.close()
        except Exception: pass
        _proxy_srv = None


def proxy_running() -> bool:
    return _proxy_thread is not None and _proxy_thread.is_alive()

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH / PROBE
# ─────────────────────────────────────────────────────────────────────────────

def probe_proxy(http_port: int, url: str, timeout: int = 12) -> tuple:
    """
    Probe end-to-end connectivity through our HTTP proxy.
    Returns (success: bool, detail: str).

    Always use a plain http:// URL (e.g. http://1.1.1.1).
    For https:// we send CONNECT then plain HTTP — only works on targets
    that accept plain HTTP on 443 (e.g. 1.1.1.1).  Real HTTPS targets
    will reject the unencrypted HEAD, causing a false failure.
    """
    m = re.match(r"(https?)://([^/:]+)(?::(\d+))?", url)
    if not m:
        return False, "invalid URL"

    scheme = m.group(1)
    host   = m.group(2)
    port   = int(m.group(3) or (443 if scheme == "https" else 80))
    outer_timeout = timeout + 8

    try:
        s = socket.create_connection(("127.0.0.1", http_port), timeout=outer_timeout)
        s.settimeout(outer_timeout)

        if scheme == "https":
            s.sendall(f"CONNECT {host}:{port} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(256)
                if not chunk: break
                resp += chunk
            if b"200" not in resp:
                s.close()
                code = resp.split(b"\r\n")[0].decode(errors="replace") if resp else "no response"
                return False, f"CONNECT rejected: {code}"
            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        else:
            s.sendall(f"HEAD {url} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())

        resp = s.recv(256)
        s.close()

        if not resp:
            return False, "empty response from target (try http://1.1.1.1 as probe URL)"

        first_line = resp.split(b"\r\n")[0].decode(errors="replace")
        return True, first_line

    except socket.timeout:
        return False, (
            f"timed out after {outer_timeout}s — "
            f"try: (1) use http://1.1.1.1 as probe URL  "
            f"(2) increase probe timeout in Watchdog settings"
        )
    except ConnectionRefusedError:
        return False, "connection refused — is the tunnel running?"
    except Exception as e:
        return False, str(e)


# ── #8: Tunnel warm-up probe after start ─────────────────────────────────────

def probe_tunnel(cfg: dict, timeout: int = 12) -> tuple[bool, str]:
    """Unified watchdog/warmup probe supporting HTTP-proxy and SOCKS-only modes."""
    mode = (cfg.get("watchdog_probe_mode", "auto") or "auto").lower()
    if mode not in ("auto", "http", "socks"):
        mode = "auto"

    # Prefer HTTP probe if enabled and running
    if mode in ("auto", "http"):
        if cfg.get("enable_http_proxy", True) and proxy_running():
            return probe_proxy(
                cfg["http_proxy_port"],
                cfg.get("watchdog_probe_url", "http://1.1.1.1"),
                timeout=timeout,
            )
        if mode == "http":
            return False, "http proxy not running"

    # SOCKS-only probe fallback
    ports = live_ports()
    if not ports:
        return False, "tunnel not running"
    socks_port = ports[0]
    user = cfg.get("socks_user") if cfg.get("socks_auth") else None
    passwd = cfg.get("socks_pass") if cfg.get("socks_auth") else None
    host = cfg.get("verify_probe_host", "example.com")
    port = int(cfg.get("verify_probe_port", 80))
    ok = _socks5_probe("127.0.0.1", socks_port, host, port,
                      user=user, passwd=passwd, timeout=float(timeout))
    return (ok, f"SOCKS {'OK' if ok else 'FAIL'} via 127.0.0.1:{socks_port}")


def warmup_probe(cfg: dict, timeout: float = 8.0) -> tuple[bool, str]:
    """
    Quick post-start connectivity check for both HTTP-proxy and SOCKS-only modes.
    """
    time.sleep(1.5)
    return probe_tunnel(cfg, timeout=int(timeout))

# ─────────────────────────────────────────────────────────────────────────────
# WATCHDOG
# ─────────────────────────────────────────────────────────────────────────────

_watchdog_thread: threading.Thread | None = None
_watchdog_stop   = threading.Event()
_scan_lock        = threading.Lock()


def _do_scan(profile_name: str, cfg: dict, reason: str,
             progress_cb=None) -> list[str]:
    """
    Internal scan + verify + merge.  Returns new IPs added to pool.
    Uses parallel verification (#3), score store (#1), pool cap (#5),
    auto scan mode (#11).
    """
    if not _scan_lock.acquire(blocking=False):
        flog(profile_name, "watchdog", "Scan already running, skipping")
        return []
    try:
        # #11: auto-select scan mode based on context
        mode = auto_scan_mode(profile_name, reason)
        flog(profile_name, "watchdog", f"Scan start ({reason}, mode={mode})")

        tmp = pdir(profile_name) / f"scan_{reason}.txt"
        new = run_dnscan(cfg, profile_name, mode=mode, output=tmp,
                         progress_cb=progress_cb)

        # If list-mode returns nothing, escalate to fast automatically (#11)
        if not new and mode == "list":
            flog(profile_name, "watchdog",
                 "list-mode found nothing, escalating to fast")
            if progress_cb:
                progress_cb("[auto-escalate] list mode found 0 — trying fast mode…")
            new = run_dnscan(cfg, profile_name, mode="fast", output=tmp,
                             progress_cb=progress_cb)

        # Parallel verify with integrity checks (#3 #9)
        if new and CLIENT_EXE.exists():
            verified = []
            def _cb(ip, passed):
                if progress_cb:
                    progress_cb(f"  verify {'✓' if passed else '✗'}  {ip}")
            verified = verify_resolvers_parallel(
                new, cfg,
                profile_name=profile_name,
                max_workers=cfg.get("verify_workers", 4),
                result_cb=_cb,
            )
            # SlipNet-like strictness: scan results must pass full E2E verification.
            if verified:
                new = verified
            elif cfg.get("verify_strict_required", True):
                if progress_cb:
                    progress_cb("[verify] 0 passed full E2E verification; strict mode rejecting candidates")
                new = []

        if new:
            # Build merged pool: new first, then surviving existing
            existing  = load_servers(profile_name)
            surviving = surviving_resolvers(
                existing,
                lambda ip: _dns_latency(ip, cfg["domain"]) < 9999,
            )
            merged    = merge_new_with_existing(new, surviving)

            # #5: enforce pool cap
            max_pool = cfg.get("resolver_max_pool", 12)
            merged   = enforce_pool_cap(profile_name, merged, max_pool)

            # #1: sort by score
            merged = sort_by_score(profile_name, merged)

            save_servers(profile_name, merged)
            flog(profile_name, "watchdog",
                 f"Scan done ({reason}): {len(new)} new → {len(merged)} total")
        else:
            flog(profile_name, "watchdog", f"Scan done ({reason}): nothing new")
        return new
    finally:
        _scan_lock.release()


def _watchdog_loop(profile_name: str):
    flog(profile_name, "watchdog", "Watchdog started")
    consec_fails = 0
    last_scan    = time.monotonic() + 180  # delay first periodic scan
    last_ka_check = time.monotonic()

    while not _watchdog_stop.is_set():
        try:
            cfg = load_cfg(profile_name)
            _watchdog_stop.wait(cfg["watchdog_check_interval"])
            if _watchdog_stop.is_set():
                break

            cfg = load_cfg(profile_name)

            restarted = restart_dead_instances(cfg, profile_name)
            if restarted:
                time.sleep(1)

            # ── 1. End-to-end probe through configured path ───────────────────
            probe_ok, probe_detail = probe_tunnel(
                cfg,
                timeout=cfg.get("watchdog_probe_timeout", 12),
            )
            flog(profile_name, "watchdog",
                 f"Probe {'OK' if probe_ok else 'FAIL'}: {probe_detail}")

            if probe_ok:
                consec_fails = 0
                servers = load_servers(profile_name)
                if servers:
                    check_resolvers(cfg["domain"], servers, profile_name=profile_name)
                    scores = load_scores(profile_name)

                    hijacked = [ip for ip in servers if scores.get(ip, {}).get("hijacked", False)]
                    if hijacked:
                        for ip in hijacked:
                            servers.remove(ip)
                            flog(profile_name, "watchdog", f"Removed hijacked resolver: {ip}")

                    prune_after = cfg.get("watchdog_prune_dead", 3)
                    to_prune = [ip for ip in servers if scores.get(ip, {}).get("consecutive_dead", 0) >= prune_after]
                    if to_prune:
                        for ip in to_prune:
                            servers.remove(ip)
                            flog(profile_name, "watchdog", f"Pruned dead resolver: {ip} ({prune_after} consecutive failures)")

                    if hijacked or to_prune:
                        save_servers(profile_name, servers)
                        if servers:
                            restart_tunnel(cfg, profile_name)

                    new_order = sort_by_score(profile_name, servers)
                    if new_order != servers:
                        save_servers(profile_name, new_order)

                    if time.monotonic() - last_ka_check > cfg["watchdog_check_interval"] * 5:
                        new_ka = compute_adaptive_keepalive(profile_name, servers, cfg)
                        old_ka = cfg.get("keep_alive_ms", 400)
                        if abs(new_ka - old_ka) / max(old_ka, 1) > 0.2:
                            cfg["keep_alive_ms"] = new_ka
                            save_cfg(profile_name, cfg)
                            flog(profile_name, "watchdog", f"Adaptive keep-alive: {old_ka}ms → {new_ka}ms")
                            restart_tunnel(cfg, profile_name)
                        last_ka_check = time.monotonic()

                    if needs_background_refresh(profile_name, servers, cfg.get("resolver_max_age_days", 7)):
                        flog(profile_name, "watchdog", "Pool >50% stale — triggering background list-mode refresh")
                        threading.Thread(target=_do_scan, args=(profile_name, cfg, "stale-refresh"), daemon=True).start()
            else:
                consec_fails += 1
                flog(profile_name, "watchdog", f"Fail #{consec_fails}/{cfg['watchdog_fail_threshold']}")

                if consec_fails == 1:
                    restarted = restart_dead_instances(cfg, profile_name)
                    if restarted:
                        flog(profile_name, "watchdog", f"Quick self-heal restarted {restarted} dead instance(s)")
                    else:
                        flog(profile_name, "watchdog", "Quick restart")
                        restart_tunnel(cfg, profile_name)
                    time.sleep(3)
                    _recheck, _detail = probe_tunnel(cfg, timeout=cfg.get("watchdog_probe_timeout", 12))
                    if _recheck:
                        flog(profile_name, "watchdog", f"Quick restart worked: {_detail}")
                        consec_fails = 0
                elif consec_fails < cfg["watchdog_fail_threshold"]:
                    servers = load_servers(profile_name)
                    if len(servers) > 1:
                        rotated = servers[1:] + servers[:1]
                        save_servers(profile_name, rotated)
                        flog(profile_name, "watchdog", f"Rotated resolvers, new primary: {rotated[0]}")
                        restart_tunnel(cfg, profile_name)

                if consec_fails >= cfg["watchdog_fail_threshold"]:
                    flog(profile_name, "watchdog", "Emergency rescan")
                    new = _do_scan(profile_name, cfg, "emergency")
                    consec_fails = 0
                    last_scan = time.monotonic()
                    if new:
                        restart_tunnel(cfg, profile_name)

            if time.monotonic() - last_scan >= cfg["watchdog_scan_interval"]:
                flog(profile_name, "watchdog", "Periodic rescan")
                periodic_new = _do_scan(profile_name, cfg, "periodic")
                last_scan = time.monotonic()
                if periodic_new:
                    restart_tunnel(cfg, profile_name)
        except Exception as e:
            flog(profile_name, "watchdog", f"Loop error: {e}")
            time.sleep(1)

    flog(profile_name, "watchdog", "Watchdog stopped")

def start_watchdog(cfg: dict, profile_name: str):
    global _watchdog_thread, _watchdog_stop
    if _watchdog_thread and _watchdog_thread.is_alive():
        return
    _watchdog_stop.clear()
    _watchdog_thread = threading.Thread(
        target=_watchdog_loop, args=(profile_name,), daemon=True)
    _watchdog_thread.start()


def stop_watchdog():
    global _watchdog_thread
    _watchdog_stop.set()
    if _watchdog_thread and _watchdog_thread.is_alive():
        _watchdog_thread.join(timeout=2)


def watchdog_running() -> bool:
    return _watchdog_thread is not None and _watchdog_thread.is_alive()

# ─────────────────────────────────────────────────────────────────────────────
# #10  HEADLESS MODE SUPPORT (SIGUSR1/SIGUSR2, PID file, status line)
# ─────────────────────────────────────────────────────────────────────────────

def write_pid_file():
    """Write current PID to state/slipstream.pid for process supervisors."""
    try:
        PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except Exception:
        pass

def remove_pid_file():
    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass

def headless_status_line(profile_name: str, cfg: dict) -> str:
    """
    Returns a compact status line for headless periodic output.
    Format:  [HH:MM:SS] alive=2/2 resolvers=8 avg_ms=320 probe=OK
    """
    ts         = datetime.now().strftime("%H:%M:%S")
    t_alive, t_total = tunnel_counts()
    servers    = load_servers(profile_name)
    scores     = load_scores(profile_name)
    entries    = [scores.get(ip, _default_score_entry()) for ip in servers]
    avg_ms     = int(sum(e["ewma_ms"] for e in entries) / len(entries)) if entries else 0
    avg_qps    = round(sum(e["qps_rate"] for e in entries) / len(entries), 2) if entries else 0
    ka_ms      = cfg.get("keep_alive_ms", 400)

    probe_str = "untested"
    ok, _ = probe_tunnel(cfg, timeout=5)
    probe_str = "OK" if ok else "FAIL"

    return (f"[{ts}] alive={t_alive}/{t_total}  resolvers={len(servers)}"
            f"  avg_ms={avg_ms}  qps_rate={avg_qps}  ka={ka_ms}ms  probe={probe_str}")


def install_headless_signals(profile_name: str, cfg: dict):
    """
    Install SIGUSR1 (status dump) and SIGUSR2 (force rescan) handlers.
    Only meaningful on Unix; silently skipped on Windows.
    """
    if platform.system() == "Windows":
        return

    def _usr1(sig, frame):
        print(headless_status_line(profile_name, cfg), flush=True)

    def _usr2(sig, frame):
        print("[SIGUSR2] Forcing immediate rescan…", flush=True)
        threading.Thread(
            target=_do_scan,
            args=(profile_name, load_cfg(profile_name), "signal"),
            daemon=True,
        ).start()

    try:
        signal.signal(signal.SIGUSR1, _usr1)
        signal.signal(signal.SIGUSR2, _usr2)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────────────────
# HIGH-LEVEL START/STOP (used by UI)
# ─────────────────────────────────────────────────────────────────────────────

def start_all(cfg: dict, profile_name: str) -> dict:
    """
    Start tunnel + optional HTTP proxy + optional system proxy + optional watchdog.
    Returns result dict from start_tunnel plus proxy/system/warmup info.
    """
    _register_proxy_guard()
    result = start_tunnel(cfg, profile_name)
    if result["started"] > 0:
        if cfg.get("enable_http_proxy", True):
            start_proxy(cfg)
            result["proxy"] = True
            if cfg.get("system_proxy"):
                ok = set_system_proxy(True, cfg["http_proxy_port"])
                result["system_proxy"] = ok
        else:
            result["proxy"] = False
            result["system_proxy"] = False
        if cfg.get("watchdog_enabled") and not watchdog_running():
            start_watchdog(cfg, profile_name)
            result["watchdog"] = True
    return result


def stop_all(cfg: dict):
    stop_tunnel()
    stop_proxy()
    if watchdog_running():
        stop_watchdog()
    if cfg.get("enable_http_proxy", True) and cfg.get("system_proxy"):
        restore_system_proxy_defaults()
    remove_pid_file()
