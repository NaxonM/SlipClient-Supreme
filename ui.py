"""
ui.py  —  slipstream-tunnel interactive UI
All menus, prompts, display. Run this file directly.
    python ui.py
    python ui.py --profile shatel
    python ui.py --no-menu
"""

import argparse, os, platform, re, signal, subprocess, sys, threading, time
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import core
import ui_runtime
import ui_resolver_maintenance

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────
try:
    import colorama; colorama.init()
except ImportError:
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"
M="\033[95m"; DIM="\033[2m"; BO="\033[1m"; RS="\033[0m"

def _c(*parts):
    codes = [p for p in parts if isinstance(p, str) and p.startswith("\033")]
    text  = next((p for p in parts if not (isinstance(p,str) and p.startswith("\033"))),"")
    return "".join(codes) + str(text) + RS

def pill(label, color): return _c(f" {label} ", color, BO)

def clr(): os.system("cls" if platform.system() == "Windows" else "clear")
def hr(w=56): print(f"  {_c('─'*w, DIM)}")
def section(title): print(); print(f"  {_c('▸',C,BO)} {_c(title,BO)}"); hr(); print()
def pause(): input(f"\n  {_c('Press Enter to continue…', DIM)}")
def ok(m):   print(f"  {_c('[✓]',G)} {m}")
def warn(m): print(f"  {_c('[!]',Y)} {m}")
def err(m):  print(f"  {_c('[x]',R)} {m}")
def info(m): print(f"  {_c('[i]',C)} {m}")

def ask(prompt: str, default: str = "") -> str:
    hint = f" {_c(f'[{default}]', DIM)}" if default else ""
    return input(f"  {_c(prompt,C)}{hint} : ").strip() or default

def ask_bool(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    val  = ask(f"{prompt} ({hint})").lower()
    return (val in ("y","yes")) if val else default

def ask_int(prompt: str, default: int, lo: int = 1, hi: int = 9999) -> int:
    while True:
        try:
            v = int(ask(prompt, str(default)))
            if lo <= v <= hi: return v
        except ValueError: pass
        print(f"  {_c(f'Enter a number {lo}–{hi}', Y)}")


def ask_domain(prompt: str, default: str = "") -> str:
    while True:
        v = ask(prompt, default).strip().lower()
        if re.match(r"^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", v):
            return v
        warn("Invalid domain format (example: t.example.com).")


def ask_timeout_str(prompt: str, default: str = "1s") -> str:
    while True:
        v = ask(prompt, default).strip().lower()
        if re.match(r"^\d+(ms|s)$", v):
            return v
        warn("Timeout must be like 800ms or 2s.")


def ask_url_http(prompt: str, default: str) -> str:
    while True:
        v = ask(prompt, default).strip()
        if re.match(r"^https?://[^\s/$.?#].[^\s]*$", v):
            return v
        warn("Invalid URL. Example: http://1.1.1.1")


def ask_country_code(prompt: str, default: str = "ir") -> str:
    while True:
        v = ask(prompt, default).strip().lower()
        if re.match(r"^[a-z]{2}$", v):
            return v
        warn("Country code must be 2 letters (e.g. ir, cn, ru).")


def fmt_rate(bps: float) -> str:
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    x = float(max(0.0, bps))
    idx = 0
    while x >= 1024 and idx < len(units)-1:
        x /= 1024
        idx += 1
    return f"{x:.1f} {units[idx]}"


def fmt_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(max(0, n))
    idx = 0
    while x >= 1024 and idx < len(units)-1:
        x /= 1024
        idx += 1
    return f"{x:.1f} {units[idx]}"

# ─────────────────────────────────────────────────────────────────────────────
# STATUS BAR
# ─────────────────────────────────────────────────────────────────────────────

def _status_bar(cfg: dict) -> str:
    t_alive, t_total = core.tunnel_counts()
    t_on = core.tunnel_running()
    p_on = core.proxy_running()
    w_on = core.watchdog_running()
    sys_on, _ = core.get_system_proxy()
    if not t_on and not p_on and not w_on:
        return pill("STOPPED", R)
    parts = []
    if t_on:
        label = f"TUNNEL {t_alive}/{t_total}" if t_total > 1 else "TUNNEL"
        parts.append(pill(label, G))
    if p_on:  parts.append(pill("HTTP PROXY", G))
    if w_on:  parts.append(pill("WATCHDOG", G))
    if sys_on and cfg.get("system_proxy"): parts.append(pill("SYS PROXY", G))
    return "  ".join(parts)


def print_header(active: str, cfg: dict):
    clr()
    servers = core.load_servers(active)
    print()
    print("  " + _c("  _____ ____   ____      _____                                  ", C, BO))
    print("  " + _c(r" / ____/ __ \ / __ \    / ___/___  ______  _____ ___  ___      ", C, BO))
    print("  " + _c(r"/ / __/ /_/ // /_/ /____ \__ \/ / / / __ \/ ___/ _ \/ _ \     ", C, BO))
    print("  " + _c(r"/ /_/ / ____// ____/____/___/ / /_/ / /_/ / /  /  __/  __/     ", C, BO))
    print("  " + _c(r"\____/_/    /_/          /____/\__,_/ .___/_/   \___/\___/      ", C, BO))
    print("  " + _c("                                   /_/  SSC-Supreme", C, BO) + "  " + _c(platform.system(), DIM))
    print()
    hr()
    print(f"  {_c('Profile', DIM)}  {_c(active, M, BO)}")
    print(f"  {_c('Domain ', DIM)}  {_c(cfg['domain'], C)}"
          f"   {_c('resolvers:', DIM)}{_c(len(servers), BO)}"
          f"   {_c('HTTP:', DIM)}{_c(cfg['http_proxy_port'], BO)}"
          f"   {_c('instances:', DIM)}{_c(cfg.get('multi_instance',1), BO)}"
          f"   {_c('fo:', DIM)}{_c(cfg.get('instance_failover_count',1), BO)}"
          f"   {_c('keep-alive:', DIM)}{_c(cfg.get('keep_alive_ms',400), BO)}ms")
    if cfg.get("socks_auth"):
        print(f"  {_c('Auth   ', DIM)}  {_c(cfg['socks_user'], Y)}"
              f"  {_c('(password set)', DIM)}")
    print()
    print(f"  {_status_bar(cfg)}")
    hr(); print()

# ─────────────────────────────────────────────────────────────────────────────
# START HELPER  (#8 warm-up probe)
# ─────────────────────────────────────────────────────────────────────────────

def _start_and_report(cfg: dict, profile_name: str):
    result = core.start_all(cfg, profile_name)
    print()

    # Hard failures: nothing started at all
    if result["started"] == 0:
        hard_msgs = {
            "no_resolvers": "No resolvers in pool — run a scan first (s).",
            "no_client":    f"slipstream-client not found: {core.CLIENT_EXE}",
        }
        hard = hard_msgs.get(result.get("error", ""))
        if hard:
            err(hard)
            return
        err("Failed to start any tunnel instances.")
        print()
        # Show per-instance errors, full width, deduplicated
        shown = set()
        for e_line in result.get("instance_errors", []):
            # Strip "instance N (port X): " prefix to show just the binary output
            msg = e_line.split(": ", 1)[-1].strip() if ": " in e_line else e_line
            for line in msg.splitlines():
                line = line.strip()
                if line and line not in shown:
                    shown.add(line)
                    if "ERROR" in line or "error" in line.lower():
                        print(f"  {_c('│', R)} {_c(line, R)}")
                    elif "WARN" in line:
                        print(f"  {_c('│', Y)} {_c(line, DIM)}")
                    else:
                        print(f"  {_c('│', DIM)} {line}")
        print()
        # Diagnose common causes from the error text
        all_errors = " ".join(result.get("instance_errors", []))
        if "10013" in all_errors or "forbidden by its access permissions" in all_errors:
            warn("Port binding was blocked by Windows (error 10013 = WSAEACCES).")
            print(f"  {_c('Fix options:', BO)}")
            port = cfg.get('listen_port', 1080)
            print(f"    1) Try a different port — change Internal SOCKS5 port in Configure")
            print(f"       (well-known ports like 1080, 1081, 1090 are usually allowed)")
            print(f"    2) Run as Administrator")
            print(f"    3) Windows Defender Firewall may be blocking port {port} for this app")
        elif "in use" in all_errors.lower() or "10048" in all_errors:
            warn("Port already in use — something else is listening on that port.")
            print(f"  Change Internal SOCKS5 port in {_c('Configure', C)} (c from main menu).")
        elif "certificate" in all_errors.lower() or "cert" in all_errors.lower():
            warn("Certificate error — check cert path in Configure, or leave blank to disable pinning.")
        return

    # Partial or full success
    for inst in result.get("instances", []):
        ok(f"Instance {inst.get('index',0)+1}  PID={inst['pid']}"
           f"  port={inst['port']}  resolvers={inst['resolvers']}")
    # Show any instances that failed to start
    for e_line in result.get("instance_errors", []):
        warn(f"  {e_line[:100]}")

    if result.get("proxy"):
        ok(f"HTTP proxy  ->  127.0.0.1:{cfg['http_proxy_port']}")
    else:
        info("SOCKS-only mode enabled (HTTP/system proxy disabled)")
        ports = core.live_ports()
        if ports:
            ok(f"SOCKS5 endpoints -> " + ", ".join(f"127.0.0.1:{p}" for p in ports))
    if cfg.get("enable_http_proxy", True) and cfg.get("system_proxy"):
        if result.get("system_proxy"):
            _sp_name = {"Darwin": "macOS", "Linux": "Linux"}.get(platform.system(), "Windows")
            ok(f"{_sp_name} system proxy enabled")
        else:
            _hint = {"Darwin": "System Settings → Network → [interface] → Proxies",
                     "Linux":  "set HTTP_PROXY=http://127.0.0.1:{cfg['http_proxy_port']} in your shell"
                    }.get(platform.system(), "Windows Settings → Proxy")
            warn(f"System proxy could not be set automatically — configure manually: {_hint}")
    if result.get("watchdog"):
        ok(f"Watchdog active  (probing every {cfg['watchdog_check_interval']}s)")

    # #8: Warm-up connectivity probe
    print()
    sys.stdout.write(f"  {_c('[~]', C)} Warming up tunnel…"); sys.stdout.flush()
    warmup_ok, warmup_detail = core.warmup_probe(cfg, timeout=8.0)
    if warmup_ok:
        print(f"\r  {_c('[✓]',G)} Tunnel ready  {_c(warmup_detail, DIM)}")
    else:
        print(f"\r  {_c('[~]',Y)} Tunnel started — not yet fully ready")
        print(f"     {_c(warmup_detail, DIM)}")
        tip = 'Give it 10–15 seconds, then try your browser.' if cfg.get('enable_http_proxy', True) else 'Give it 10–15 seconds, then connect your app to local SOCKS5.'
        print(f"     {_c(tip, DIM)}")

# ─────────────────────────────────────────────────────────────────────────────
# SCAN HELPER  (#3 parallel verify, #9 integrity check)
# ─────────────────────────────────────────────────────────────────────────────

def run_scan_interactive(profile_name: str, cfg: dict,
                         skip_verify_prompt: bool = False) -> list:
    m = cfg["scan_mode"]
    print(f"\n  {_c('→',C)}  Scanning  "
          f"mode={_c(m,M,BO)}  workers={_c(cfg['scan_workers'],BO)}  "
          f"timeout={_c(cfg['scan_timeout'],BO)}  "
          f"threshold={_c(cfg['scan_threshold'],BO)}%\n")

    # Filtered progress: show found IPs, errors, and periodic summaries.
    # Suppress per-probe noise (individual DNS probe lines from dnscan).
    _last_summary = [time.monotonic()]
    _found_count  = [0]

    def _scan_progress(line: str):
        l = line.strip()
        if not l:
            return
        if (re.match(r"^\d+\.\d+\.\d+\.\d+", l)
                or l.startswith("[")
                or "error" in l.lower()
                or "warning" in l.lower()
                or "done" in l.lower()
                or "found" in l.lower()
                or "scann" in l.lower()):
            if re.match(r"^\d+\.\d+\.\d+\.\d+", l):
                _found_count[0] += 1
                sys.stdout.write(f"\r  {_c('→',C)} Found {_c(_found_count[0], G, BO)} resolver(s)\u2026   ")
                sys.stdout.flush()
            else:
                sys.stdout.write("\r" + " " * 70 + "\r")
                print(f"  {l}")
            return
        now = time.monotonic()
        if now - _last_summary[0] >= 3.0:
            _last_summary[0] = now
            sys.stdout.write(f"\r  {_c('…',DIM)} {l[:60]:<60}")
            sys.stdout.flush()

    candidates = core.run_dnscan(cfg, profile_name, progress_cb=_scan_progress)
    sys.stdout.write("\r" + " " * 70 + "\r")
    sys.stdout.flush()

    if not candidates:
        print()
        warn("No candidates found from scan.")
        if m == "list":
            info("Tip: 'list' mode only tests ~170 known servers.")
            info("Try 'fast' mode to scan broader IP ranges.")
        return []

    print(f"\n  {_c(len(candidates), BO)} candidate(s) passed dnscan benchmark.")

    if skip_verify_prompt:
        return candidates

    return ui_resolver_maintenance.verify_candidates_interactive(
        core,
        profile_name,
        cfg,
        candidates,
        {
            "ask_bool": ask_bool,
            "warn": warn,
            "_c": _c,
            "colors": {"G": G, "Y": Y, "R": R, "C": C, "BO": BO, "DIM": DIM},
        },
    )

# ─────────────────────────────────────────────────────────────────────────────
# MENU: SCAN
# ─────────────────────────────────────────────────────────────────────────────

def menu_scan(profile_name: str, cfg: dict):
    clr()
    section(f"Scan for Resolvers  ·  {profile_name}")
    print(f"  {_c('Domain',DIM)}  {_c(cfg['domain'],C,BO)}"
          f"   {_c('Country:',DIM)} {_c(cfg['country'],C,BO)}\n")
    print(f"  {_c('Scan modes:',BO)}")
    print(f"    {_c('list  ',M)}  ~170 known servers — fastest, good starting point")
    print(f"    {_c('fast  ',M)}  samples .1 / .53 / .254 per subnet")
    print(f"    {_c('medium',M)}  7 IPs per subnet")
    print(f"    {_c('all   ',M)}  every IP  (~1–23 min depending on workers)")
    print(f"  {_c('Note:',DIM)} list mode auto-escalates to fast if 0 results found.\n")

    cfg["scan_mode"]      = ask("Mode",               cfg["scan_mode"])
    cfg["scan_workers"]   = ask_int("Workers",         cfg["scan_workers"], 100, 16000)
    cfg["scan_timeout"]   = ask_timeout_str("Timeout  (e.g. 1s)", cfg["scan_timeout"])
    cfg["scan_threshold"] = ask_int("Benchmark threshold %", cfg["scan_threshold"], 1, 100)
    core.save_cfg(profile_name, cfg)

    verified = run_scan_interactive(profile_name, cfg)
    if not verified: pause(); return

    existing = core.load_servers(profile_name)
    merged   = list(dict.fromkeys(verified + existing))

    # #5: enforce pool cap, #1: sort by score
    max_pool = cfg.get("resolver_max_pool", 12)
    if len(merged) > max_pool:
        merged = core.enforce_pool_cap(profile_name, merged, max_pool)
        info(f"Pool capped at {max_pool} resolvers (best by score).")
    merged = core.sort_by_score(profile_name, merged)
    core.save_servers(profile_name, merged)

    print()
    ok(f"Resolver pool: {_c(len(merged),BO)} total  ({len(verified)} new, {len(existing)} kept)")
    print()
    if ask_bool("Start tunnel now?", default=True):
        _start_and_report(cfg, profile_name)
    pause()

# ─────────────────────────────────────────────────────────────────────────────
# MENU: HEALTH CHECK  (#1 scores, #6 adaptive KA suggestion, #2 CPS)
# ─────────────────────────────────────────────────────────────────────────────

def menu_health(profile_name: str, cfg: dict):
    servers = core.load_servers(profile_name)
    if not servers: warn("No resolvers in pool."); pause(); return

    print(f"\n  Testing {_c(len(servers),BO)} resolver(s)...\n")
    results = core.check_resolvers(cfg["domain"], servers, profile_name=profile_name)
    summary = core.get_score_summary(profile_name, servers)

    print(f"  {'IP':<22}  {'Latency':>8}  {'QPS%':>5}  {'Score':>6}  {'Age':>4}  Note")
    print(f"  {'─'*22}  {'─'*8}  {'─'*5}  {'─'*6}  {'─'*4}  {'─'*10}")
    for s in summary:
        ip = s["ip"]
        ms = results.get(ip, 9999)
        if   ms < 300:  lat_str = _c(f"{ms}ms", G, BO)
        elif ms < 1000: lat_str = _c(f"{ms}ms", Y)
        elif ms < 9999: lat_str = _c(f"{ms}ms", R)
        else:           lat_str = _c("DEAD", R, BO)
        qps_col = G if s["qps_rate"] > 0.8 else (Y if s["qps_rate"] > 0.5 else R)
        qps_str = _c(f"{s['qps_rate']*100:.0f}%", qps_col)
        note    = _c("HIJACKED", R, BO) if s["hijacked"] else \
                  (_c("stale", Y) if s["age_days"] > cfg.get("resolver_max_age_days",7) else "")
        scr_str = _c(f"{s['score']:.1f}", C)
        age_str = _c(str(s["age_days"]) + "d", DIM)
        print(f"  {ip:<22}  {lat_str:>8}  {qps_str:>5}  {scr_str:>6}  {age_str:>4}  {note}")

    alive = sum(1 for ms in results.values() if ms < 9999)
    color = G if alive == len(servers) else (Y if alive > 0 else R)
    print(f"\n  Alive: {_c(alive,color,BO)} / {len(servers)}")

    # #6: Adaptive keep-alive suggestion
    if servers:
        new_ka = core.compute_adaptive_keepalive(profile_name, servers, cfg)
        old_ka = cfg.get("keep_alive_ms", 400)
        if abs(new_ka - old_ka) / max(old_ka, 1) > 0.2:
            print()
            info(f"Adaptive keep-alive suggests {_c(new_ka, BO)}ms "
                 f"(current: {old_ka}ms) based on pool health.")
            if ask_bool(f"Apply {new_ka}ms keep-alive now?", default=False):
                cfg["keep_alive_ms"] = new_ka
                core.save_cfg(profile_name, cfg)
                if core.tunnel_running():
                    core.restart_tunnel(cfg, profile_name)
                ok(f"Keep-alive updated to {new_ka}ms.")

    if core.proxy_running():
        print()
        url     = cfg.get("watchdog_probe_url", "http://1.1.1.1")
        timeout = cfg.get("watchdog_probe_timeout", 12)
        info(f"Probing end-to-end -> {_c(url,C)}  (timeout {timeout}s)...")
        probe_ok, detail = core.probe_tunnel(cfg, timeout=timeout)
        if probe_ok:
            ok(f"Proxy probe OK  {_c(detail, DIM)}")
        else:
            err(f"Proxy probe failed:  {_c(detail, Y)}")
            if "google" in url.lower() or url.lower().startswith("https"):
                warn(f"Probe URL is {_c(url, Y)} — HTTPS targets reject plain HTTP.")
                ok(f"Fix: change probe URL to {_c('http://1.1.1.1', G, BO)}")
            else:
                print(f"  {_c('Common causes:', DIM)}")
                print(f"    - Probe timeout {timeout}s too short -> increase to 25-30s")
                print(f"    - SOCKS5 auth mismatch -> Configure -> Auth")
                print(f"    - Tunnel server down -> check your VPS")

    # #2: Instance-level CPS stats
    inst_info = core.tunnel_instance_info()
    if inst_info:
        print()
        print(f"  {_c('Instance load:', DIM)}")
        for i in inst_info:
            status = _c("alive", G) if i["alive"] else _c("dead", R)
            print(f"    inst {i['index']+1}  port={i['port']}  "
                  f"cps={_c(i['cps'], BO)}  {status}")

    core.flog(profile_name, "health", f"Health check: {alive}/{len(servers)} alive")
    pause()




# ─────────────────────────────────────────────────────────────────────────────
# MENU: RESOLVER POOL  (#1 scores display, #5 cap, #12 export)
# ─────────────────────────────────────────────────────────────────────────────

def menu_resolvers(profile_name: str, cfg: dict):
    while True:
        clr()
        section(f"Resolver Pool  ·  {profile_name}")
        servers = core.load_servers(profile_name)

        if not servers:
            print(f"  {_c('(empty — run a scan first)',DIM)}")
        else:
            summary = core.get_score_summary(profile_name, servers)
            print(f"  {'#':<4} {'IP':<22} {'ms':>6} {'QPS%':>5} {'Score':>6} {'Age':>4}  Note")
            print(f"  {'─'*4} {'─'*22} {'─'*6} {'─'*5} {'─'*6} {'─'*4}  {'─'*8}")
            for idx, s in enumerate(summary, 1):
                tag     = _c(" <- primary", G) if idx == 1 else ""
                note    = _c("HIJACKED", R, BO) if s["hijacked"] else \
                          (_c("stale", Y) if s["age_days"] > cfg.get("resolver_max_age_days",7) else "")
                qps_col = G if s["qps_rate"] > 0.8 else (Y if s["qps_rate"] > 0.5 else R)
                qps_str2 = _c(f"{s['qps_rate']*100:.0f}%", qps_col)
                scr_str2 = _c(f"{s['score']:.1f}", C)
                age_str2 = _c(str(s["age_days"]) + "d", DIM)
                print(f"  {str(idx)+')':<4} {s['ip']:<22}"
                      f" {_c(s['ewma_ms'],BO):>6}"
                      f" {qps_str2:>5}"
                      f" {scr_str2:>6}"
                      f" {age_str2:>4}"
                      f"  {note}{tag}")
            print(f"\n  {_c(len(servers),C,BO)} resolver(s)  cap={cfg.get('resolver_max_pool',12)}")

        print()
        print(f"  {_c('a',C)})  Add manually")
        print(f"  {_c('r',C)})  Remove one")
        print(f"  {_c('c',C)})  Clear pool")
        print(f"  {_c('e',C)})  Open in Notepad")
        print(f"  {_c('x',C)})  Export as slipnet:// URI  (share with others)")
        print(f"  {_c('v',C)})  E2E verify pool  (prompt to remove failures)")
        print(f"  {_c('0',DIM)})  Back")
        print()

        choice = input(f"  {_c('Choice:',C)} ").strip().lower()

        if choice == "0": break
        elif choice == "a":
            ip = ask("Resolver IP")
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                servers.insert(0, ip); core.save_servers(profile_name, servers)
                ok(f"Added {ip}  {_c('(set as primary — first in list)', DIM)}")
            else: err("Invalid IP format")
            pause()
        elif choice == "r":
            ip = ask("IP to remove")
            if ip in servers: servers.remove(ip); core.save_servers(profile_name, servers); ok("Removed")
            else: warn("Not found in pool")
            pause()
        elif choice == "c":
            if ask_bool("Clear all resolvers?", False):
                core.save_servers(profile_name, []); ok("Pool cleared")
            pause()
        elif choice == "e":
            core.srvfile(profile_name).touch()
            _sys = platform.system()
            if _sys == "Windows":
                subprocess.run(["notepad.exe", str(core.srvfile(profile_name))])
            elif _sys == "Darwin":
                subprocess.run(["open", "-t", str(core.srvfile(profile_name))])
            else:
                editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"
                subprocess.run([editor, str(core.srvfile(profile_name))])
            if core.tunnel_running() and core._running_prof == profile_name:
                core.restart_tunnel(cfg, profile_name); ok("Tunnel reloaded")
            pause()
        elif choice == "v":
            ui_resolver_maintenance.verify_existing_pool(core, profile_name, cfg, {
                "warn": warn, "info": info, "ok": ok, "ask_bool": ask_bool,
                "_c": _c, "colors": {"G": G, "Y": Y, "BO": BO}
            })
            pause()
        elif choice == "x":
            # #12: Export slipnet:// URI
            if not servers:
                warn("No resolvers to export."); pause(); continue
            n = ask_int("How many top resolvers to include?",
                        min(len(servers), 10), 1, len(servers))
            uri = core.build_slipnet(profile_name, cfg, max_resolvers=n)
            print()
            ok(f"slipnet:// URI ({n} resolvers):")
            print(f"\n  {_c(uri, C, BO)}\n")
            info("Share this with users on the same ISP/network.")
            info("They can import it via Profiles -> Import slipnet:// URI")
            pause()

# ─────────────────────────────────────────────────────────────────────────────
# MENU: CONFIGURE  (#5 pool cap, #6 adaptive KA, #3 verify workers, #4 age)
# ─────────────────────────────────────────────────────────────────────────────

def menu_configure(profile_name: str, cfg: dict):
    clr()
    section(f"Configure  ·  {profile_name}")

    print(f"  {_c('Tunnel Server',BO)}\n")
    cfg["domain"]        = ask_domain("Tunnel domain",              cfg["domain"])
    cfg["cert_path"]     = ask("Cert path  (blank = none)",  cfg.get("cert_path",""))
    cfg["keep_alive_ms"] = ask_int("Keep-alive interval ms", cfg.get("keep_alive_ms",400), 50, 10000)

    print(f"\n  {_c('Slipstream Engine',BO)}\n")
    cfg["authoritative_mode"] = ask_bool(
        "Authoritative mode?",
        bool(cfg.get("authoritative_mode", False)))

    print(f"\n  {_c('Python Socket Tuning',BO)}  {_c('(client-binary independent)',DIM)}\n")
    cfg["low_latency_mode"] = ask_bool(
        "Enable low-latency socket tuning (TCP_NODELAY + keepalive)?",
        bool(cfg.get("low_latency_mode", True)))

    print(f"\n  {_c('Adaptive Keep-Alive',BO)}  "
          f"{_c('(auto-adjusts keep-alive based on tunnel health)',DIM)}\n")
    cfg["keep_alive_adaptive"] = ask_bool(
        "Enable adaptive keep-alive?", bool(cfg.get("keep_alive_adaptive", True)))
    if cfg["keep_alive_adaptive"]:
        cfg["keep_alive_min_ms"] = ask_int("Min keep-alive ms", cfg.get("keep_alive_min_ms",200), 50, 1000)
        cfg["keep_alive_max_ms"] = ask_int("Max keep-alive ms", cfg.get("keep_alive_max_ms",2000), 500, 10000)

    print(f"\n  {_c('Auth',BO)}  {_c('(only if the server requires login)',DIM)}\n")
    cfg["socks_auth"] = ask_bool("Server requires username/password?", bool(cfg.get("socks_auth")))
    if cfg["socks_auth"]:
        cfg["socks_user"] = ask("Username", cfg.get("socks_user",""))
        cfg["socks_pass"] = ask("Password", cfg.get("socks_pass",""))
    else:
        cfg["socks_user"] = cfg["socks_pass"] = ""

    print(f"\n  {_c('Local Ports',BO)}\n")
    cfg["listen_port"]     = ask_int("Internal SOCKS5 base port",
                                      cfg["listen_port"], 1024, 65000)
    cfg["enable_http_proxy"] = ask_bool(
        "Enable local HTTP proxy bridge? (disable for SOCKS-only mode)",
        bool(cfg.get("enable_http_proxy", True)))
    if cfg["enable_http_proxy"]:
        cfg["http_proxy_port"] = ask_int(
            "HTTP proxy port  (enter this in browser / OS settings)",
            cfg["http_proxy_port"], 1024, 65000)
        cfg["domestic_bypass_enabled"] = ask_bool(
            "Bypass domestic IR domains/IPs directly (ir.domains + ir.cidr)?",
            bool(cfg.get("domestic_bypass_enabled", True)))
    else:
        cfg["system_proxy"] = False

    print(f"\n  {_c('Redundancy',BO)}\n")
    cfg["multi_instance"] = ask_int(
        "Parallel tunnel instances  (1 = single, 2-4 = redundancy)",
        cfg.get("multi_instance",1), 1, 8)

    print(f"\n  {_c('System Proxy',BO)}\n")
    _os_lbl = {"Darwin": "macOS", "Linux": "Linux"}.get(platform.system(), "Windows")
    if not cfg.get("enable_http_proxy", True):
        info("System proxy requires HTTP proxy bridge; disabled in SOCKS-only mode.")
        cfg["system_proxy"] = False
    elif platform.system() == "Linux":
        info("Linux: system proxy cannot be set automatically. Use shell env vars.")
        cfg["system_proxy"] = False
    else:
        cfg["system_proxy"] = ask_bool(f"Auto-set as {_os_lbl} system proxy on start?",
                                        bool(cfg.get("system_proxy")))

    print(f"\n  {_c('Pool Management',BO)}\n")
    cfg["resolver_max_pool"] = ask_int(
        "Max resolvers in pool  (12 recommended — concentrates keep-alive traffic)",
        cfg.get("resolver_max_pool", 12), 1, 200)
    cfg["resolver_max_age_days"] = ask_int(
        "Flag resolvers as stale after N days  (0 = never)",
        cfg.get("resolver_max_age_days", 7), 0, 365)

    print(f"\n  {_c('Scan Defaults',BO)}\n")
    cfg["country"]        = ask_country_code("Country code  (ir, cn, ru...)",  cfg["country"])
    cfg["scan_mode"]      = ask("Default scan mode",              cfg["scan_mode"])
    cfg["scan_workers"]   = ask_int("Default workers",            cfg["scan_workers"], 100, 16000)
    cfg["scan_timeout"]   = ask_timeout_str("Default timeout  (e.g. 1s)",    cfg["scan_timeout"])
    cfg["scan_threshold"] = ask_int("Default benchmark threshold%",
                                     cfg["scan_threshold"], 1, 100)
    cfg["scan_target_count"] = ask_int("Resolver candidates from resolvers.txt",
                                        cfg.get("scan_target_count", 7000), 100, 20000)
    cfg["scan_burst_count"] = ask_int("Burst filter query count", cfg.get("scan_burst_count", 6), 0, 30)
    cfg["scan_burst_workers"] = ask_int("Burst filter workers", cfg.get("scan_burst_workers", 64), 1, 512)
    cfg["verify_workers"] = ask_int(
        "Parallel verify workers  (4 recommended)",
        cfg.get("verify_workers", 4), 1, 16)
    cfg["verify_timeout"] = ask_int(
        "Verify timeout (s)",
        cfg.get("verify_timeout", 14), 4, 60)
    cfg["verify_sample_count"] = ask_int(
        "How many scan candidates to E2E verify",
        cfg.get("verify_sample_count", 20), 1, 500)
    cfg["dns_precheck_mode"] = ask(
        "DNS precheck mode (quick/full)",
        cfg.get("dns_precheck_mode", "quick")).lower() or "quick"
    cfg["watchdog_probe_mode"] = ask(
        "Watchdog probe mode (auto/http/socks)",
        cfg.get("watchdog_probe_mode", "auto")).lower() or "auto"
    cfg["instance_failover_count"] = ask_int(
        "Per-instance resolver failovers (extra after primary)",
        cfg.get("instance_failover_count", 1), 0, 8)
    cfg["verify_relaxed_retry"] = ask_bool(
        "Retry small subset when strict verify finds none?",
        bool(cfg.get("verify_relaxed_retry", True)))
    cfg["verify_relaxed_count"] = ask_int(
        "Relaxed retry count",
        cfg.get("verify_relaxed_count", 6), 1, 40)
    cfg["monitor_refresh_sec"] = ask_int(
        "Live monitor refresh interval (s)",
        cfg.get("monitor_refresh_sec", 2), 1, 10)

    core.save_cfg(profile_name, cfg)
    print(); ok("Configuration saved.")
    pause()

# ─────────────────────────────────────────────────────────────────────────────
# MENU: WATCHDOG
# ─────────────────────────────────────────────────────────────────────────────

def menu_watchdog(profile_name: str, cfg: dict):
    while True:
        clr()
        section(f"Watchdog  ·  {profile_name}")
        ci  = cfg["watchdog_check_interval"]
        si  = cfg["watchdog_scan_interval"]
        ft  = cfg["watchdog_fail_threshold"]
        url = cfg.get("watchdog_probe_url", "http://1.1.1.1")
        pt  = cfg.get("watchdog_probe_timeout", 12)
        pd  = cfg.get("watchdog_prune_dead", 3)
        running = core.watchdog_running()

        print(f"  Status             {pill('RUNNING',G) if running else pill('STOPPED',R)}")
        print()
        print(f"  {_c('Probe interval  ',DIM)}  every {_c(f'{ci}s',BO)}")
        print(f"  {_c('Probe URL       ',DIM)}  {_c(url,BO)}")
        print(f"  {_c('Probe timeout   ',DIM)}  {_c(f'{pt}s',BO)}"
              f"  {_c('<- increase if probe fails but tunnel works',DIM)}")
        print(f"  {_c('Probe mode      ',DIM)}  {_c(cfg.get('watchdog_probe_mode','auto'),BO)}")
        print(f"  {_c('Periodic rescan ',DIM)}  every {_c(f'{si//3600}h {(si%3600)//60}m',BO)}")
        print(f"  {_c('Emergency after ',DIM)}  {_c(ft,BO)} consecutive probe failures")
        print(f"  {_c('Prune dead after',DIM)}  {_c(pd,BO)} consecutive dead health checks"
              f"  {_c('(0 = keep forever)',DIM)}")
        print(f"  {_c('Adaptive KA     ',DIM)}  "
              f"{'enabled' if cfg.get('keep_alive_adaptive',True) else 'disabled'}"
              f"  {_c('(auto-tunes keep-alive interval)',DIM)}")
        print(f"  {_c('Stale refresh   ',DIM)}  after {_c(cfg.get('resolver_max_age_days',7),BO)} days"
              f"  {_c('(silent background scan)',DIM)}")
        print()
        print(f"  {_c('Recovery sequence:',DIM)}  restart -> rotate resolvers -> emergency rescan")
        print()

        toggle = "Stop watchdog" if running else "Start watchdog"
        print(f"  {_c('1',C)})  {toggle}")
        print(f"  {_c('2',C)})  Change settings")
        print(f"  {_c('3',C)})  View log  (last 40 lines)")
        print(f"  {_c('4',C)})  Probe now  (test end-to-end)")
        print(f"  {_c('5',C)})  Force emergency rescan")
        print(f"  {_c('0',DIM)})  Back")
        print()

        c = input(f"  {_c('Choice:',C)} ").strip()
        if c == "0": break

        elif c == "1":
            if running:
                core.stop_watchdog()
                cfg["watchdog_enabled"] = False; core.save_cfg(profile_name, cfg)
                ok("Watchdog stopped.")
            else:
                cfg["watchdog_enabled"] = True; core.save_cfg(profile_name, cfg)
                core.start_watchdog(cfg, profile_name)
                ok(f"Watchdog started  (probe every {ci}s)")
            pause()

        elif c == "2":
            print()
            cfg["watchdog_check_interval"] = ask_int("Probe interval (s)", ci, 10, 3600)
            cfg["watchdog_scan_interval"]  = ask_int("Periodic rescan (s)", si, 300, 86400)
            cfg["watchdog_fail_threshold"] = ask_int("Emergency threshold (fails)", ft, 1, 20)
            cfg["watchdog_probe_url"]      = ask_url_http("Probe URL", url)
            cfg["watchdog_probe_timeout"]  = ask_int(
                "Probe timeout (s)  [15-20 recommended for slow tunnels]", pt, 2, 60)
            cfg["watchdog_probe_mode"] = ask(
                "Probe mode (auto/http/socks)",
                cfg.get("watchdog_probe_mode", "auto")).lower() or "auto"
            cfg["watchdog_prune_dead"]     = ask_int(
                "Prune dead resolvers after N checks  (0 = never)", pd, 0, 100)
            core.save_cfg(profile_name, cfg)
            ok("Settings saved.")
            if running:
                core.stop_watchdog(); time.sleep(0.5)
                core.start_watchdog(cfg, profile_name); ok("Watchdog restarted.")
            pause()

        elif c == "3":
            clr(); section("Watchdog Log")
            lf = core.logfile(profile_name, "watchdog")
            if lf.exists():
                for line in lf.read_text(encoding="utf-8").splitlines()[-40:]:
                    print(f"  {line}")
            else: print(f"  {_c('(empty)',DIM)}")
            pause()

        elif c == "4":
            print()
            info(f"Probing tunnel ({cfg.get('watchdog_probe_mode','auto')})  (timeout {pt}s)...")
            probe_ok, detail = core.probe_tunnel(cfg, timeout=pt)
            if probe_ok:
                ok(f"Probe OK  {_c(detail, DIM)}")
            else:
                err(f"Probe failed:  {_c(detail, Y)}")
                if "google" in url.lower() or url.lower().startswith("https"):
                    warn("Probe URL uses HTTPS — our probe cannot negotiate TLS.")
                    ok(f"Fix: change probe URL to {_c('http://1.1.1.1', G, BO)}")
                    print(f"  {_c('Change settings -> Probe URL', DIM)}")
                else:
                    info("Tunnel working in other apps but probe still fails?")
                    hp = cfg["http_proxy_port"]
                    print(f"    -> Current timeout is {pt}s — try increasing to 25-30s")
                    print(f"    -> Confirm proxy is running: {_c(f'http://127.0.0.1:{hp}', C)}")
                    print(f"    -> Check auth credentials  (Configure -> Auth)")
            pause()

        elif c == "5":
            clr(); section("Emergency Rescan")
            new = core._do_scan(profile_name, cfg, "manual",
                                progress_cb=lambda l: print(f"  {l}"))
            if new:
                core.restart_tunnel(cfg, profile_name)
                print(); ok(f"{len(new)} new resolver(s), tunnel reloaded.")
            else:
                print(); warn("No new resolvers found. Try 'all' scan mode.")
            pause()

# ─────────────────────────────────────────────────────────────────────────────
# MENU: LOGS
# ─────────────────────────────────────────────────────────────────────────────

def menu_logs(profile_name: str):
    while True:
        clr(); section(f"Logs  ·  {profile_name}")
        print(f"  {_c('1',C)})  Health log")
        print(f"  {_c('2',C)})  Watchdog log")
        print(f"  {_c('3',C)})  Scan log")
        print(f"  {_c('0',DIM)})  Back")
        print()
        c = input(f"  {_c('Choice:',C)} ").strip()
        if c == "0": break
        kinds = {"1":"health","2":"watchdog","3":"scan"}
        if c in kinds:
            clr(); section(f"{kinds[c].title()} Log")
            lf = core.logfile(profile_name, kinds[c])
            if lf.exists():
                for line in lf.read_text(encoding="utf-8").splitlines()[-50:]:
                    print(f"  {line}")
            else: print(f"  {_c('(empty)',DIM)}")
            pause()

# ─────────────────────────────────────────────────────────────────────────────
# MENU: CONNECTION INFO
# ─────────────────────────────────────────────────────────────────────────────

def menu_connection_info(cfg: dict):
    clr(); section("Connection Info")
    addr = f"127.0.0.1:{cfg['http_proxy_port']}"
    sys_en, sys_srv = core.get_system_proxy()
    socks_ports = core.live_ports() or [cfg.get("listen_port", 1080)]
    print(f"  {_c('SOCKS5', BO)}      {_c(', '.join(f'127.0.0.1:{p}' for p in socks_ports), G, BO)}")
    if cfg.get("enable_http_proxy", True):
        print(f"  {_c('HTTP proxy', BO)}  {_c(addr, G, BO)}")
    else:
        print(f"  {_c('HTTP proxy', BO)}  {_c('disabled (SOCKS-only mode)', DIM)}")
    sys_state = _c(f"enabled -> {sys_srv}", G) if sys_en else _c("disabled", DIM)
    print(f"  {_c('System proxy', DIM)}  {sys_state}\n")
    print(f"  {_c('Browser (Chrome / Edge / Firefox)', BO)}")
    if cfg.get("enable_http_proxy", True):
        print(f"    Settings -> Proxy -> Manual -> HTTP: {addr}\n")
    else:
        print(f"    Configure app-specific SOCKS5 using one of the local SOCKS ports above.\n")
    _sysname = {"Darwin": "macOS system-wide  (auto via networksetup)",
                 "Linux":  "Linux system-wide  (manual — see shell env vars below)"
                }.get(platform.system(), "Windows system-wide  (auto)")
    print(f"  {_c(_sysname, BO)}")
    if platform.system() == "Linux":
        print(f"    export HTTP_PROXY=http://127.0.0.1:{cfg['http_proxy_port']}")
        print(f"    export HTTPS_PROXY=http://127.0.0.1:{cfg['http_proxy_port']}\n")
    else:
        print(f"    Enable 'System proxy' in Configure\n")
    print(f"  {_c('CMD (current session)', BO)}")
    print(f"    set HTTP_PROXY=http://{addr}")
    print(f"    set HTTPS_PROXY=http://{addr}\n")
    print(f"  {_c('curl', BO)}")
    print(f"    curl -x http://{addr} https://ifconfig.me")
    hr()
    base = cfg.get("listen_port", 7000)
    n    = cfg.get("multi_instance", 1)
    auth = f"  user={cfg['socks_user']}" if cfg.get("socks_auth") else ""
    print(f"\n  {_c('Direct SOCKS5', BO)}")
    for i in range(n):
        tag = f"  {_c(f'instance {i+1}', DIM)}" if n > 1 else ""
        print(f"    127.0.0.1:{base+i}{auth}{tag}")
    pause()

# ─────────────────────────────────────────────────────────────────────────────
# SLIPNET IMPORT / EXPORT  (#12)
# ─────────────────────────────────────────────────────────────────────────────

def _import_slipnet() -> str | None:
    clr(); section("Import slipnet:// Profile")
    print(f"  {_c('Paste your slipnet:// URI below:', DIM)}\n")
    uri = input("  ").strip()
    if not uri: return None

    result = core.parse_slipnet(uri)
    if not result["ok"]:
        reason = result.get("reason","unknown")
        print()
        if "encrypted" in str(reason):
            warn("This slipnet config appears to be encrypted.")
            info("The app may use additional encryption beyond base64.")
        else:
            err(f"Could not parse: {reason}")
        pause(); return None

    cfg, ips = result["cfg"], result["resolvers"]
    print(); ok("Decoded successfully!")
    print(f"\n  Domain    : {_c(cfg['domain'], C, BO)}")
    print(f"  Port      : {_c(cfg['listen_port'], BO)}")
    if cfg.get("socks_auth"):
        print(f"  Auth      : {_c(cfg['socks_user'], Y)}  (password set)")
    if ips:
        print(f"  Resolvers : {_c(len(ips), BO)} found")
        for ip in ips[:5]: print(f"              {ip}")
        if len(ips) > 5: print(f"              ...and {len(ips)-5} more")
    print()

    name = ask("Profile name", result["name"])
    if not name: return None
    core.create_profile(name, cfg)
    if ips:
        core.save_servers(name, ips); ok(f"Saved {len(ips)} resolver(s) from config.")

    print()
    if ask_bool("Scan for additional resolvers now?", default=True):
        additional = run_scan_interactive(name, cfg)
        if additional:
            existing = core.load_servers(name)
            merged   = list(dict.fromkeys(additional + existing))
            merged   = core.enforce_pool_cap(name, merged, cfg.get("resolver_max_pool", 12))
            merged   = core.sort_by_score(name, merged)
            core.save_servers(name, merged); ok(f"Pool: {len(merged)} resolvers total")

    core.set_active(name); ok(f"Profile '{name}' created and activated.")
    pause(); return name

# ─────────────────────────────────────────────────────────────────────────────
# SETUP WIZARD
# ─────────────────────────────────────────────────────────────────────────────

def wizard(default_active: str = None) -> str | None:
    clr(); section("New Profile Wizard")
    print(f"  {_c('Set up a new tunnel profile step by step.',DIM)}")
    print(f"  {_c('You can change any setting later via Configure.',DIM)}\n")

    if ask_bool("Import from a slipnet:// URI instead?", False):
        return _import_slipnet()

    cfg = deepcopy(core.DEFAULT_CFG)

    # 1/6 Name
    print(f"\n  {_c('1/6  Profile name',Y,BO)}\n")
    name = ask("Name  (e.g. shatel, hamrah, home)").strip()
    if not name: return None
    if core.profile_exists(name):
        warn(f"'{name}' already exists. Use Configure to edit it.")
        pause(); return None

    # 2/6 Server
    print(f"\n  {_c('2/6  Tunnel server',Y,BO)}\n")
    cfg["domain"] = ask_domain("Tunnel domain  (e.g. t.example.com)")
    if not cfg["domain"]: return None
    cfg["cert_path"]  = ask("Cert path  (blank if not needed)", "")
    cfg["socks_auth"] = ask_bool("Does the server require username/password?", False)
    if cfg["socks_auth"]:
        cfg["socks_user"] = ask("Username")
        cfg["socks_pass"] = ask("Password")

    # 3/6 Ports
    print(f"\n  {_c('3/6  Ports & proxy',Y,BO)}\n")
    cfg["listen_port"]     = ask_int("Internal SOCKS5 port", 7000, 1024, 65000)
    cfg["enable_http_proxy"] = ask_bool("Enable HTTP proxy bridge?", True)
    if cfg["enable_http_proxy"]:
        print(f"  {_c('The HTTP proxy port is what you enter in browser / OS settings.',DIM)}\n")
        cfg["http_proxy_port"] = ask_int("HTTP proxy port",      8080, 1024, 65000)
    _os_lbl2 = {"Darwin": "macOS", "Linux": "Linux"}.get(platform.system(), "Windows")
    if not cfg.get("enable_http_proxy", True):
        cfg["system_proxy"] = False
    elif platform.system() == "Linux":
        info("Linux: system proxy not set automatically. Use shell env vars after start.")
        cfg["system_proxy"] = False
    else:
        cfg["system_proxy"] = ask_bool(
            f"Set as {_os_lbl2} system proxy automatically on start?", True)

    # 4/6 Redundancy
    print(f"\n  {_c('4/6  Redundancy',Y,BO)}\n")
    print(f"  {_c('Multiple instances run in parallel — if one dies, traffic keeps flowing.',DIM)}\n")
    cfg["multi_instance"] = ask_int(
        "Parallel tunnel instances  (1 = single, 2 = recommended)", 2, 1, 8)

    # 5/6 Watchdog
    print(f"\n  {_c('5/6  Watchdog',Y,BO)}\n")
    print(f"  {_c('The watchdog probes your connection and auto-recovers on failure.',DIM)}\n")
    cfg["watchdog_enabled"] = ask_bool("Enable watchdog?", True)
    if cfg["watchdog_enabled"]:
        cfg["watchdog_check_interval"] = ask_int("Probe every N seconds", 60, 10, 3600)
        cfg["watchdog_probe_url"]      = ask_url_http(
            "Probe URL  [use http://1.1.1.1 — plain HTTP, most reliable]", "http://1.1.1.1")
        cfg["watchdog_probe_timeout"]  = ask_int(
            "Probe timeout (s)  [15-20s recommended for slow tunnels]", 15, 2, 60)

    # Save immediately
    core.save_cfg(name, cfg)
    print(); ok(f"Profile '{name}' saved.")

    # 6/6 Scan settings
    print(f"\n  {_c('6/6  Scan Settings',Y,BO)}\n")
    print(f"  {_c('Country code for the IP ranges to scan.',DIM)}\n")
    cfg["country"]        = ask_country_code("Country code", "ir")
    cfg["scan_mode"]      = ask("Scan mode  (list / fast / medium / all)", "fast")
    cfg["scan_workers"]   = ask_int("Workers", 1200, 100, 16000)
    cfg["scan_timeout"]   = ask_timeout_str("Timeout", "1s")
    cfg["scan_threshold"] = ask_int("Benchmark threshold %", 50, 1, 100)
    cfg["verify_sample_count"] = ask_int("E2E verify top N candidates", 20, 1, 500)
    cfg["dns_precheck_mode"] = ask("DNS precheck mode (quick/full)", "quick").lower() or "quick"
    cfg["scan_burst_count"] = ask_int("Burst filter query count", 6, 0, 30)
    cfg["scan_burst_workers"] = ask_int("Burst filter workers", 64, 1, 512)
    cfg["monitor_refresh_sec"] = ask_int("Live monitor refresh (s)", 2, 1, 10)
    core.save_cfg(name, cfg)

    if ask_bool("Scan for resolvers now?", True):
        verified = run_scan_interactive(name, cfg)
        if verified:
            verified = core.sort_by_score(name, verified)
            core.save_servers(name, verified)
            ok(f"{len(verified)} resolver(s) saved.")
            print()
            if ask_bool("Start tunnel now?", True):
                core.set_active(name)
                _start_and_report(cfg, name)
                pause()
                return name
        else:
            warn("No resolvers found. Scan later from the main menu (s).")

    core.set_active(name)
    ok(f"Profile '{name}' is ready. Use the main menu to scan and start.")
    pause()
    return name

# ─────────────────────────────────────────────────────────────────────────────
# MENU: PROFILES
# ─────────────────────────────────────────────────────────────────────────────

def menu_profiles(active: str) -> str:
    while True:
        clr(); section("Profiles")
        profiles = core.list_profiles()
        for i, name in enumerate(profiles, 1):
            c   = core.load_cfg(name)
            cnt = len(core.load_servers(name))
            tag = _c("  <- active", G) if name == active else ""
            print(f"  {_c(i,DIM)})  {_c(name,M,BO):<32}  "
                  f"{_c(c['domain'],C)}  {_c(cnt,BO)} resolver(s){tag}")

        print()
        print(f"  {_c('n',C)})  New profile  (wizard)")
        print(f"  {_c('i',C)})  Import slipnet:// URI")
        print(f"  {_c('d',C)})  Duplicate  {_c(f'({active})',DIM)}")
        print(f"  {_c('r',C)})  Rename")
        print(f"  {_c('x',C)})  Delete")
        print(f"  {_c('0',DIM)})  Back")
        print()

        choice = input(f"  {_c('Switch to # or command:',C)} ").strip().lower()

        if choice == "0": return active
        elif choice == "n":
            new = wizard(default_active=active)
            return new if new else active
        elif choice == "i":
            new = _import_slipnet()
            return new if new else active
        elif choice == "d":
            new_n = ask(f"Name for copy of '{active}'")
            if not new_n: continue
            core.create_profile(new_n, core.load_cfg(active))
            core.save_servers(new_n, core.load_servers(active))
            ok(f"Duplicated as '{new_n}'"); pause()
        elif choice == "r":
            old = ask("Profile to rename")
            if not core.profile_exists(old): err(f"Not found: {old}"); pause(); continue
            new_n = ask("New name")
            if not new_n: continue
            core.create_profile(new_n, core.load_cfg(old))
            core.save_servers(new_n, core.load_servers(old))
            core.delete_profile(old)
            if active == old: core.set_active(new_n); active = new_n
            ok(f"Renamed to '{new_n}'"); pause()
        elif choice == "x":
            name = ask("Profile to delete")
            if name == active: warn("Cannot delete the active profile."); pause(); continue
            if not core.profile_exists(name): err(f"Not found: {name}"); pause(); continue
            if ask_bool(f"Delete '{name}'?", False):
                core.delete_profile(name); ok(f"Deleted '{name}'")
            pause()
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(profiles):
                    new = profiles[idx]; core.set_active(new)
                    ok(f"Switched to '{new}'"); pause(); return new
            except ValueError: pass
            warn("Invalid choice."); time.sleep(0.5)




def menu_live_monitor(profile_name: str, cfg: dict):
    return ui_runtime.run_live_monitor(core, profile_name, cfg, {
        "clr": clr,
        "section": section,
        "pill": pill,
        "_c": _c,
        "fmt_rate": fmt_rate,
        "fmt_bytes": fmt_bytes,
        "colors": {"G": G, "R": R, "C": C, "BO": BO, "DIM": DIM},
    })


# ─────────────────────────────────────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────────────────────────────────────

def main_menu(start_profile: str = None):
    active = start_profile or core.get_active()
    while True:
        cfg = core.load_cfg(active)
        print_header(active, cfg)

        if core.tunnel_running():
            print(f"  {_c('t',M,BO)})  Stop tunnel")
            print(f"  {_c('r',M)})  Restart tunnel")
        else:
            print(f"  {_c('t',M,BO)})  Start tunnel")

        print()
        print(f"  {_c('s',C)})  Scan for resolvers")
        print(f"  {_c('h',C)})  Health check")
        print(f"  {_c('l',C)})  Resolver pool")
        print(f"  {_c('w',C)})  Watchdog")
        print()
        print(f"  {_c('p',DIM)})  Profiles  "
              f"{_c(f'({len(core.list_profiles())} total, active: {active})',DIM)}")
        print(f"  {_c('c',DIM)})  Configure this profile")
        print(f"  {_c('m',DIM)})  Live monitor")
        print(f"  {_c('?',DIM)})  Connection info")
        print(f"  {_c('g',DIM)})  Logs")
        print(f"  {_c('y',DIM)})  Toggle system proxy now")
        print(f"  {_c('u',DIM)})  Restore system proxy defaults")
        print()
        print(f"  {_c('0',DIM)})  Exit")
        print()

        raw_choice = input(f"  {_c('>',C,BO)} ").strip().lower()
        if not raw_choice:
            continue
        aliases = {"start":"t","stop":"t","restart":"r","scan":"s","health":"h","resolvers":"l","watchdog":"w","profiles":"p","config":"c","monitor":"m","logs":"g","proxy":"y","toggle-proxy":"y","restore-proxy":"u","exit":"0","quit":"0"}
        choice = aliases.get(raw_choice, raw_choice)

        if choice == "t":
            if core.tunnel_running():
                core.stop_all(cfg); print(); ok("Tunnel stopped.")
            else:
                if not core.load_servers(active):
                    warn("No resolvers in pool — run a scan first (s).")
                else:
                    _start_and_report(cfg, active)
            pause()
        elif choice == "r" and core.tunnel_running():
            core.restart_tunnel(cfg, active); ok("Tunnel restarted."); pause()
        elif choice == "s":
            menu_scan(active, cfg)
        elif choice == "h":
            clr(); section(f"Health Check  ·  {active}")
            menu_health(active, cfg)
        elif choice == "l":
            menu_resolvers(active, cfg)
        elif choice == "w":
            menu_watchdog(active, cfg); cfg = core.load_cfg(active)
        elif choice == "p":
            new = menu_profiles(active)
            if new != active:
                if core.tunnel_running(): core.stop_all(core.load_cfg(active))
                active = new; core.set_active(active)
        elif choice == "c":
            menu_configure(active, cfg)
        elif choice == "m":
            menu_live_monitor(active, cfg)
        elif choice == "?":
            menu_connection_info(cfg)
        elif choice == "g":
            menu_logs(active)
        elif choice == "y":
            ok_toggle, detail = core.toggle_system_proxy_runtime(cfg)
            if ok_toggle:
                ok(f"System proxy {detail}.")
            else:
                warn(f"System proxy toggle failed: {detail}")
            pause()
        elif choice == "u":
            if core.restore_system_proxy_defaults():
                ok("System proxy restored to previously captured defaults.")
            else:
                warn("Could not restore previous proxy settings (or no backup exists).")
            pause()
        elif choice == "0":
            if core.tunnel_running() and ask_bool("Stop tunnel before exiting?", True):
                core.stop_all(cfg)
            print(); sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT  (#10 headless improvements)
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="slipstream-tunnel")
    ap.add_argument("--profile", help="Activate named profile on start")
    ap.add_argument("--no-menu", action="store_true",
                    help="Headless: start tunnel immediately, print status periodically")
    ap.add_argument("--status-interval", type=int, default=60,
                    help="Headless status line interval in seconds (default: 60)")
    args = ap.parse_args()

    def _exit(sig, frame):
        print("\n\n  Shutting down...")
        try: core.stop_all(core.load_cfg(core.get_active()))
        except Exception: pass
        sys.exit(0)
    signal.signal(signal.SIGINT, _exit)

    if args.profile:
        if not core.profile_exists(args.profile):
            core.create_profile(args.profile)
        core.set_active(args.profile)

    missing = []
    if not core.DNSCAN_EXE.exists(): missing.append(f"dnscan  ({core.DNSCAN_EXE})")
    if not core.CLIENT_EXE.exists(): missing.append(f"slipstream-client  ({core.CLIENT_EXE})")
    if missing:
        print()
        for m in missing: print(f"  {_c('[!]',Y)} Not found: {m}")
        print(f"  {_c('[~]',C)} Attempting binary bootstrap...")
        for line in core.bootstrap_binaries():
            print(f"    - {line}")
        print()

    c_ok, c_detail = core.diagnose_client_binary()
    if not c_ok:
        warn(f"Client diagnostic: {c_detail}")
        if "OpenSSL" in c_detail or "libcrypto" in c_detail:
            info("Fix: place libcrypto-3-x64.dll and libssl-3-x64.dll next to slipstream-client EXE, then restart.")

    if args.no_menu:
        # #10: Headless mode with PID file, periodic status, signal handlers
        active = core.get_active()
        cfg    = core.load_cfg(active)
        if not core.load_servers(active):
            print("  No resolvers in pool."); sys.exit(1)

        core.write_pid_file()
        core.install_headless_signals(active, cfg)

        _start_and_report(cfg, active)
        print(f"\n  {_c('[>]',G)} Running headless. Ctrl+C to stop.")
        print(f"  {_c('[i]',C)} Status every {args.status_interval}s."
              f"  {_c('SIGUSR1=status dump  SIGUSR2=force rescan', DIM)}\n")

        last_status = time.monotonic()
        try:
            while True:
                time.sleep(1)
                if time.monotonic() - last_status >= args.status_interval:
                    cfg = core.load_cfg(active)
                    print(core.headless_status_line(active, cfg), flush=True)
                    last_status = time.monotonic()
        except KeyboardInterrupt:
            pass
        finally:
            core.remove_pid_file()
    else:
        if core.is_first_run():
            clr()
            print(f"\n  {_c('Welcome to slipstream-tunnel!',C,BO)}")
            print(f"  {_c('No profiles configured yet. Starting setup wizard...',DIM)}\n")
            time.sleep(1)
            wizard()
        main_menu()


if __name__ == "__main__":
    main()
