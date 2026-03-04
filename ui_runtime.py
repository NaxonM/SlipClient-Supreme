"""Runtime + interactive terminal refresh helpers for the UI."""

from __future__ import annotations

import platform
import sys
import time


def runtime_snapshot(core, profile_name: str) -> dict:
    st = core.tunnel_runtime_stats(profile_name)
    alive, total = core.tunnel_counts()
    lat = st.get("active_latency_ms")
    if isinstance(lat, (float, int)):
        lat = int(round(lat))
    return {
        "connected": st.get("connected", False),
        "down_bps": st.get("down_bps", 0.0),
        "up_bps": st.get("up_bps", 0.0),
        "total_down": st.get("total_down", 0),
        "total_up": st.get("total_up", 0),
        "active_port": st.get("active_port"),
        "active_resolver": st.get("active_resolver"),
        "active_latency_ms": lat,
        "total_conns": st.get("total_conns", 0),
        "alive": alive,
        "total": total,
    }


def _poll_enter_or_q(timeout_s: float) -> str | None:
    """
    Non-blocking line poll.
    Returns:
      - 'q' when user pressed q + Enter
      - '' when Enter was pressed
      - None when timed out with no input
    """
    if timeout_s <= 0:
        return None

    if platform.system() == "Windows":
        try:
            import msvcrt
            buf = []
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\r", "\n"):
                        print()
                        return "".join(buf).strip().lower()
                    if ch == "\x08":
                        if buf:
                            buf.pop()
                    elif ch and ch >= " ":
                        buf.append(ch)
                time.sleep(0.02)
            return None
        except Exception:
            pass

    try:
        import select
        ready, _, _ = select.select([sys.stdin], [], [], timeout_s)
        if ready:
            line = sys.stdin.readline()
            return line.strip().lower()
        return None
    except Exception:
        return None


def timed_menu_choice(prompt: str, timeout_s: float) -> str | None:
    """Prompt with timeout so headers can auto-refresh in main menu."""
    print(prompt, end="", flush=True)
    val = _poll_enter_or_q(timeout_s)
    if val is None:
        return None
    return val


def render_live_strip(ui, snap: dict) -> str:
    lat = f"{snap['active_latency_ms']}ms" if snap.get("active_latency_ms") is not None else "-"
    return (
        f"  {ui['_c']('Live', ui['colors']['DIM'])}"
        f"  down={ui['_c'](ui['fmt_rate'](snap['down_bps']), ui['colors']['G'])}"
        f"  up={ui['_c'](ui['fmt_rate'](snap['up_bps']), ui['colors']['C'])}"
        f"  lat={ui['_c'](lat, ui['colors']['BO'])}"
        f"  conns={ui['_c'](snap['total_conns'], ui['colors']['BO'])}"
    )


def run_live_monitor(core, profile_name: str, cfg: dict, ui) -> None:
    """Auto-refreshing monitor. Press q + Enter to quit."""
    refresh = max(1, int(cfg.get("monitor_refresh_sec", 2)))
    while True:
        ui["clr"]()
        ui["section"](f"Live Monitor  ·  {profile_name}")
        st = runtime_snapshot(core, profile_name)
        conn = ui["pill"]("CONNECTED", ui["colors"]["G"]) if st["connected"] else ui["pill"]("DISCONNECTED", ui["colors"]["R"])
        print(f"  Status           {conn}")
        inst = f"{st['alive']}/{st['total']}"
        print(f"  Instances        {ui['_c'](inst, ui['colors']['BO'])}")
        print(f"  Download         {ui['_c'](ui['fmt_rate'](st['down_bps']), ui['colors']['G'], ui['colors']['BO'])}")
        print(f"  Upload           {ui['_c'](ui['fmt_rate'](st['up_bps']), ui['colors']['C'], ui['colors']['BO'])}")
        print(f"  Total Download   {ui['_c'](ui['fmt_bytes'](st['total_down']), ui['colors']['BO'])}")
        print(f"  Total Upload     {ui['_c'](ui['fmt_bytes'](st['total_up']), ui['colors']['BO'])}")
        print(f"  Active port      {ui['_c'](st.get('active_port') or '-', ui['colors']['BO'])}")
        print(f"  Active resolver  {ui['_c'](st.get('active_resolver') or '-', ui['colors']['BO'])}")
        lat = f"{st['active_latency_ms']} ms" if st.get("active_latency_ms") is not None else "-"
        print(f"  Resolver latency {ui['_c'](lat, ui['colors']['BO'])}")
        print(f"  Connections      {ui['_c'](st.get('total_conns', 0), ui['colors']['BO'])}")
        print()
        print(f"  {ui['_c'](f'Auto-refresh every {refresh}s. Type q + Enter to return.', ui['colors']['DIM'])}")
        cmd = _poll_enter_or_q(float(refresh))
        if cmd == "q":
            return
