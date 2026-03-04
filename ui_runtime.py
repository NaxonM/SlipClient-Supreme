"""Runtime/monitor helpers extracted from ui.py for maintainability."""

from __future__ import annotations

import time


def runtime_snapshot(core, profile_name: str) -> dict:
    st = core.tunnel_runtime_stats(profile_name)
    alive, total = core.tunnel_counts()
    return {
        "connected": st.get("connected", False),
        "down_bps": st.get("down_bps", 0.0),
        "up_bps": st.get("up_bps", 0.0),
        "total_down": st.get("total_down", 0),
        "total_up": st.get("total_up", 0),
        "active_port": st.get("active_port"),
        "active_resolver": st.get("active_resolver"),
        "active_latency_ms": st.get("active_latency_ms"),
        "total_conns": st.get("total_conns", 0),
        "alive": alive,
        "total": total,
    }


def run_live_monitor(core, profile_name: str, cfg: dict, ui) -> None:
    """
    ui is a small adapter namespace/dict exposing:
      clr, section, pill, _c, fmt_rate, fmt_bytes, colors{G,R,C,BO,DIM}
    """
    refresh = max(1, int(cfg.get("monitor_refresh_sec", 1)))
    while True:
        ui["clr"]()
        ui["section"](f"Live Monitor  ·  {profile_name}")
        st = runtime_snapshot(core, profile_name)
        conn = ui["pill"]("CONNECTED", ui["colors"]["G"]) if st["connected"] else ui["pill"]("DISCONNECTED", ui["colors"]["R"])
        lat = f"{st['active_latency_ms']} ms" if st.get("active_latency_ms") is not None else "-"
        print(f"  Status           {conn}")
        inst = f"{st['alive']}/{st['total']}"
        print(f"  Instances        {ui['_c'](inst, ui['colors']['BO'])}")
        print(f"  Download         {ui['_c'](ui['fmt_rate'](st['down_bps']), ui['colors']['G'], ui['colors']['BO'])}")
        print(f"  Upload           {ui['_c'](ui['fmt_rate'](st['up_bps']), ui['colors']['C'], ui['colors']['BO'])}")
        print(f"  Total Download   {ui['_c'](ui['fmt_bytes'](st['total_down']), ui['colors']['BO'])}")
        print(f"  Total Upload     {ui['_c'](ui['fmt_bytes'](st['total_up']), ui['colors']['BO'])}")
        print(f"  Active port      {ui['_c'](st.get('active_port') or '-', ui['colors']['BO'])}")
        print(f"  Active resolver  {ui['_c'](st.get('active_resolver') or '-', ui['colors']['BO'])}")
        print(f"  Resolver latency {ui['_c'](lat, ui['colors']['BO'])}")
        print(f"  Connections      {ui['_c'](st.get('total_conns', 0), ui['colors']['BO'])}")
        print()
        print(f"  {ui['_c'](f'Auto-refresh: every {refresh}s', ui['colors']['DIM'])}")
        cmd = input(f"  {ui['_c']('Press Enter to refresh or type q to return:', ui['colors']['DIM'])} ").strip().lower()
        if cmd == "q":
            return
        time.sleep(refresh)
