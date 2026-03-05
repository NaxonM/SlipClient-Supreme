"""Resolver verification and maintenance workflows."""

from __future__ import annotations

import threading


def verify_candidates_interactive(core, profile_name: str, cfg: dict, candidates: list[str], ui) -> list[str]:
    """Interactive E2E verification for freshly scanned candidates."""
    if not candidates:
        return []

    verify_all = bool(cfg.get("verify_all_candidates", True))
    verify_n = max(1, int(cfg.get("verify_sample_count", 20)))
    n_test = len(candidates) if verify_all else min(len(candidates), verify_n)
    workers = cfg.get("verify_workers", 4)
    eta_s = max(8, (n_test // max(1, workers) + 1) * 8)

    print()
    do_verify = ui["ask_bool"](
        f"Tunnel-verify {'all' if verify_all else 'top'} {n_test} candidate(s)? "
        f"(~{eta_s}s with {workers} parallel workers — confirms actual tunnel + hijack check)",
        default=True,
    )
    if not do_verify:
        ui["warn"](f"Skipping verification — using all {len(candidates)} candidates unverified.")
        return candidates

    print()
    print(f"  {ui['_c']('━'*54, ui['colors']['C'])}")
    print(f"  {ui['_c']('  TUNNEL VERIFICATION', ui['colors']['C'], ui['colors']['BO'])}")
    print(f"  {ui['_c']('━'*54, ui['colors']['C'])}")
    print(f"  {ui['_c'](n_test, ui['colors']['BO'])} candidates  ·  "
          f"{ui['_c'](workers, ui['colors']['BO'])} parallel workers  ·  "
          f"~{ui['_c'](eta_s, ui['colors']['BO'])}s estimated")
    print(f"  {ui['_c']('Each IP: spawns client → waits for SOCKS5 → probes tunnel → DNS hijack check', ui['colors']['DIM'])}")
    print(f"  {ui['_c']('━'*54, ui['colors']['C'])}")
    print()

    verified = []
    result_lock = threading.Lock()
    counter = [0]

    def _cb(ip, passed):
        with result_lock:
            counter[0] += 1
            i = counter[0]
            if passed:
                mark = f"  {ui['_c']('✓  PASS', ui['colors']['G'], ui['colors']['BO'])}"
                verified.append(ip)
            else:
                scores = core.load_scores(profile_name)
                if scores.get(ip, {}).get("hijacked"):
                    mark = f"  {ui['_c']('✗  HIJACKED', ui['colors']['R'], ui['colors']['BO'])}"
                else:
                    mark = f"  {ui['_c']('✗  fail', ui['colors']['DIM'])}"
            print(f"  {ui['_c'](f'[{i}/{n_test}]', ui['colors']['C'], ui['colors']['BO'])}  {ip:<22}{mark}")

    print(f"  {ui['_c']('Starting workers…', ui['colors']['DIM'])}")
    core.verify_resolvers_parallel(
        candidates[:n_test],
        cfg,
        profile_name=profile_name,
        max_workers=workers,
        result_cb=_cb,
    )

    print()
    print(f"  {ui['_c']('━'*54, ui['colors']['C'])}")
    color = ui['colors']['G'] if verified else ui['colors']['Y']
    total_tested = min(n_test, len(candidates))
    print(f"  Result: {ui['_c'](len(verified), color, ui['colors']['BO'])} / {total_tested} passed")
    print(f"  {ui['_c']('━'*54, ui['colors']['C'])}")

    if not verified:
        print()
        ui["warn"]("All verifications failed — this usually means the tunnel server is")
        ui["warn"]("unreachable or the domain is wrong, NOT that the resolvers are bad.")
        if cfg.get("verify_strict_required", True):
            ui["warn"]("Strict E2E mode is enabled — unverified candidates are rejected.")
            print(f"  {ui['_c']('Tip:', ui['colors']['DIM'])} Check your domain/server, then re-scan.")
            return []
        ui["warn"]("Falling back to unverified candidates so you can still start the tunnel.")
        print(f"  {ui['_c']('Tip:', ui['colors']['DIM'])} Check your domain and server, then re-scan.")
        return candidates

    return verified


def verify_existing_pool(core, profile_name: str, cfg: dict, ui) -> None:
    servers = core.load_servers(profile_name)
    if not servers:
        ui["warn"]("Resolver pool is empty.")
        return

    workers = cfg.get("verify_workers", 4)
    print()
    ui["info"](f"E2E-verifying {len(servers)} resolver(s) with {workers} worker(s)...")
    passed: list[str] = []
    failed: list[str] = []

    def _cb(ip, ok_pass):
        if ok_pass:
            passed.append(ip)
            print(f"  {ui['_c']('✓', ui['colors']['G'], ui['colors']['BO'])} {ip}")
        else:
            failed.append(ip)
            print(f"  {ui['_c']('✗', ui['colors']['Y'], ui['colors']['BO'])} {ip}")

    core.verify_resolvers_parallel(
        servers,
        cfg,
        profile_name=profile_name,
        max_workers=workers,
        result_cb=_cb,
    )

    print()
    ui["ok"](f"E2E pass: {len(passed)} / {len(servers)}")
    if failed and ui["ask_bool"](f"Remove {len(failed)} failed resolver(s) from pool?", default=False):
        left = [ip for ip in servers if ip not in set(failed)]
        core.save_servers(profile_name, left)
        ui["ok"](f"Removed {len(failed)} resolver(s). {len(left)} remain.")
