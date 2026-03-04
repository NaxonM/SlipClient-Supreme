"""Resolver maintenance workflows extracted from ui.py."""


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
