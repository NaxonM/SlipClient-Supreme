# SlipClient-Supreme User Guide

This guide explains setup, safe operation, scanner usage, watchdog behavior, and recovery.

## 1) What this app does

SlipClient-Supreme manages a local Slipstream DNS-tunnel client with:
- Resolver scanning + quality filtering
- Multi-instance local tunnel processes
- HTTP→SOCKS local proxy bridge
- Optional system proxy automation (Windows/macOS)
- Watchdog monitoring + auto-rescan

## 2) First run checklist

1. Open app (`python start.py`).
2. Create/import a profile.
3. Set a valid tunnel domain (example: `t.example.com`).
4. Run resolver scan.
5. Start tunnel.
6. (Optional) Enable system proxy automation for Windows/macOS.

## 3) Cause of `libcrypto-3-x64.dll` error (Windows)

If you see:
> `... code execution cannot proceed because libcrypto-3-x64.dll was not found ...`

it means the bundled `slipstream-client` build depends on OpenSSL 3 runtime DLLs that are missing on your machine.

### Fix
Place these files in the same folder as the Slipstream client executable:
- `libcrypto-3-x64.dll`
- `libssl-3-x64.dll`

Then restart the app. The app now runs a startup diagnostic and warns when this issue is detected.

## 4) Safe proxy control (without stopping tunnel)

From main menu:
- `y` toggles system proxy on/off immediately.
- `u` restores previously captured proxy defaults.

This works without stopping the tunnel process.

## 5) Proxy safety / network-setting recovery

To reduce risk of broken network settings:
- Before enabling system proxy, app captures previous proxy state in `state/system_proxy_backup.json`.
- On normal stop and on registered exit paths, app restores prior state.
- You can force restoration manually from menu (`u`).

## 6) Recommended defaults (balanced resources)

These defaults are tuned for lower resource usage while preserving throughput:
- `scan_workers`: 1200
- `monitor_refresh_sec`: 2
- `verify_workers`: 4
- `multi_instance`: 1–2 for most systems

If your device is weak:
- lower `scan_workers` to 300–800
- keep monitor refresh ≥2s
- use `list` or `fast` scan modes

## 7) Input validation behavior

The UI now validates:
- Domain format (`t.example.com` style)
- Timeout format (`800ms` or `2s`)
- Probe URL format (`http://...` / `https://...`)
- Country code format (2 letters)

Invalid values are rejected immediately with guidance.

## 8) Scanner workflow tips

Recommended flow:
1. Start with `list` mode.
2. If empty/weak results, use `fast`, then `medium`.
3. Keep E2E verification enabled.
4. Use resolver pool verify action (`v`) periodically and remove failed resolvers.
5. Configure how many candidates are E2E-verified (`verify_sample_count`) based on your speed/quality preference.

The app additionally applies burst post-filtering to reduce false positives.

## 9) Watchdog best practices

- Use `http://1.1.1.1` as probe URL for reliability.
- Increase probe timeout to 15–25s on slower links.
- Keep periodic scan interval conservative if your network is unstable.

## 10) Troubleshooting quick map

- **Tunnel starts but traffic fails**: verify domain, run health check, re-scan resolvers.
- **All E2E fail**: usually domain/server-side problem, not resolver quality alone.
- **System proxy stuck**: use menu `u` restore, or stop app cleanly and restart.
- **High CPU during scan**: lower `scan_workers`, prefer `list/fast`, reduce monitor refresh frequency.


## 11) Why scan/verification can feel slow (and how to speed it up)

There are two costly phases after raw scan output:
1. Burst filter (repeated DNS checks for stability)
2. E2E tunnel verify (spawns client and probes traffic)

These are useful for quality, but now tunable:
- `scan_burst_count` (lower = faster, less strict)
- `scan_burst_workers` (higher = faster, more CPU/network load)
- `verify_sample_count` (how many candidates get full E2E verification)
- `dns_precheck_mode=quick` (faster) or `full` (stricter)

Suggested fast profile:
- burst count: 4–6
- burst workers: 64–128
- verify sample count: 8–15
- dns precheck mode: quick
