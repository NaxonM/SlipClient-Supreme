# SlipClient-Supreme Audit (code + docs)

## Fixed in this pass

1. **No safe monitor exit path**
   - Replaced Ctrl+C-only monitor behavior with a non-destructive `q` exit flow.
   - Added configurable monitor refresh interval (`monitor_refresh_sec`).

2. **Scanner verification inconsistency across OSes**
   - UI previously skipped E2E verification on non-Windows platforms, leading to inconsistent resolver quality.
   - E2E verification is now offered cross-platform.

3. **Resolver pruning UX gap after E2E failures**
   - Added resolver-pool action to E2E-verify existing resolvers and explicitly ask whether failed ones should be removed.

4. **Potential false positives in scan candidates**
   - Added post-scan burst DNS sampling (`scan_burst_count`) to reject unstable resolvers before pool merge.

5. **Unsupported/ineffective client flags exposed in UI**
   - Removed user-facing `congestion_control` and `gso_enabled` tuning from config flow.
   - Added Python-side socket tuning (`low_latency_mode`) in HTTP↔SOCKS bridge as a cross-binary, portable optimization.

6. **Watchdog disruption issue**
   - Periodic watchdog rescan no longer restarts tunnel unconditionally; restart now happens only when new resolvers are found.

## Remaining concerns (not fully solved yet)

1. **Core/UI module size**
   - `core.py` and `ui.py` remain large and would benefit from decomposition into submodules (`scanner`, `watchdog`, `proxy`, `profiles`, `monitoring`, `menus`).

2. **Load balancing strategy is simplistic**
   - Current instance selection is CPS-based only; it does not incorporate per-instance resolver quality, recent fail rate, or active probe RTT.

3. **Scanner external dependency quality**
   - `dnscan` is still the first-stage source of candidates. While post-filtering and E2E verification help, replacing/embedding scanner logic fully in Python (or aligning 1:1 with SlipNet scanner pipeline) would further improve control and observability.

4. **Documentation drift**
   - The included docs mix upstream Slipstream/deploy/dnscan narratives and can confuse ownership/supported features for this client app. A project-specific README for this repo should clarify exact behavior and limitations.


## Additional improvements in follow-up pass

- Decomposed UI runtime/monitor logic into `ui_runtime.py` (snapshot model + live monitor runner).
- Decomposed resolver E2E maintenance flow into `ui_resolver_maintenance.py` to keep menu logic leaner and testable.
- Main menu now accepts word aliases (`start`, `scan`, `watchdog`, `exit`, etc.) in addition to single-key shortcuts.
- Header now includes a compact live runtime strip (down/up/latency/conn count) when tunnel is active, reducing context switches to monitor page.

- Core decomposition started: DNS scan/compatibility logic moved to `core_dns.py` and resolver pool merge helpers moved to `core_pool.py`; `core.py` now composes these modules instead of hosting all internals in one file.


## Stability and safety hardening pass

- Added startup client binary diagnostics (`diagnose_client_binary`) to detect missing OpenSSL runtime DLLs on Windows and provide actionable guidance.
- Added runtime system-proxy controls: toggle without stopping tunnel + explicit restore-to-defaults operation.
- Added proxy guard backup/restore safety (`state/system_proxy_backup.json`) with exit hooks to reduce risk of stuck network settings after crashes/exits.
- Refined defaults to reduce resource usage spikes (`scan_workers` lowered to 1200, monitor refresh to 2s).
- Expanded input validation in UI (domain, timeout, URL, country code) to reduce bad config states.
- Added complete user-facing guide in `docs/USER_GUIDE.md`.
- Expanded UI runtime module to include timed menu input + auto-refresh monitor mechanics, and moved candidate verification flow into resolver maintenance module to reduce `ui.py` size further.
- Monitor latency display now rounds to integer milliseconds for readability.
- Added configurable `verify_sample_count` default to improve scan-quality control.

## Input responsiveness fix pass

- Removed aggressive header live-refresh loop that could interfere with interactive input; near-real-time stats remain in dedicated monitor section only.
- Added `start.py` as a clear, distinct application entrypoint.
