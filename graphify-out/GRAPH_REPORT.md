# Graph Report - RustWarden  (2026-11-17)

## Corpus Check
- 234 files · ~325,688 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 2, .ico 1, .tsv 1)

## Summary
- 6131 nodes · 13066 edges · 259 communities (234 shown, 25 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 804 edges (avg confidence: 0.61)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `d37aad01`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- live/firewall.rs
- LiveBackend
- UiTree
- theme.rs
- threat.rs
- MockBackend
- Icon
- thinkbroadband/src/lib.rs
- cloudflare/src/lib.rs
- engine.rs
- Ui
- webview.rs
- baseline.rs
- .notify
- update.rs
- guard.rs
- Backend
- manager.rs
- Context
- .default
- live/apps.rs
- speedtest/src/lib.rs
- live/scanner.rs
- Db
- demo.rs
- FwController
- traffic_load.rs
- popup.rs
- widgets.rs
- src/notify.rs
- pdh.rs
- alerts.rs
- AlertKind
- autostart.rs
- picker.rs
- sys/mod.rs
- icmp.rs
- sys/firewall.rs
- data.rs
- wfp.rs
- QosLimit
- abuseipdb/src/lib.rs
- RustWarden
- driver.rs
- netinfo.rs
- etw.rs
- ui/traffic.rs
- dest.rs
- windivert.rs
- conns.rs
- rules_file.rs
- helper.rs
- RustWarden features
- lease.rs
- sniff.rs
- asn.rs
- notify.rs
- steps
- live/qos.rs
- Call
- p2p.rs
- Address
- steps
- dnsguard.rs
- net.rs
- Dialog
- monitors.rs
- clock.rs
- hashset
- scandetect.rs
- steps
- Scale
- beacon.rs
- ConfirmAction
- latency.rs
- proc.rs
- ha/src/lib.rs
- speed.rs
- notes.rs
- opnsense/src/lib.rs
- TcpState
- watch.rs
- map.rs
- tlsprint.rs
- Windows system changes
- live/geo.rs
- toast.rs
- quota.rs
- arc
- services.rs
- connections.rs
- tamper.rs
- Monitors
- PluginFeed
- live/traffic.rs
- ask.rs
- .memory
- netpkt.rs
- alertrules.rs
- Priority
- AppRecord
- ui_tree.rs
- live/dns.rs
- latency.rs
- run
- Geo
- capture.rs
- PlanPeriod
- tray_menu.rs
- destrules.rs
- dnstunnel.rs
- Found
- windows_extras.rs
- guest.rs
- report.rs
- tcp_row
- st
- listeners
- Country
- pcwstr
- filedialog.rs
- Tab
- PWSTR
- err
- host.rs
- fluent.rs
- migrate.rs
- plugins.rs
- Creating a RustWarden plugin
- upnp.rs
- wallpaper.rs
- tray_menu.rs
- pathbuf
- live/traffic.rs
- netparse.rs
- ping/src/lib.rs
- RuleSpec
- sys/qos.rs
- saved_path
- sys/apps.rs
- .load
- DeviceKind
- .tick
- legacy.rs
- StatusNote
- export.rs
- util.rs
- store.rs
- wizard.rs
- Report
- DestRule
- hashmap
- vt.rs
- domains.rs
- NetInfoSource
- Vt
- HostCall
- Rule
- docs.yml
- Writing a RustWarden plugin
- curl.rs
- Priority
- loader.rs
- QuotaAction
- RustWarden
- AppGroup
- VirusTotal
- Target
- src/geo.rs
- countries.rs
- bundled.rs
- Answer
- QuotaLevel
- AlertLevel
- NetEvent
- pcwstr
- v1.21.3.md
- quiet
- live/mod.rs
- credits.rs
- Security Policy
- upnp/src/lib.rs
- arc
- ExtrasAct
- AppMode
- Notifications
- AGENTS.md
- Troubleshooting and FAQ
- build.rs
- v1.22.1.md
- PlanDirection
- OPNsense plugin
- Manual checks on a real machine
- 1.25.5: hotfix for false alerts and "unknown process" traffic
- uninstall_service
- QuotaStatus
- The Firewall tab
- tray.rs
- CaFile
- plan-release.sh
- Settings reference
- Held
- Traffic
- main.rs
- pathbuf
- flag_data.rs
- plugin-sdk
- Place
- PCWSTR
- TimeRange
- 1.23.3: a quieter, smarter behaviour baseline
- Driver mode
- Built-in plugins
- Installing and first run
- icons.rs
- Updates, backup and upkeep
- Speedtest
- Network Scanner
- Alerts
- Limits / QoS
- Key ideas
- Plugins
- Countries and lookups
- VPN
- Destination Rules
- The window
- Malicious IP and domain protection
- Quotas
- Alert rules
- Rescue: removing every RustWarden rule
- v1.20.6.md
- 1.25.1: hotfix for "Unknown process"
- Live Connections
- DNS Log
- Behaviour baseline
- path
- RustWarden user guide
- plugin-sdk/src/lib.rs
- Alert
- Hardware
- v1.20.0.md
- AccountChange
- settings.rs
- Third-party data and credits
- DnsEntry
- install_service
- Direction

## God Nodes (most connected - your core abstractions)
1. `Ui` - 156 edges
2. `Db` - 148 edges
3. `RustWarden` - 125 edges
4. `LiveBackend` - 113 edges
5. `Settings` - 112 edges
6. `Backend` - 103 edges
7. `MockBackend` - 91 edges
8. `Context` - 87 edges
9. `FwController` - 72 edges
10. `UiTree` - 71 edges

## Surprising Connections (you probably didn't know these)
- `style()` --references--> `Ui`  [INFERRED]
  src/ui/fluent.rs → plugin-sdk/src/lib.rs
- `Writer` --references--> `W`  [INFERRED]
  src/pcap.rs → build.rs
- `Host` --references--> `Call`  [INFERRED]
  src/plugins/wasm/host.rs → plugin-sdk/src/lib.rs
- `feeds()` --references--> `Ui`  [INFERRED]
  src/credits.rs → plugin-sdk/src/lib.rs
- `line()` --references--> `Ui`  [INFERRED]
  src/credits.rs → plugin-sdk/src/lib.rs

## Import Cycles
- 1-file cycle: `src/ui/dialogs.rs -> src/ui/dialogs.rs`
- 1-file cycle: `src/ui/map.rs -> src/ui/map.rs`
- 1-file cycle: `src/ui/mod.rs -> src/ui/mod.rs`
- 1-file cycle: `src/data.rs -> src/data.rs`
- 2-file cycle: `src/plugins/wasm/manager.rs -> src/plugins/wasm/ui_tree.rs -> src/plugins/wasm/manager.rs`

## Communities (259 total, 25 thin omitted)

### Community 0 - "live/firewall.rs"
Cohesion: 0.04
Nodes (69): ACTIVE_PROFILE_KEY, adopt_legacy_rules(), allow_engine_traffic(), ASK_KEY, ask_marker_exists(), ask_marker_path(), audit_prev_path(), block_all_exceptions() (+61 more)

### Community 1 - "LiveBackend"
Cohesion: 0.04
Nodes (3): db_path(), LiveBackend, verdict_shown()

### Community 2 - "UiTree"
Cohesion: 0.08
Nodes (26): UiTree, Button, Card, Column, Copy, Disabled, Dropdown, FileButton (+18 more)

### Community 3 - "theme.rs"
Cohesion: 0.08
Nodes (55): accent(), ACCENT, accent_default(), accent_replaces_the_defaults_and_clears(), accent_rgb(), accent_soft(), accent_text(), acrylic() (+47 more)

### Community 4 - "threat.rs"
Cohesion: 0.11
Nodes (30): a_failed_list_keeps_only_its_own_last_good_entries(), act(), add_name(), ALLOW_KEY, cache_keeps_list_names(), cache_path(), download(), feeds_keep_only_public_addresses() (+22 more)

### Community 5 - "MockBackend"
Cohesion: 0.05
Nodes (6): demo_bandwidth_limits_can_be_added_changed_and_cleared(), demo_destination_rules_add_replace_remove_and_reset(), demo_networks_keep_separate_devices_and_threat_lists(), demo_traffic_filter_narrows_the_sample_data(), DemoState, MockBackend

### Community 6 - "Icon"
Cohesion: 0.05
Nodes (40): Icon, Alerts, ArrowDown, ArrowUp, Bell, Bulb, Camera, Check (+32 more)

### Community 7 - "thinkbroadband/src/lib.rs"
Cohesion: 0.08
Nodes (54): ALERT_MAX_AGE_SECS, alert_pct(), attr(), backfill(), BASE, chart(), CHART_SQL, civil_from_days() (+46 more)

### Community 8 - "cloudflare/src/lib.rs"
Cohesion: 0.10
Nodes (34): args_for(), begin(), cfg(), demo_step(), each_step_runs_the_right_command(), event(), EXE, finished() (+26 more)

### Community 9 - "engine.rs"
Cohesion: 0.08
Nodes (33): a_limit_only_paces_the_directions_it_names(), die(), DROP_LIMIT, DROP_WINDOW_MS, Engine, filter_loop(), filter_needs_swap(), flow_loop() (+25 more)

### Community 10 - "Ui"
Cohesion: 0.05
Nodes (76): ThreatLists, P2pApp, Settings, about_click_hits(), ABOUT_CLICKS, ABOUT_PNG, accent_picker(), ACCENTS (+68 more)

### Community 11 - "webview.rs"
Cohesion: 0.09
Nodes (21): CHECK, CHECK_SECS, Ev, GiveUp, Loaded, Msg, fetch(), GIVE_UP_SECS (+13 more)

### Community 12 - "baseline.rs"
Cohesion: 0.04
Nodes (36): active_days_by_hour(), ASN_WAIT_SCANS, BUSY_HOUR, DAY, DIM_ASN, DIM_COUNTRY, DIM_DOMAIN, DIM_HOUR (+28 more)

### Community 13 - ".notify"
Cohesion: 0.14
Nodes (6): Confirm, mode_confirm(), profile_confirm(), RustWarden, set_mode_and_enable(), RustWarden

### Community 14 - "update.rs"
Cohesion: 0.05
Nodes (43): UpdateView, Available, CheckFailed, Checking, InstallFailed, Installing, Latest, UpdateChannel (+35 more)

### Community 15 - "guard.rs"
Cohesion: 0.10
Nodes (35): fingerprint(), GUARD_PREFIX, adapter(), ARMED_KEY, AUTO_RELEASE_AFTER_SECS, DOH_ADDRS, DOH_PREFIX, doh_specs() (+27 more)

### Community 16 - "Backend"
Cohesion: 0.04
Nodes (5): Backend, HardwareSnapshot, Verdict, Allowed, Blocked

### Community 17 - "manager.rs"
Cohesion: 0.09
Nodes (17): broadcast_alert(), deliver_alert(), deserialize(), HELD_MAX, intern(), MAX_FILE, OFFLINE, Open (+9 more)

### Community 18 - "Context"
Cohesion: 0.12
Nodes (4): cell(), Context, RustWarden, screen_size()

### Community 19 - ".default"
Cohesion: 0.12
Nodes (14): a_secret_sealed_for_someone_else_is_not_imported(), alert_rules_are_sanitized_and_survive_a_save(), app_mode_defaults_to_normal_and_round_trips(), baseline_settings_are_clamped(), export_round_trips_and_leaves_out_the_password(), import_keeps_what_the_file_lacks_and_skips_what_it_cannot_read(), nan_scale_is_reset(), pending_blocks_survive_a_save_and_load() (+6 more)

### Community 20 - "live/apps.rs"
Cohesion: 0.10
Nodes (21): core_services_are_refused_and_other_services_are_not(), CRITICAL_SERVICES, describe_change(), ensure_record(), ensure_service_record(), file_name(), is_svchost(), is_vpn_client() (+13 more)

### Community 21 - "speedtest/src/lib.rs"
Cohesion: 0.09
Nodes (35): SpeedLive, demo_history(), demo_live(), demo_readings_ramp_up_through_the_three_phases(), demo_result(), DEMO_STEP_MS, DEMO_TEST_SECS, event() (+27 more)

### Community 22 - "live/scanner.rs"
Cohesion: 0.11
Nodes (28): arp_probe(), Found, MAX_PREFIX_HOSTS, nbstat(), nbstat_request(), networks(), oui_map(), OUI_TABLE (+20 more)

### Community 23 - "Db"
Cohesion: 0.06
Nodes (7): row(), app_records_and_missing_state(), Db, .APP_COLS, DeviceRow, devices_keep_user_names_and_go_offline(), dns_log_round_trips_and_prunes()

### Community 24 - "demo.rs"
Cohesion: 0.07
Nodes (30): bump(), demo_alerts(), demo_apps(), demo_block_all_shows_active(), demo_connections(), demo_connections_have_sample_rows(), demo_dest_rules(), demo_devices() (+22 more)

### Community 25 - "FwController"
Cohesion: 0.12
Nodes (12): extras_paused(), extras_rules(), FwController, is_aux(), is_ours(), paused_extras(), profile_since(), removed_apps() (+4 more)

### Community 26 - "traffic_load.rs"
Cohesion: 0.10
Nodes (20): Scope, .ALL, Both, Lan, Wan, TrafficDir, .ALL, Both (+12 more)

### Community 27 - "popup.rs"
Cohesion: 0.07
Nodes (29): ThreatAct, Block, Unblock, Unwhitelist, Whitelist, ALERT_INFO_TITLE, ALERT_TITLE, ALERTS_SECTION (+21 more)

### Community 28 - "widgets.rs"
Cohesion: 0.08
Nodes (48): Ui, labelled(), startup_controls(), fit_text(), area(), area_faded(), area_faded_to(), area_impl() (+40 more)

### Community 29 - "src/notify.rs"
Cohesion: 0.05
Nodes (48): simplify(), Discord, .FIELDS, .HOSTS, .ID, .NAME, DISCORD_URLS, Field (+40 more)

### Community 30 - "pdh.rs"
Cohesion: 0.10
Nodes (12): engine_type(), expand(), gpu_load(), GpuQuery, Handle, Pdh, ProcQuery, Query (+4 more)

### Community 31 - "alerts.rs"
Cohesion: 0.07
Nodes (30): a_reused_dhcp_address_is_not_spoofing(), adapter_ignored(), anomaly_kinds_have_keys_and_switches(), arp_mac_change_is_reported_once(), ArpChange, device_events(), device_events_find_new_changed_multi_and_returned(), device_use_reports_new_and_later_uses() (+22 more)

### Community 32 - "AlertKind"
Cohesion: 0.05
Nodes (41): AlertKind, .ALL, AnomalyContact, AnomalyHour, AnomalyVolume, AppChanged, Arp, Away (+33 more)

### Community 33 - "autostart.rs"
Cohesion: 0.07
Nodes (15): CHILD, claim_instance(), EVENTS, LAUNCH, LAUNCH_HIDDEN, MOVED_TO, REFUSED, RUN_KEY (+7 more)

### Community 34 - "picker.rs"
Cohesion: 0.05
Nodes (14): find(), find_all(), MAIN, app_in(), each_window(), is_frame_host(), Pick, proc() (+6 more)

### Community 35 - "sys/mod.rs"
Cohesion: 0.08
Nodes (21): file_icon_rgba(), has_valid_embedded_signature(), service_has_sid(), from_wide(), hidden_start(), home_region(), message(), NO_WINDOW (+13 more)

### Community 36 - "icmp.rs"
Cohesion: 0.10
Nodes (9): AT_ONCE, echo(), echoes(), MAX_ADDRS, ping_v4(), ping_v6(), Round, round() (+1 more)

### Community 37 - "sys/firewall.rs"
Cohesion: 0.06
Nodes (6): PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC, PROFILES, ProfileState, PROTO_ANY

### Community 38 - "data.rs"
Cohesion: 0.04
Nodes (48): LogState, ActiveCountries, AlertDest, .ALL, Any, Local, Remote, AlertFilter (+40 more)

### Community 39 - "wfp.rs"
Cohesion: 0.06
Nodes (17): auditpol(), blocked_since(), data(), failure_audit_on(), parse_events(), reads_outbound_drops_only(), set_failure_audit(), SUBCATEGORY (+9 more)

### Community 40 - "QosLimit"
Cohesion: 0.08
Nodes (16): decode_all(), directions_round_trip_and_old_lines_still_read(), encode_all(), fmt_rate(), limit(), MAX_DELAY_MS, MAX_KBPS, MAX_LIMITS (+8 more)

### Community 41 - "abuseipdb/src/lib.rs"
Cohesion: 0.16
Nodes (18): AbuseIpDb, DEFAULT_ALERT_SCORE, demo_verdict(), FRESH_SECS, is_public(), KEEP, key_ok(), lookup() (+10 more)

### Community 42 - "RustWarden"
Cohesion: 0.05
Nodes (29): BLOCK_AFTER_MINS, BlockProgram, ConnsState, default_window(), DestDraft, About, DnsState, DomainDraft (+21 more)

### Community 43 - "driver.rs"
Cohesion: 0.09
Nodes (28): BLOCKED_HELP, dir(), DLL, DriverState, Blocked, Missing, Ready, folder_state_tells_missing_ready_and_blocked_apart() (+20 more)

### Community 44 - "netinfo.rs"
Cohesion: 0.08
Nodes (12): adapters(), adapters_and_neighbors_are_readable(), host_routes(), idle_seconds(), is_tunnel(), is_virtual(), Neighbor, neighbors() (+4 more)

### Community 45 - "etw.rs"
Cohesion: 0.06
Nodes (32): cached_path(), decode(), dns_answer_maps_name_to_addresses(), DNS_CLIENT, dns_payload(), DROPPED, failed_lookup_is_logged_without_addresses(), forget_dead() (+24 more)

### Community 46 - "ui/traffic.rs"
Cohesion: 0.10
Nodes (13): RustWarden, RustWarden, blur_averages_and_keeps_length(), box_blur(), row_in(), tick_step(), command_card(), command_card_id() (+5 more)

### Community 47 - "dest.rs"
Cohesion: 0.12
Nodes (16): DestRuleView, MAX_RULES_PER_DEST, Dest, DNS_WINDOW, firewall_rules_belong_to_their_destination_rule(), id_of(), load(), name_changes_with_the_address_list_program_and_mode_only() (+8 more)

### Community 48 - "windivert.rs"
Cohesion: 0.08
Nodes (21): ChecksumFn, CloseFn, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED, FLAG_DROP, FLAG_RECV_ONLY, FLAG_SNIFF, flow_address() (+13 more)

### Community 49 - "conns.rs"
Cohesion: 0.07
Nodes (3): ENABLED, STATE_ESTABLISHED, STATE_SYN_SENT

### Community 50 - "rules_file.rs"
Cohesion: 0.16
Nodes (13): a_file_survives_writing_and_reading(), AppRule, current_of(), destination_rules_are_added_once_and_get_fresh_ids(), file(), FORMAT, matching_state_plans_nothing(), old_files_without_settings_or_lists_still_load() (+5 more)

### Community 51 - "helper.rs"
Cohesion: 0.12
Nodes (25): a_program_that_isnt_downloaded_is_refused_before_anything_runs(), a_programs_folders_are_copied_with_their_files(), adopt(), adopt_user_copy(), adopts_only_a_genuine_copy(), cached_sha(), CHECKED, confirmed() (+17 more)

### Community 52 - "RustWarden features"
Cohesion: 0.12
Nodes (17): 🚨 Alerts and log analysis, 🧭 Behaviour baseline, Clean up, 📏 Data quotas, 🔎 DNS Log, ⚙️ Everything else, 🛡️ Firewall: your firewall, simplified, 📈 Hardware resources (+9 more)

### Community 53 - "lease.rs"
Cohesion: 0.14
Nodes (21): before_spawn(), check_again_at(), decode(), due(), encode(), end(), end_all(), GROUP (+13 more)

### Community 54 - "sniff.rs"
Cohesion: 0.07
Nodes (40): a_udp_flow_filter_names_both_directions_and_one_ip_version(), dhcp_reply(), FILTER, flow_loop(), Flows, kill_udp(), MAX_FLOWS, packet_loop() (+32 more)

### Community 55 - "asn.rs"
Cohesion: 0.15
Nodes (15): curl_url(), cymru(), cymru_name(), cymru_names_are_reversed(), format_info(), from_json(), http(), json_val() (+7 more)

### Community 56 - "notify.rs"
Cohesion: 0.09
Nodes (6): balloon(), copy(), copy_truncates_and_terminates(), icon(), LINGER, worker()

### Community 57 - "steps"
Cohesion: 0.07
Nodes (27): run, GH_TOKEN, RUSTFLAGS, TAG_MATCH, UPDATE_SIGNING_KEY, jobs, release, name (+19 more)

### Community 58 - "live/qos.rs"
Cohesion: 0.13
Nodes (10): KEY, load(), NEEDS_ADMIN, Qos, remove_orphans(), run(), saved_limits_round_trip_through_the_store(), store() (+2 more)

### Community 59 - "Call"
Cohesion: 0.05
Nodes (49): Guest, API_VERSION, Call, Alert, Event, HelperDone, HelperLine, Manifest (+41 more)

### Community 60 - "p2p.rs"
Cohesion: 0.14
Nodes (19): P2P_PREFIX, blocked_keys(), blocks_only_with_detection_on_and_no_vpn(), BROWSERS, CLIENTS, Detector, ip(), is_peer_port() (+11 more)

### Community 61 - "Address"
Cohesion: 0.15
Nodes (3): Address, FlowInfo, Handle

### Community 62 - "steps"
Cohesion: 0.07
Nodes (26): run, GH_TOKEN, RUSTFLAGS, UPDATE_SIGNING_KEY, jobs, release, name, on (+18 more)

### Community 63 - "dnsguard.rs"
Cohesion: 0.16
Nodes (14): Action, Pass, Redirect, Restore, decide(), FILTER, Guard, KEEP (+6 more)

### Community 64 - "net.rs"
Cohesion: 0.14
Nodes (18): classify(), classify_v4(), classify_v6(), dns_results_are_scanned_for_addresses(), ip(), ips_in_dns_results(), is_cgnat(), Locality (+10 more)

### Community 65 - "Dialog"
Cohesion: 0.12
Nodes (16): Dialog, Confirm, Info, InstallService, NewProfile, Password, Rename, Report (+8 more)

### Community 66 - "monitors.rs"
Cohesion: 0.12
Nodes (19): Debounce, diff_files(), per_user_base(), plan_level(), PlanLevel, Over, Warning, arp_snapshot() (+11 more)

### Community 67 - "clock.rs"
Cohesion: 0.14
Nodes (13): civil_from_days(), day_label(), days_from_civil(), file_stamp(), fmt_date(), fmt_stamp(), fmt_time_lower(), local_offset_at() (+5 more)

### Community 68 - "hashset"
Cohesion: 0.11
Nodes (9): a_domain_covers_everything_below_it_but_not_lookalikes(), decode_all(), DomainRule, DomainView, encode_all(), MAX_LIST, MAX_RULES, normalize() (+1 more)

### Community 69 - "scandetect.rs"
Cohesion: 0.18
Nodes (12): a_burst_from_many_sources_is_a_flood(), Detector, Finding, PortScan, SynFlood, FLOOD_PER_SEC, ip(), many_ports_from_one_source_is_a_scan_reported_once() (+4 more)

### Community 70 - "steps"
Cohesion: 0.08
Nodes (23): run, GALLIUM_DRIVER, MESA_SHA256, RUSTWARDEN_SHOTS, jobs, screenshots, name, on (+15 more)

### Community 71 - "Scale"
Cohesion: 0.13
Nodes (12): Scale, .ALL, S1, S30, S600, Dim, App, Proto (+4 more)

### Community 72 - "beacon.rs"
Cohesion: 0.07
Nodes (35): a_browser_is_not_exempt(), a_cdn_suffix_lowers_the_level_without_hiding_it(), a_steady_timer_is_reported_once(), already_excluded(), an_unsigned_program_with_tiny_uniform_payloads_to_a_rare_host_is_reported(), Beat, BULK_PER_MIN, cfg() (+27 more)

### Community 73 - "ConfirmAction"
Cohesion: 0.10
Nodes (20): ConfirmAction, ApplyRules, BlockWindowsExtras, CleanUp, ClearHistory, DeleteProfile, FirewallEnabled, FirewallMode (+12 more)

### Community 74 - "latency.rs"
Cohesion: 0.18
Nodes (9): calendar(), day_shift(), Feed, Line, refresh_status(), reload(), State, tab() (+1 more)

### Community 75 - "proc.rs"
Cohesion: 0.05
Nodes (26): a_long_script_runs_from_the_environment_and_a_long_command_line_falls_back(), Child, command_line(), dir_ptr_or(), environment(), environment_changes_are_applied_and_nothing_means_inherit(), inheritable(), MAX_LINE (+18 more)

### Community 76 - "ha/src/lib.rs"
Cohesion: 0.11
Nodes (26): event(), explain(), Ha, headers(), known(), LOGO, lookup(), next_due() (+18 more)

### Community 77 - "speed.rs"
Cohesion: 0.08
Nodes (30): SpeedPage, result_of(), query_speed(), arc_mesh(), card_frame(), chart(), dial_frac(), DIAL_START (+22 more)

### Community 78 - "notes.rs"
Cohesion: 0.20
Nodes (10): Device, DeviceNote, Annotator, device_kind(), device_url(), display_name(), flag(), ICON (+2 more)

### Community 79 - "opnsense/src/lib.rs"
Cohesion: 0.06
Nodes (53): flag(), a_leftover_alias_is_reported(), a_read_check_keeps_the_earlier_write_result(), a_read_only_key_cannot_push(), a_read_only_key_is_told_apart(), a_writable_key_creates_then_removes_the_test_alias(), Added, Denied (+45 more)

### Community 80 - "TcpState"
Cohesion: 0.13
Nodes (14): state_raw(), TcpState, Closed, CloseWait, Closing, DeleteTcb, Established, FinWait1 (+6 more)

### Community 81 - "watch.rs"
Cohesion: 0.14
Nodes (9): device_use(), open(), root_certs(), RUN_KEYS, service_names(), snapshots_read_the_registry(), startup_entries(), subkeys() (+1 more)

### Community 82 - "map.rs"
Cohesion: 0.22
Nodes (13): ARC, blocked_color(), clamp_center(), home_dot(), land(), land_active(), land_edge(), land_hover() (+5 more)

### Community 83 - "tlsprint.rs"
Cohesion: 0.20
Nodes (17): grease(), Hello, hello(), ja3(), ja3_drops_grease_and_is_the_md5_of_its_text(), ja3_text(), ja4(), ja4_follows_the_layout() (+9 more)

### Community 84 - "Windows system changes"
Cohesion: 0.05
Nodes (42): Alert types, Application info monitor, ARP spoofing detection, Beaconing detection, Behaviour baseline, Behaviour: new country, network or domain, Behaviour: traffic spike, Behaviour: unusual hour (+34 more)

### Community 85 - "live/geo.rs"
Cohesion: 0.14
Nodes (11): asn_db_path(), city_db_path(), DATABASES, db_path(), DbInfo, default_db_path(), download_dbip(), download_script() (+3 more)

### Community 86 - "toast.rs"
Cohesion: 0.06
Nodes (55): ANIM_SECS, app_tile(), button(), button_colors(), checkbox(), CHEVRON_W, chrome(), chrome_edged() (+47 more)

### Community 87 - "quota.rs"
Cohesion: 0.23
Nodes (17): action_none_only_warns(), block_is_asked_for_until_it_happens(), clock_moved_back_starts_a_fresh_period(), Decision, deleted_disabled_or_retargeted_quotas_orphan_their_track(), jumping_straight_over_alerts_once(), KV_KEY, level() (+9 more)

### Community 88 - "arc"
Cohesion: 0.16
Nodes (13): a_slow_client_cannot_hold_the_endpoint(), bind_retrying(), Endpoint, exchange(), handle(), label(), LOG, metrics_answers_loopback_requests() (+5 more)

### Community 89 - "services.rs"
Cohesion: 0.15
Nodes (8): by_pid(), label(), lists_running_services(), one_service_is_named_with_its_short_name(), SC_MANAGER_ENUMERATE_SERVICE, Service, shared_hosts_are_keyed_in_a_stable_order(), svc()

### Community 90 - "connections.rs"
Cohesion: 0.07
Nodes (23): LiveConn, Act, Block, Capture, Kill, compare(), conn(), ConnGroup (+15 more)

### Community 91 - "tamper.rs"
Cohesion: 0.16
Nodes (10): copy_path(), digest(), hash(), hex(), recall(), remember(), ROUNDS, salt() (+2 more)

### Community 93 - "PluginFeed"
Cohesion: 0.16
Nodes (3): query_samples(), Missing, PluginFeed

### Community 94 - "live/traffic.rs"
Cohesion: 0.14
Nodes (9): TrafficDelta, kernel_service(), Aggregator, Collector, is_vpn_outer(), Names, publish_geo_note(), recent_names() (+1 more)

### Community 95 - "ask.rs"
Cohesion: 0.18
Nodes (13): icon_for(), count(), fw_closed_since(), IN_FLIGHT, is_noise(), lookups_on(), MAX_IN_FLIGHT, MAX_OPEN_ASKS (+5 more)

### Community 96 - ".memory"
Cohesion: 0.08
Nodes (27): AlertCheck, add_column(), alert_chain_survives_reads_and_names_the_first_change(), alert_hash(), alerts_round_trip_and_mark_read(), BASE_LEARNED, blocked_attempts_add_up_prune_and_clear(), chained() (+19 more)

### Community 97 - "netpkt.rs"
Cohesion: 0.14
Nodes (16): pkt(), limited_ports(), addresses_can_be_swapped_in_ipv4_only(), FlowKey, ipv4_tcp(), parse(), Parsed, reads_ipv4_tcp_and_both_directions_share_one_flow() (+8 more)

### Community 98 - "alertrules.rs"
Cohesion: 0.09
Nodes (27): AlertInfo, AlertRule, ALL_DAYS, conditions_all_have_to_hold(), contains_nocase(), DAY_NAMES, decide(), Effect (+19 more)

### Community 99 - "Priority"
Cohesion: 0.12
Nodes (10): LimitDir, .ALL, Both, Down, Up, Priority, .ALL, High (+2 more)

### Community 100 - "AppRecord"
Cohesion: 0.23
Nodes (8): learning_note(), local_day_hour(), new_item(), run(), throttled(), Worker, AppRecord, BaselineItem

### Community 101 - "ui_tree.rs"
Cohesion: 0.14
Nodes (9): chart(), CHARTS, draw(), Env, file_button(), flag(), Picked, show() (+1 more)

### Community 102 - "live/dns.rs"
Cohesion: 0.12
Nodes (19): a_failed_feed_keeps_only_its_own_names(), cache_path(), check(), clean(), domain_of(), download(), each_program_and_name_is_reported_once(), hits() (+11 more)

### Community 103 - "latency.rs"
Cohesion: 0.19
Nodes (17): BLUE, camera(), column_count(), columns(), columns_keep_the_extremes_and_average_the_rest(), export(), FLASH_SECS, FOOTER_H (+9 more)

### Community 104 - "run"
Cohesion: 0.16
Nodes (15): Active, HELD, Job, Alert, Call, Event, Stop, Pages (+7 more)

### Community 105 - "Geo"
Cohesion: 0.23
Nodes (4): asn_networks(), country_networks_cover_addresses_the_database_places_there(), Geo, shared_reader()

### Community 108 - "capture.rs"
Cohesion: 0.18
Nodes (3): Capture, Session, CaptureStatus

### Community 109 - "PlanPeriod"
Cohesion: 0.17
Nodes (11): PeriodKind, Day, Month, Week, period_kind(), period_word(), PlanPeriod, .ALL (+3 more)

### Community 110 - "tray_menu.rs"
Cohesion: 0.04
Nodes (33): png(), texture(), scene(), triangle(), PendingBlock, Theme, theme_button_cycles_system_light_dark(), theme_choice_is_system_light_or_dark() (+25 more)

### Community 111 - "destrules.rs"
Cohesion: 0.11
Nodes (18): block_mode_never_touches_the_local_network(), blocked_set(), complement_covers_everything_else(), ip(), local_ranges(), long_lists_are_split_into_rules_within_the_limits(), MAX_CHARS_PER_RULE, MAX_RANGES_PER_RULE (+10 more)

### Community 112 - "dnstunnel.rs"
Cohesion: 0.09
Nodes (27): BASE_ALERTED, BASE_NORMAL, a_domain_marked_normal_stays_quiet(), addresses_written_as_names_are_not_data(), ANY_APP, CLEANED, clear_false_reports(), DIM (+19 more)

### Community 113 - "Found"
Cohesion: 0.18
Nodes (15): a_changed_hash_is_not_approved(), apply(), Found, inspect(), install(), plugin_dir(), reconcile(), scan() (+7 more)

### Community 114 - "windows_extras.rs"
Cohesion: 0.21
Nodes (9): expand(), Group, GROUPS, is_protected(), matches(), PROTECTED, resolve(), t() (+1 more)

### Community 115 - "guest.rs"
Cohesion: 0.12
Nodes (40): __alloc(), blocked_addresses(), browser_fetch(), browser_sign_in(), browser_sign_out(), __call(), config_get(), config_set() (+32 more)

### Community 116 - "report.rs"
Cohesion: 0.17
Nodes (18): a_report_is_due_once_per_slot(), build(), build_finds_new_hosts_only_with_older_history(), country_of(), due(), KV_LAST, last_slot(), LISTED (+10 more)

### Community 117 - "tcp_row"
Cohesion: 0.18
Nodes (12): ConnRow, filetime_to_unix(), fill_bytes(), kill(), killable(), raw_port(), read_bytes(), row_uses_network_byte_order() (+4 more)

### Community 118 - "st"
Cohesion: 0.18
Nodes (14): annotates(), annotator(), annotator_ids(), any_notification_plugin(), granted_settings(), Render, lock(), note() (+6 more)

### Community 119 - "listeners"
Cohesion: 0.20
Nodes (8): Conn, fetch(), fetch_class(), is_listening(), Listener, listeners(), port_of(), tcp()

### Community 120 - "Country"
Cohesion: 0.18
Nodes (11): Country, France, Germany, Ireland, Iso, Local, Netherlands, Other (+3 more)

### Community 121 - "pcwstr"
Cohesion: 0.12
Nodes (6): protect(), round_trips_and_rejects_garbage(), take(), unprotect(), EVENT_ID, write()

### Community 122 - "filedialog.rs"
Cohesion: 0.13
Nodes (5): filter_list(), filter_list_is_double_null_terminated_with_all_files_last(), MAX_TEXT_BYTES, open(), open_async()

### Community 123 - "Tab"
Cohesion: 0.06
Nodes (23): every_tab_has_its_own_key_that_reads_back(), Tab, AlertRules, .ALL, Bandwidth, Connections, DestRules, Dns (+15 more)

### Community 124 - "PWSTR"
Cohesion: 0.25
Nodes (8): handler(), launch_gui(), logon_hidden(), make_events(), report(), report_step(), run_dispatcher(), service_main()

### Community 125 - "err"
Cohesion: 0.21
Nodes (15): add_rule(), adopt_rule(), bool_variant(), default_outbound_blocked(), enable_windows_firewall(), err(), interfaces_variant(), is_not_found() (+7 more)

### Community 126 - "host.rs"
Cohesion: 0.08
Nodes (24): HostReply, Err, Ok, a_keypair_is_32_bytes_each_and_the_public_key_follows_from_the_private(), a_pinned_ca_skips_the_revocation_lookup_a_private_ca_cannot_answer(), a_plugin_cannot_keep_a_transaction_open_or_run_for_ever(), a_value_cannot_break_out_of_the_curl_config(), answer() (+16 more)

### Community 128 - "migrate.rs"
Cohesion: 0.25
Nodes (13): DONE, merge_dir(), merge_keeps_what_the_new_folder_has(), move_program_files(), move_user_data(), OLD, rename_in_db(), run() (+5 more)

### Community 129 - "plugins.rs"
Cohesion: 0.14
Nodes (20): beta_hidden(), beta_shows_hidden_plugins_and_locking_uninstalls_them(), card(), CREATE_URL, files(), listed(), mark(), Modal (+12 more)

### Community 130 - "Creating a RustWarden plugin"
Cohesion: 0.13
Nodes (15): 1. Set up, 2. Create the crate, 3. Write the plugin, 4. Keep state, 5. Talk to the network (optional), 6. Run in the background (optional), 7. Ask for permissions (optional), 8. Build (+7 more)

### Community 131 - "upnp.rs"
Cohesion: 0.24
Nodes (7): discover(), Gateway, lan_addr(), local_networks(), location_of(), private(), SEARCH

### Community 132 - "wallpaper.rs"
Cohesion: 0.11
Nodes (7): W, Writer, dword(), windows_accent(), windows_dark(), reg_str(), set_wallpaper()

### Community 133 - "tray_menu.rs"
Cohesion: 0.05
Nodes (35): Capabilities, FirewallInfo, FirewallMode, .ALL, AskToConnect, BlockAll, ClickToBlock, PROMPT_FOR (+27 more)

### Community 134 - "pathbuf"
Cohesion: 0.39
Nodes (8): disable(), disables_the_features_that_use_downloads(), remove(), removes_files_and_folders_and_ignores_missing(), run(), size(), targets(), warning()

### Community 135 - "live/traffic.rs"
Cohesion: 0.17
Nodes (18): KIND_LAN, KIND_UNKNOWN, a_tls_server_name_names_its_own_programs_traffic(), aggregator_sums_by_key(), ev(), Flow, flow_of(), ip() (+10 more)

### Community 136 - "netparse.rs"
Cohesion: 0.25
Nodes (10): client_hello(), dns(), DnsMessage, finds_the_server_name_and_refuses_junk(), host_ok(), name_at(), query(), reads_queries_and_answers_with_compressed_names() (+2 more)

### Community 137 - "ping/src/lib.rs"
Cohesion: 0.13
Nodes (22): add_form(), chart(), CHART_SQL, clean(), demo_row(), demo_rows_are_sane_and_stable(), DEMO_SPAN, event() (+14 more)

### Community 138 - "RuleSpec"
Cohesion: 0.22
Nodes (8): a_service_rule_is_a_separate_row_with_its_own_name(), block_spec(), block_specs_are_scoped_to_one_program_and_direction(), icmp_specs(), lan_block_is_its_own_outbound_rule(), lan_specs(), ping_rules_are_ours_allow_icmp_and_stay_off_the_program_list(), RuleSpec

### Community 139 - "sys/qos.rs"
Cohesion: 0.21
Nodes (9): add_exclusion(), remove_exclusion(), apply(), list(), parse_policy(), Policy, powershell(), remove() (+1 more)

### Community 140 - "saved_path"
Cohesion: 0.21
Nodes (14): table_prefix(), drop_tables(), erase(), forget_recent(), load_saved(), remove(), repaint(), save_saved() (+6 more)

### Community 141 - "sys/apps.rs"
Cohesion: 0.09
Nodes (6): current_process_has_a_path(), notepad_like_system_binary_has_version_info(), pid_path(), running_paths(), version_info(), VersionInfo

### Community 142 - ".load"
Cohesion: 0.15
Nodes (10): config_dir(), config_path(), env_dir(), Mode, Demo, Live, plugin_decisions_survive_the_admin_copy_and_junk_reads_as_none(), plugins_copy_path() (+2 more)

### Community 143 - "DeviceKind"
Cohesion: 0.20
Nodes (9): DeviceKind, Generic, Laptop, Raspberry, SmartDevice, WiFi, guess_kind(), kind_from_i64() (+1 more)

### Community 144 - ".tick"
Cohesion: 0.18
Nodes (10): orphaned(), run(), Track, tracks_from_text(), tracks_round_trip_through_text(), tracks_to_text(), used_by(), user_blocked() (+2 more)

### Community 145 - "legacy.rs"
Cohesion: 0.15
Nodes (23): ha_config(), migrate_tables(), NOTIFICATIONS, old_ping_rows_move_into_the_plugin_table_once(), old_speedtest_rows_move_into_the_plugin_table(), old_thinkbroadband_samples_move_into_the_plugin_table(), old_values(), old_values_are_found_trimmed_and_empty_ones_skipped() (+15 more)

### Community 146 - "StatusNote"
Cohesion: 0.18
Nodes (5): NoteLevel, Info, Vpn, Warn, StatusNote

### Community 147 - "export.rs"
Cohesion: 0.26
Nodes (9): a_value_that_looks_like_a_formula_is_made_text(), AlertRow, alerts_csv(), csv_keeps_awkward_values_in_one_cell(), json(), json_uses_field_names(), traffic_csv(), traffic_csv_has_one_line_per_row_after_the_header() (+1 more)

### Community 148 - "util.rs"
Cohesion: 0.07
Nodes (24): animate(), app_icon_rgba(), async_memo_answers_none_until_the_read_lands_then_keeps_it(), AsyncMemo, AsyncMemo<K, V>, Bg, bg_runs_the_latest_waiting_request_and_reports_a_panic_once(), Bg<T> (+16 more)

### Community 149 - "store.rs"
Cohesion: 0.09
Nodes (21): ConnectAsk, a_mute_rule_records_the_alert_but_shows_nothing(), a_quiet_alert_is_logged_read_without_a_popup_even_when_escalated(), ALERT_SINK, an_escalate_rule_makes_an_alert_important_with_a_popup(), blocked_addresses(), country_of(), HwNow (+13 more)

### Community 150 - "wizard.rs"
Cohesion: 0.24
Nodes (12): alerts(), databases(), firewall(), firewall_note(), show(), Step, Finish, Keep (+4 more)

### Community 151 - "Report"
Cohesion: 0.25
Nodes (5): new_line(), Report, sample(), text_lists_every_section(), text_says_when_history_is_too_short_and_stays_under_the_limit()

### Community 152 - "DestRule"
Cohesion: 0.15
Nodes (7): demo_dest_status(), decode_all(), DestRule, encode_all(), Mode, Block, OnlyAllow

### Community 153 - "hashmap"
Cohesion: 0.22
Nodes (5): Counters, delta(), IF_OPER_STATUS_UP, IF_TYPE_SOFTWARE_LOOPBACK, read()

### Community 154 - "vt.rs"
Cohesion: 0.09
Nodes (22): json_find(), a_hash_virustotal_has_not_seen_is_never_uploaded_by_itself(), a_hash_with_a_final_answer_is_not_looked_up_or_sent_again(), API, curl(), HOLD, HOLD_AFTER, key() (+14 more)

### Community 155 - "domains.rs"
Cohesion: 0.13
Nodes (13): Matcher, Domains, FILTER, FILTER_BROAD, KEY, list_path(), load_rules(), packet_loop() (+5 more)

### Community 156 - "NetInfoSource"
Cohesion: 0.33
Nodes (5): NetInfoSource, .ALL, Http, Off, TeamCymru

### Community 157 - "Vt"
Cohesion: 0.15
Nodes (12): Vt, Analysing, Failed, None, NotFound, OnHold, Pending, Result (+4 more)

### Community 158 - "HostCall"
Cohesion: 0.07
Nodes (29): HostCall, BlockedAddresses, BrowserFetch, BrowserSignIn, BrowserSignOut, ConfigGet, ConfigSet, DbExec (+21 more)

### Community 159 - "Rule"
Cohesion: 0.39
Nodes (8): enabled_outbound_allows(), enabled_outbound_blocks(), read_rule(), reading_rules_works_without_administrator(), Rule, rules_in_group(), rules_named(), rules_where()

### Community 160 - "docs.yml"
Cohesion: 0.06
Nodes (35): if, runs-on, steps, concurrency, cancel-in-progress, group, environment, needs (+27 more)

### Community 161 - "Writing a RustWarden plugin"
Cohesion: 0.22
Nodes (9): Build, Calls into your plugin, Install, Notification services, Pages, Rules your plugin must follow, The code, What you may ask RustWarden for (+1 more)

### Community 162 - "curl.rs"
Cohesion: 0.27
Nodes (4): globbing_is_off(), PROTO, refuses_other_protocols(), run()

### Community 163 - "Priority"
Cohesion: 0.24
Nodes (6): Line, Plan, At, Drop, Pass, the_line_serves_high_first_and_squeezes_the_rest()

### Community 164 - "loader.rs"
Cohesion: 0.11
Nodes (20): restrict_db(), a_wrong_api_version_is_refused(), an_infinite_loop_is_stopped_by_the_fuel_limit(), call_tick(), engine(), FUEL, hash_of(), host_calls_are_checked_by_the_host() (+12 more)

### Community 165 - "QuotaAction"
Cohesion: 0.20
Nodes (7): QuotaAction, AlertOnly, .ALL, Block, None, Throttle, ThrottleBlock

### Community 166 - "RustWarden"
Cohesion: 0.25
Nodes (8): Acknowledgements, Build from source, Built to be safe, Download, Project layout, Rescue: remove every RustWarden firewall rule, RustWarden, What it does

### Community 167 - "AppGroup"
Cohesion: 0.29
Nodes (6): AppGroup, Active, .ALL, Inactive, Uninstalled, Windows

### Community 168 - "VirusTotal"
Cohesion: 0.29
Nodes (6): Demo mode, Reading the score, Setting it up, Uploading a file, VirusTotal, What is sent

### Community 169 - "Target"
Cohesion: 0.33
Nodes (5): only_allow_needs_a_program(), Target, Asn, Country, Domain

### Community 170 - "src/geo.rs"
Cohesion: 0.26
Nodes (7): Country, load(), no_giant_triangles(), Poly, Reader, world(), WORLD_BIN

### Community 171 - "countries.rs"
Cohesion: 0.31
Nodes (6): by_a2(), Entry, table!, parse_a2(), parse_name_or_a2(), search()

### Community 172 - "bundled.rs"
Cohesion: 0.20
Nodes (16): every_built_in_plugin_loads_with_its_own_id(), found(), load(), bundle!, the_abuseipdb_plugin_scores_addresses_in_alerts(), the_cloudflare_plugin_pretends_in_demo(), the_home_assistant_plugin_keeps_its_settings_and_waits_for_a_token(), the_opnsense_plugin_gates_its_options_on_a_probe() (+8 more)

### Community 173 - "Answer"
Cohesion: 0.40
Nodes (3): Answer, Allow, Block

### Community 174 - "QuotaLevel"
Cohesion: 0.50
Nodes (4): QuotaLevel, Ok, Over, Warn

### Community 175 - "AlertLevel"
Cohesion: 0.33
Nodes (4): AlertLevel, .ALL, Important, Logs

### Community 176 - "NetEvent"
Cohesion: 0.14
Nodes (11): EtwSession, inject(), NetEvent, Data, Dns, Sni, PATHS, Props (+3 more)

### Community 177 - "pcwstr"
Cohesion: 0.15
Nodes (7): LINKTYPE_RAW, MAX_BYTES, MAX_SECS, tcp_filter(), the_filter_names_both_directions_of_one_connection(), Writer<W>, writes_the_pcap_header_and_records()

### Community 179 - "quiet"
Cohesion: 0.20
Nodes (16): authorize_stop(), end_other_instances(), end_processes(), ensure_service_running(), ok(), prepare_debug(), quiet(), remove_legacy_service() (+8 more)

### Community 180 - "live/mod.rs"
Cohesion: 0.08
Nodes (20): DetailRow, Glyph, App, Flag, More, Window, UsageBreakdown, UsageDetail (+12 more)

### Community 181 - "credits.rs"
Cohesion: 0.24
Nodes (13): DBIP, feed_source(), feed_sources(), feeds(), FEEDS, known_feeds_are_credited_to_their_publisher(), line(), Source (+5 more)

### Community 182 - "Security Policy"
Cohesion: 0.29
Nodes (6): Design notes, Reporting a vulnerability, Scope, Security Policy, Supported versions, What to expect

### Community 183 - "upnp/src/lib.rs"
Cohesion: 0.11
Nodes (33): clean(), click(), CONFLICT, control_of(), DESC, envelope(), find_router(), finds_the_internet_service_and_makes_its_address_absolute() (+25 more)

### Community 184 - "arc"
Cohesion: 0.14
Nodes (6): HardwareSample, GB, HISTORY_STEP, MB, run(), HW_WINDOW

### Community 186 - "ExtrasAct"
Cohesion: 0.29
Nodes (4): ExtrasAct, Pause, Resume, Unblock

### Community 187 - "AppMode"
Cohesion: 0.50
Nodes (3): AppMode, Driver, Normal

### Community 188 - "Notifications"
Cohesion: 0.29
Nodes (7): Choosing which alerts are sent, Notifications, Setting one up, Snooze, Weekly summary, When the internet is down, Windows event log

### Community 189 - "AGENTS.md"
Cohesion: 0.33
Nodes (5): File updates, graphify, Project rules, Version control, Versioning

### Community 190 - "Troubleshooting and FAQ"
Cohesion: 0.14
Nodes (14): A program (or everything) lost its internet, Bandwidth limits don't affect downloads, I forgot the tamper-protection password, I got a "Firewall rule monitor" alert, Microsoft Defender flagged the driver, No country flags or map, Reporting a bug, The DNS log doesn't show my browser's lookups (+6 more)

### Community 191 - "build.rs"
Cohesion: 0.28
Nodes (7): BG, bundle_plugins(), graph_pixels(), H, main(), PALETTE, PLUGINS

### Community 192 - "v1.22.1.md"
Cohesion: 0.40
Nodes (4): Fixes, Helper programs no longer run as administrator, Security, Updates

### Community 193 - "PlanDirection"
Cohesion: 0.33
Nodes (5): PlanDirection, .ALL, In, Out, Total

### Community 194 - "OPNsense plugin"
Cohesion: 0.14
Nodes (13): Demo mode, Device names, Gateways and the firewall log, History, Names and prefixes, OPNsense plugin, Permissions, Privacy and safety (+5 more)

### Community 195 - "Manual checks on a real machine"
Cohesion: 0.29
Nodes (6): Automated, Elevated (use "Restart as administrator"), Helper programs without administrator rights (elevated window, service installed and not), Manual checks on a real machine, Testing RustWarden, Unelevated (a normal user)

### Community 196 - "1.25.5: hotfix for false alerts and "unknown process" traffic"
Cohesion: 0.50
Nodes (3): 1.25.5: hotfix for false alerts and "unknown process" traffic, Cleaning up earlier false alerts, Fixes

### Community 197 - "uninstall_service"
Cohesion: 0.17
Nodes (14): downloads_exe(), ensure_recovery(), file_version(), in_program_files(), install_elevated(), installed_exe(), own_version(), refresh_stale_service() (+6 more)

### Community 199 - "The Firewall tab"
Cohesion: 0.15
Nodes (13): Backing up and moving rules, Block after N minutes, Block an app by clicking it, Firewall modes, Firewall rulesets, Importing rules from another firewall app, Letting RustWarden's own helpers through, Prompt (+5 more)

### Community 200 - "tray.rs"
Cohesion: 0.19
Nodes (5): icon(), Tray, TrayCmd, Menu, Toggle

### Community 202 - "plan-release.sh"
Cohesion: 0.83
Nodes (3): section(), plan-release.sh script, skip()

### Community 203 - "Settings reference"
Cohesion: 0.15
Nodes (13): Alerts, Countries & Network, Data Plan, Firewall, General, Malicious IPs, Network Scanner, Other (+5 more)

### Community 205 - "Traffic"
Cohesion: 0.15
Nodes (13): Alert pins, Common controls, Filter, Graph view, History and retention, Kernel & System split, Map view, Program details (+5 more)

### Community 206 - "main.rs"
Cohesion: 0.83
Nodes (3): harden_dll_search(), main(), saved_window()

### Community 210 - "plugin-sdk"
Cohesion: 0.11
Nodes (19): example-hello, plugin-abuseipdb, plugin-cloudflare, plugin-discord, plugin-gotify, plugin-ha, plugin-ntfy, plugin-opnsense (+11 more)

### Community 212 - "Place"
Cohesion: 0.29
Nodes (4): Place, Country, Local, Unknown

### Community 213 - "PCWSTR"
Cohesion: 0.18
Nodes (12): answer_stop(), DISPLAY, EV_ACK, EV_ASK, EV_NO, EV_OK, open_event(), SHOW_EVENT (+4 more)

### Community 214 - "TimeRange"
Cohesion: 0.09
Nodes (21): TimeRange, Day, FifteenMinutes, FiveMinutes, OneHour, OneMinute, TenMinutes, ThirtyMinutes (+13 more)

### Community 215 - "1.23.3: a quieter, smarter behaviour baseline"
Cohesion: 0.50
Nodes (3): 1.23.3: a quieter, smarter behaviour baseline, Fixes, Improved

### Community 216 - "Driver mode"
Cohesion: 0.17
Nodes (12): Demo mode, Driver mode, Force DNS, Host names, Line speed, Logs, Microsoft Defender, QUIC fallback (+4 more)

### Community 217 - "Built-in plugins"
Cohesion: 0.18
Nodes (11): AbuseIPDB, Built-in plugins, Cloudflare Tunnel, Home Assistant, Notification plugins, Ping Monitor, Prometheus Metrics, Shodan InternetDB (+3 more)

### Community 218 - "Installing and first run"
Cohesion: 0.20
Nodes (10): Administrator rights, Building from source, Checking the download (optional), Download, Installing and first run, Next steps, Run as administrator without a prompt every time, Running it (+2 more)

### Community 226 - "icons.rs"
Cohesion: 0.11
Nodes (27): AppIcon, Bitwarden, Chrome, Claude, ClaudeCode, Drive, Gear, Generic (+19 more)

### Community 227 - "Updates, backup and upkeep"
Cohesion: 0.20
Nodes (10): Backup and restore, Clean up, History and storage, Snapshots, Tamper protection, The Windows service, Uninstalling RustWarden, Updates (+2 more)

### Community 229 - "Speedtest"
Cohesion: 0.22
Nodes (9): Adding hosts, Charts, First use, Ping Monitor, Ping Monitor and Speedtest, Removing it, Running a test, Settings (+1 more)

### Community 231 - "Network Scanner"
Cohesion: 0.22
Nodes (9): Demo mode, Device details, Home Assistant, How scanning works, Network Scanner, Other VLANs and subnets, Scanner alerts, Scanning automatically (+1 more)

### Community 233 - "Alerts"
Cohesion: 0.25
Nodes (8): Alert pins on the Traffic graph, Alerts, Exporting, Setting up alerts, Tamper-evident log, Testing, The Alerts tab, Weekly report

### Community 234 - "Limits / QoS"
Cohesion: 0.25
Nodes (8): Demo mode, Driver mode: downloads, both directions, and pacing, Limits / QoS, Network-condition simulator (Driver mode), Normal mode: upload limits through Windows QoS, Priority, Quota caps, Setting a limit

### Community 235 - "Key ideas"
Cohesion: 0.25
Nodes (8): Administrator rights, Key ideas, Live and Demo mode, Local first, Normal and Driver mode, Programs, services and the kernel, RustWarden's own rules, Where RustWarden keeps things

### Community 236 - "Plugins"
Cohesion: 0.25
Nodes (8): Installing one, Plugins, Removing one, Third-party plugins, Uninstalling and reinstalling built-in plugins, Using a plugin, Where plugin data lives, Writing your own

### Community 237 - "Countries and lookups"
Cohesion: 0.25
Nodes (8): AS number and company, Countries and lookups, Downloads, Geolocation, Lookups, Public IP address, Removing the databases, Whois

### Community 238 - "VPN"
Cohesion: 0.25
Nodes (8): Block DNS-over-HTTPS resolvers, Don't count VPN tunnel traffic, Incognito and hidden apps, Peer-to-peer guard, Privacy and VPN, Related, VPN, VPN kill switch

### Community 240 - "Destination Rules"
Cohesion: 0.29
Nodes (7): Adding a rule, Block by domain (Driver mode), Built-in safety, Destination Rules, Destinations, How it works, Limits

### Community 241 - "The window"
Cohesion: 0.29
Nodes (7): Layout, Look and feel, Popups, Settings, The RustWarden menu, The tray icon, The window

### Community 242 - "Malicious IP and domain protection"
Cohesion: 0.29
Nodes (7): Blocked & whitelisted, Demo mode, List safety checks, Malicious domains, Malicious IP and domain protection, Malicious IPs, Never blocked

### Community 243 - "Quotas"
Cohesion: 0.29
Nodes (7): Actions at 100%, Data plan, Data plan and quotas, How counting works, Lifting blocks and caps, Quotas, Where you see it

### Community 244 - "Alert rules"
Cohesion: 0.40
Nodes (5): Actions, Alert rules, Conditions, Examples, Order

### Community 245 - "Rescue: removing every RustWarden rule"
Cohesion: 0.33
Nodes (6): 1. Restore firewall defaults (in the app), 2. Disable the firewall (temporary), 3. The rescue command (when the app won't open), Other command-line options, Rescue: removing every RustWarden rule, Running it with no working desktop

### Community 249 - "Live Connections"
Cohesion: 0.40
Nodes (5): Actions, Demo mode, Driver mode extras, Live Connections, The table

### Community 250 - "DNS Log"
Cohesion: 0.40
Nodes (5): DNS Log, How it works, Settings, The table, What uses the DNS log

### Community 251 - "Behaviour baseline"
Cohesion: 0.33
Nodes (6): Behaviour baseline, Teaching it, The alerts, Turning it on, What it learns, While it learns

### Community 253 - "path"
Cohesion: 0.47
Nodes (4): a_full_log_moves_aside_and_restarts(), append(), line(), MAX

### Community 254 - "RustWarden user guide"
Cohesion: 0.50
Nodes (4): Built to be safe, RustWarden user guide, What RustWarden does, Where to start

### Community 255 - "plugin-sdk/src/lib.rs"
Cohesion: 0.10
Nodes (17): CHART_DIALOG_CLOSE, CHART_LAYOUT, CHART_RANGE, CHART_REFRESH, CHART_SIGNIN, ChartLine, LatencyChart, SPEED_INSTALL (+9 more)

### Community 258 - "Hardware"
Cohesion: 0.67
Nodes (3): Hardware, History, Per-program view

### Community 264 - "AccountChange"
Cohesion: 0.29
Nodes (7): account_and_task_changes(), AccountChange, Activated, Created, Deactivated, Deleted, diff_accounts()

### Community 265 - "settings.rs"
Cohesion: 0.08
Nodes (16): DataPlan, deserialize(), DNS_FEED_DEFAULT, DNS_FEED_RETIRED, dns_log_defaults_and_clamp(), domain_alerts_are_off_until_enabled(), mode_round_trips_through_toml(), new_install_has_alerts_off_and_playground_reads_as_dev() (+8 more)

### Community 266 - "Third-party data and credits"
Cohesion: 0.40
Nodes (5): Blocklists, Data from your own accounts, Databases, Programs and drivers, Third-party data and credits

### Community 269 - "install_service"
Cohesion: 0.43
Nodes (6): adopt_legacy_entries(), desktop_lnk(), install_service(), lnk_in(), shortcut(), start_menu_lnk()

### Community 271 - "Direction"
Cohesion: 0.12
Nodes (19): Direction, In, Local, Out, critical_reason(), service_of_key(), allow_rules_are_ours_outbound_and_distinct_from_block_rules(), allow_spec() (+11 more)

## Knowledge Gaps
- **482 isolated node(s):** `System`, `Notification`, `Label`, `Heading`, `Weak` (+477 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2276 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **25 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Settings` connect `Ui` to `LiveBackend`, `plugins.rs`, `MockBackend`, `pathbuf`, `settings.rs`, `baseline.rs`, `.notify`, `.load`, `update.rs`, `Backend`, `legacy.rs`, `manager.rs`, `.tick`, `.default`, `store.rs`, `wizard.rs`, `demo.rs`, `NetInfoSource`, `alerts.rs`, `AlertKind`, `RustWarden`, `driver.rs`, `rules_file.rs`, `live/mod.rs`, `asn.rs`, `AppMode`, `Dialog`, `QuotaStatus`, `TimeRange`, `toast.rs`, `alertrules.rs`, `AppRecord`, `run`, `tray_menu.rs`, `Found`, `report.rs`?**
  _High betweenness centrality (0.049) - this node is a cross-community bridge._
- **Are the 155 inferred relationships involving `Ui` (e.g. with `app.rs` and `.alert_tabs()`) actually correct?**
  _`Ui` has 155 INFERRED edges - model-reasoned connections that need verification._
- **What connects `System`, `Notification`, `Label` to the rest of the system?**
  _482 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `live/firewall.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.041455696202531644 - nodes in this community are weakly interconnected._
- **Why does `Ui` connect `widgets.rs` to `Alert`, `plugins.rs`, `theme.rs`, `tray_menu.rs`, `Ui`, `.notify`, `legacy.rs`, `Context`, `wizard.rs`, `pdh.rs`, `RustWarden`, `ui/traffic.rs`, `credits.rs`, `Call`, `QuotaStatus`, `latency.rs`, `speed.rs`, `map.rs`, `toast.rs`, `connections.rs`, `PluginFeed`, `alertrules.rs`, `ui_tree.rs`, `latency.rs`, `tray_menu.rs`, `st`, `fluent.rs`?**
  _High betweenness centrality (0.037) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Db` (e.g. with `.target_ranges()` and `.views()`) actually correct?**
  _`Db` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Should `LiveBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.040643863179074445 - nodes in this community are weakly interconnected._