# Graph Report - RustWarden  (2026-11-11)

## Corpus Check
- 232 files · ~321,067 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 2, .ico 1, .tsv 1)

## Summary
- 6084 nodes · 12980 edges · 277 communities (253 shown, 24 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 800 edges (avg confidence: 0.61)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4972eb1f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- live/firewall.rs
- LiveBackend
- Event
- theme.rs
- threat.rs
- MockBackend
- widgets.rs
- thinkbroadband/src/lib.rs
- cloudflare/src/lib.rs
- engine.rs
- dialogs.rs
- webview.rs
- baseline.rs
- picker.rs
- update.rs
- guard.rs
- Backend
- manager.rs
- loader.rs
- settings.rs
- live/apps.rs
- speedtest/src/lib.rs
- live/scanner.rs
- Db
- demo.rs
- FwController
- traffic_load.rs
- popup.rs
- Icon
- src/notify.rs
- pdh.rs
- alerts.rs
- AlertKind
- autostart.rs
- modal.rs
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
- st
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
- .ui
- monitors.rs
- clock.rs
- domains.rs
- sniff.rs
- steps
- Scale
- beacon.rs
- Outcome
- latency.rs
- proc.rs
- ha/src/lib.rs
- speed.rs
- notes.rs
- opnsense/src/lib.rs
- scandetect.rs
- watch.rs
- map.rs
- QuotaStatus
- Windows system changes
- live/geo.rs
- toast.rs
- quota.rs
- arc
- services.rs
- connections.rs
- PluginFeed
- Monitors
- tray_menu.rs
- live/traffic.rs
- ask.rs
- .memory
- netpkt.rs
- alertrules.rs
- Priority
- sys/qos.rs
- window_at
- live/dns.rs
- .notify
- Dialog
- run
- .tick
- capture.rs
- tray.rs
- super
- RangeSet
- dnstunnel.rs
- feed
- windows_extras.rs
- guest.rs
- report.rs
- TcpState
- ConfirmAction
- Mode
- Country
- Collector
- filedialog.rs
- shots.rs
- PWSTR
- err
- host.rs
- show
- migrate.rs
- plugins.rs
- Creating a RustWarden plugin
- upnp.rs
- wallpaper.rs
- docs.yml
- pathbuf
- quota.rs
- netparse.rs
- UiTree
- Direction
- bucket.rs
- sys/apps.rs
- UiTree
- LiveConn
- PlanPeriod
- legacy.rs
- .default
- export.rs
- util.rs
- store.rs
- pcwstr
- Geo
- DeviceKind
- hashmap
- vt.rs
- hashset
- NetInfoSource
- tcp_row
- HostCall
- Rule
- steps
- Writing a RustWarden plugin
- Ui
- Priority
- tlsprint.rs
- QuotaAction
- RustWarden
- listeners
- VirusTotal
- accent.rs
- src/geo.rs
- countries.rs
- bundled.rs
- .handle
- tamper.rs
- AlertLevel
- .start
- pcap.rs
- v1.21.3.md
- quiet
- StatusNote
- credits.rs
- Security Policy
- upnp/src/lib.rs
- arc
- ExtrasAct
- Target
- Notifications
- AGENTS.md
- Troubleshooting and FAQ
- build.rs
- v1.22.1.md
- PlanDirection
- OPNsense plugin
- Manual checks on a real machine
- Vt
- install_service
- .run
- The Firewall tab
- alert_rules.rs
- Urgency
- plan-release.sh
- Settings reference
- Held
- Traffic
- main.rs
- RuleAction
- flag_data.rs
- plugin-sdk
- AccountChange
- check
- data.rs
- 1.23.3: a quieter, smarter behaviour baseline
- Driver mode
- Built-in plugins
- Installing and first run
- AppIcon
- Updates, backup and upkeep
- Job
- Speedtest
- PCWSTR
- Network Scanner
- tcp6_row
- Alerts
- Limits / QoS
- Key ideas
- Plugins
- Countries and lookups
- VPN
- AppGroup
- Destination Rules
- The window
- Malicious IP and domain protection
- Quotas
- Alert rules
- Rescue: removing every RustWarden rule
- v1.20.6.md
- wizard.rs
- Host
- Live Connections
- DNS Log
- Behaviour baseline
- HistoryData
- install_elevated
- RustWarden user guide
- SpeedLive
- Found
- device_events
- Hardware
- v1.20.0.md
- dpapi.rs
- curl.rs
- Card
- with_reader
- Report
- .load
- Third-party data and credits
- DnsEntry
- __call
- SpeedRoute
- Place
- Answer
- HardwareSample
- theme_button_cycles_system_light_dark
- ApiAsset
- pathbuf
- AppMode

## God Nodes (most connected - your core abstractions)
1. `Ui` - 156 edges
2. `Db` - 144 edges
3. `RustWarden` - 125 edges
4. `LiveBackend` - 113 edges
5. `Settings` - 112 edges
6. `Backend` - 103 edges
7. `MockBackend` - 91 edges
8. `Context` - 86 edges
9. `FwController` - 72 edges
10. `UiTree` - 71 edges

## Surprising Connections (you probably didn't know these)
- `style()` --references--> `Ui`  [INFERRED]
  src/ui/fluent.rs → plugin-sdk/src/lib.rs
- `Writer` --references--> `W`  [INFERRED]
  src/pcap.rs → build.rs
- `badge()` --references--> `UiTree`  [EXTRACTED]
  plugins/opnsense/src/lib.rs → plugin-sdk/src/lib.rs
- `Host` --references--> `Call`  [INFERRED]
  src/plugins/wasm/host.rs → plugin-sdk/src/lib.rs
- `feeds()` --references--> `Ui`  [INFERRED]
  src/credits.rs → plugin-sdk/src/lib.rs

## Import Cycles
- 1-file cycle: `src/ui/dialogs.rs -> src/ui/dialogs.rs`
- 1-file cycle: `src/ui/map.rs -> src/ui/map.rs`
- 1-file cycle: `src/ui/mod.rs -> src/ui/mod.rs`
- 1-file cycle: `src/data.rs -> src/data.rs`
- 2-file cycle: `src/plugins/wasm/manager.rs -> src/plugins/wasm/ui_tree.rs -> src/plugins/wasm/manager.rs`

## Communities (277 total, 24 thin omitted)

### Community 0 - "live/firewall.rs"
Cohesion: 0.04
Nodes (68): ACTIVE_PROFILE_KEY, adopt_legacy_rules(), allow_engine_traffic(), ASK_KEY, ask_marker_exists(), ask_marker_path(), audit_prev_path(), block_all_exceptions() (+60 more)

### Community 1 - "LiveBackend"
Cohesion: 0.04
Nodes (8): db_path(), hosts_with_the_same_label_merge_into_one_row(), LiveBackend, MAX_HOSTS, merge_hosts(), row(), share(), verdict_shown()

### Community 2 - "Event"
Cohesion: 0.12
Nodes (18): Event, Bool, ChartMissing, Click, File, Index, Number, TabOpened (+10 more)

### Community 3 - "theme.rs"
Cohesion: 0.06
Nodes (69): a_ring_has_no_repeated_end_point(), app_icon(), app_icon_for(), arc_points(), flag(), flag_texture(), glyph(), IconCache (+61 more)

### Community 4 - "threat.rs"
Cohesion: 0.11
Nodes (30): a_failed_list_keeps_only_its_own_last_good_entries(), act(), add_name(), ALLOW_KEY, cache_keeps_list_names(), cache_path(), download(), feeds_keep_only_public_addresses() (+22 more)

### Community 5 - "MockBackend"
Cohesion: 0.05
Nodes (5): demo_bandwidth_limits_can_be_added_changed_and_cleared(), demo_destination_rules_add_replace_remove_and_reset(), demo_networks_keep_separate_devices_and_threat_lists(), demo_traffic_filter_narrows_the_sample_data(), MockBackend

### Community 6 - "widgets.rs"
Cohesion: 0.14
Nodes (25): area(), area_faded(), area_faded_to(), area_impl(), area_soft_to(), column_handles(), combo_icon(), count_badge() (+17 more)

### Community 7 - "thinkbroadband/src/lib.rs"
Cohesion: 0.08
Nodes (54): ALERT_MAX_AGE_SECS, alert_pct(), attr(), backfill(), BASE, chart(), CHART_SQL, civil_from_days() (+46 more)

### Community 8 - "cloudflare/src/lib.rs"
Cohesion: 0.10
Nodes (35): args_for(), begin(), cfg(), Cloudflare, demo_step(), each_step_runs_the_right_command(), event(), EXE (+27 more)

### Community 9 - "engine.rs"
Cohesion: 0.08
Nodes (33): a_limit_only_paces_the_directions_it_names(), die(), DROP_LIMIT, DROP_WINDOW_MS, Engine, filter_loop(), filter_needs_swap(), flow_loop() (+25 more)

### Community 10 - "dialogs.rs"
Cohesion: 0.10
Nodes (43): ThreatLists, Settings, about_click_hits(), ABOUT_CLICKS, ABOUT_PNG, accent_picker(), ACCENTS, ALERT_JUMP (+35 more)

### Community 11 - "webview.rs"
Cohesion: 0.09
Nodes (21): CHECK, CHECK_SECS, Ev, GiveUp, Loaded, Msg, fetch(), GIVE_UP_SECS (+13 more)

### Community 12 - "baseline.rs"
Cohesion: 0.05
Nodes (44): active_days_by_hour(), ASN_WAIT_SCANS, BUSY_HOUR, DAY, DIM_ASN, DIM_COUNTRY, DIM_DOMAIN, DIM_HOUR (+36 more)

### Community 13 - "picker.rs"
Cohesion: 0.12
Nodes (3): Pick, run(), start()

### Community 14 - "update.rs"
Cohesion: 0.08
Nodes (19): ASSET_STEMS, CHECK_QUERY, check_signature(), cleanup(), der_to_raw(), download_sha(), expect_ok(), get() (+11 more)

### Community 15 - "guard.rs"
Cohesion: 0.11
Nodes (32): fingerprint(), GUARD_PREFIX, adapter(), ARMED_KEY, DOH_ADDRS, DOH_PREFIX, doh_specs(), ENDPOINTS_KEY (+24 more)

### Community 16 - "Backend"
Cohesion: 0.03
Nodes (4): AlertCheck, Backend, Capabilities, P2pApp

### Community 17 - "manager.rs"
Cohesion: 0.09
Nodes (16): broadcast_alert(), deliver_alert(), deserialize(), HELD_MAX, intern(), MAX_FILE, OFFLINE, Open (+8 more)

### Community 18 - "loader.rs"
Cohesion: 0.12
Nodes (20): a_wrong_api_version_is_refused(), an_infinite_loop_is_stopped_by_the_fuel_limit(), call_tick(), engine(), FUEL, hash_of(), host_calls_are_checked_by_the_host(), host_import() (+12 more)

### Community 19 - "settings.rs"
Cohesion: 0.08
Nodes (15): deserialize(), DNS_FEED_DEFAULT, DNS_FEED_RETIRED, dns_log_defaults_and_clamp(), domain_alerts_are_off_until_enabled(), mode_round_trips_through_toml(), new_install_has_alerts_off_and_playground_reads_as_dev(), parse_hex() (+7 more)

### Community 20 - "live/apps.rs"
Cohesion: 0.08
Nodes (27): core_services_are_refused_and_other_services_are_not(), critical_reason(), CRITICAL_SERVICES, describe_change(), ensure_record(), ensure_service_record(), file_name(), icon_for() (+19 more)

### Community 21 - "speedtest/src/lib.rs"
Cohesion: 0.10
Nodes (23): demo_history(), demo_result(), DEMO_STEP_MS, DEMO_TEST_SECS, EXE, EXE_SHA256, KEEP_SECS, PAGE_SQL (+15 more)

### Community 22 - "live/scanner.rs"
Cohesion: 0.09
Nodes (30): progress(), arp_probe(), Found, MAX_PREFIX_HOSTS, nbstat(), nbstat_request(), networks(), oui_map() (+22 more)

### Community 23 - "Db"
Cohesion: 0.06
Nodes (6): row(), Db, .APP_COLS, DeviceRow, devices_keep_user_names_and_go_offline(), dns_log_round_trips_and_prunes()

### Community 24 - "demo.rs"
Cohesion: 0.09
Nodes (29): FirewallApp, Verdict, Allowed, Blocked, demo_alerts(), demo_apps(), demo_block_all_shows_active(), demo_dest_rules() (+21 more)

### Community 25 - "FwController"
Cohesion: 0.13
Nodes (12): extras_paused(), extras_rules(), FwController, is_aux(), is_ours(), paused_extras(), profile_since(), removed_apps() (+4 more)

### Community 26 - "traffic_load.rs"
Cohesion: 0.10
Nodes (20): Scope, .ALL, Both, Lan, Wan, TrafficDir, .ALL, Both (+12 more)

### Community 27 - "popup.rs"
Cohesion: 0.07
Nodes (29): ThreatAct, Block, Unblock, Unwhitelist, Whitelist, ALERT_INFO_TITLE, ALERT_TITLE, ALERTS_SECTION (+21 more)

### Community 28 - "Icon"
Cohesion: 0.05
Nodes (41): Icon, Alerts, ArrowDown, ArrowUp, Bell, Bulb, Camera, Check (+33 more)

### Community 29 - "src/notify.rs"
Cohesion: 0.05
Nodes (48): simplify(), Discord, .FIELDS, .HOSTS, .ID, .NAME, DISCORD_URLS, Field (+40 more)

### Community 30 - "pdh.rs"
Cohesion: 0.10
Nodes (12): engine_type(), expand(), gpu_load(), GpuQuery, Handle, Pdh, ProcQuery, Query (+4 more)

### Community 31 - "alerts.rs"
Cohesion: 0.09
Nodes (21): adapter_ignored(), anomaly_kinds_have_keys_and_switches(), arp_mac_change_is_reported_once(), ArpChange, device_use_reports_new_and_later_uses(), diff_arp(), diff_dns(), diff_sessions() (+13 more)

### Community 32 - "AlertKind"
Cohesion: 0.05
Nodes (40): AlertKind, .ALL, AnomalyContact, AnomalyHour, AnomalyVolume, AppChanged, Arp, Away (+32 more)

### Community 33 - "autostart.rs"
Cohesion: 0.08
Nodes (17): CHILD, claim_instance(), EVENTS, in_program_files(), LAUNCH, LAUNCH_HIDDEN, MOVED_TO, REFUSED (+9 more)

### Community 34 - "modal.rs"
Cohesion: 0.09
Nodes (3): find(), find_all(), MAIN

### Community 35 - "sys/mod.rs"
Cohesion: 0.09
Nodes (20): rules_to_suspend(), service_has_sid(), from_wide(), hidden_start(), home_region(), is_elevated(), message(), NO_WINDOW (+12 more)

### Community 36 - "icmp.rs"
Cohesion: 0.10
Nodes (9): AT_ONCE, echo(), echoes(), MAX_ADDRS, ping_v4(), ping_v6(), Round, round() (+1 more)

### Community 37 - "sys/firewall.rs"
Cohesion: 0.06
Nodes (5): PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC, PROFILES, PROTO_ANY

### Community 38 - "data.rs"
Cohesion: 0.07
Nodes (23): LogState, Alert, AlertDest, .ALL, Any, Local, Remote, AlertFilter (+15 more)

### Community 39 - "wfp.rs"
Cohesion: 0.06
Nodes (18): auditpol(), blocked_since(), data(), failure_audit_on(), parse_events(), reads_outbound_drops_only(), set_failure_audit(), SUBCATEGORY (+10 more)

### Community 40 - "QosLimit"
Cohesion: 0.08
Nodes (16): decode_all(), directions_round_trip_and_old_lines_still_read(), encode_all(), fmt_rate(), limit(), MAX_DELAY_MS, MAX_KBPS, MAX_LIMITS (+8 more)

### Community 41 - "abuseipdb/src/lib.rs"
Cohesion: 0.17
Nodes (18): AbuseIpDb, DEFAULT_ALERT_SCORE, demo_verdict(), FRESH_SECS, is_public(), KEEP, key_ok(), lookup() (+10 more)

### Community 42 - "RustWarden"
Cohesion: 0.05
Nodes (14): default_window(), DestDraft, make_backend(), QosDraft, RustWarden, snap(), Plugin, cell() (+6 more)

### Community 43 - "driver.rs"
Cohesion: 0.09
Nodes (27): BLOCKED_HELP, dir(), DLL, DriverState, Blocked, Missing, Ready, folder_state_tells_missing_ready_and_blocked_apart() (+19 more)

### Community 44 - "netinfo.rs"
Cohesion: 0.08
Nodes (12): adapters(), adapters_and_neighbors_are_readable(), host_routes(), idle_seconds(), is_tunnel(), is_virtual(), Neighbor, neighbors() (+4 more)

### Community 45 - "etw.rs"
Cohesion: 0.06
Nodes (29): cached_path(), decode(), dns_answer_maps_name_to_addresses(), DNS_CLIENT, dns_payload(), DROPPED, failed_lookup_is_logged_without_addresses(), forget_dead() (+21 more)

### Community 46 - "ui/traffic.rs"
Cohesion: 0.12
Nodes (11): blur_averages_and_keeps_length(), box_blur(), row_in(), tick_step(), command_card(), command_card_id(), kind_icon(), popup_fit() (+3 more)

### Community 47 - "dest.rs"
Cohesion: 0.12
Nodes (16): DestRule, DestRuleView, Dest, DNS_WINDOW, firewall_rules_belong_to_their_destination_rule(), id_of(), load(), name_changes_with_the_address_list_program_and_mode_only() (+8 more)

### Community 48 - "windivert.rs"
Cohesion: 0.08
Nodes (18): ChecksumFn, CloseFn, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED, FLAG_DROP, FLAG_RECV_ONLY, FLAG_SNIFF, LAYER_FLOW (+10 more)

### Community 49 - "conns.rs"
Cohesion: 0.07
Nodes (3): ENABLED, STATE_ESTABLISHED, STATE_SYN_SENT

### Community 50 - "rules_file.rs"
Cohesion: 0.15
Nodes (14): a_file_survives_writing_and_reading(), AppRule, current_of(), destination_rules_are_added_once_and_get_fresh_ids(), DIRECTIONS, file(), FORMAT, matching_state_plans_nothing() (+6 more)

### Community 51 - "helper.rs"
Cohesion: 0.12
Nodes (25): a_program_that_isnt_downloaded_is_refused_before_anything_runs(), a_programs_folders_are_copied_with_their_files(), adopt(), adopt_user_copy(), adopts_only_a_genuine_copy(), cached_sha(), CHECKED, confirmed() (+17 more)

### Community 52 - "RustWarden features"
Cohesion: 0.12
Nodes (17): 🚨 Alerts and log analysis, 🧭 Behaviour baseline, Clean up, 📏 Data quotas, 🔎 DNS Log, ⚙️ Everything else, 🛡️ Firewall: your firewall, simplified, 📈 Hardware resources (+9 more)

### Community 53 - "lease.rs"
Cohesion: 0.14
Nodes (21): before_spawn(), check_again_at(), decode(), due(), encode(), end(), end_all(), GROUP (+13 more)

### Community 54 - "st"
Cohesion: 0.14
Nodes (24): table_prefix(), annotates(), annotator(), annotator_ids(), any_notification_plugin(), apply(), drop_tables(), erase() (+16 more)

### Community 55 - "asn.rs"
Cohesion: 0.14
Nodes (16): curl_url(), cymru(), cymru_name(), cymru_names_are_reversed(), format_info(), from_json(), http(), json_find() (+8 more)

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
Cohesion: 0.13
Nodes (6): Address, flow_address(), flow_events_are_read_from_the_address_union(), FlowInfo, Handle, ipv6_words_come_last_first()

### Community 62 - "steps"
Cohesion: 0.07
Nodes (26): run, GH_TOKEN, RUSTFLAGS, UPDATE_SIGNING_KEY, jobs, release, name, on (+18 more)

### Community 63 - "dnsguard.rs"
Cohesion: 0.17
Nodes (14): Action, Pass, Redirect, Restore, decide(), FILTER, Guard, KEEP (+6 more)

### Community 64 - "net.rs"
Cohesion: 0.13
Nodes (19): classify(), classify_v4(), classify_v6(), dns_results_are_scanned_for_addresses(), ip(), ips_in_dns_results(), is_cgnat(), kernel_service() (+11 more)

### Community 65 - ".ui"
Cohesion: 0.07
Nodes (21): every_tab_has_its_own_key_that_reads_back(), Tab, AlertRules, .ALL, Bandwidth, Connections, DestRules, Dns (+13 more)

### Community 66 - "monitors.rs"
Cohesion: 0.12
Nodes (19): Debounce, diff_files(), per_user_base(), plan_level(), PlanLevel, Over, Warning, arp_snapshot() (+11 more)

### Community 67 - "clock.rs"
Cohesion: 0.14
Nodes (13): civil_from_days(), day_label(), days_from_civil(), file_stamp(), fmt_date(), fmt_stamp(), fmt_time_lower(), local_offset_at() (+5 more)

### Community 68 - "domains.rs"
Cohesion: 0.12
Nodes (13): Matcher, Domains, FILTER, FILTER_BROAD, KEY, list_path(), load_rules(), packet_loop() (+5 more)

### Community 69 - "sniff.rs"
Cohesion: 0.07
Nodes (40): a_udp_flow_filter_names_both_directions_and_one_ip_version(), dhcp_reply(), FILTER, flow_loop(), Flows, kill_udp(), MAX_FLOWS, packet_loop() (+32 more)

### Community 70 - "steps"
Cohesion: 0.08
Nodes (23): run, GALLIUM_DRIVER, MESA_SHA256, RUSTWARDEN_SHOTS, jobs, screenshots, name, on (+15 more)

### Community 71 - "Scale"
Cohesion: 0.22
Nodes (7): Dim, App, Proto, Remote, inspect_db(), inspect_detail(), UsageEntry

### Community 72 - "beacon.rs"
Cohesion: 0.09
Nodes (23): a_browser_is_not_exempt(), a_cdn_suffix_lowers_the_level_without_hiding_it(), an_unsigned_program_with_tiny_uniform_payloads_to_a_rare_host_is_reported(), BULK_PER_MIN, chrome_polling_a_live_video_cdn_is_not_reported(), ctx(), DEFAULT_CDN, FORGET_AFTER (+15 more)

### Community 73 - "Outcome"
Cohesion: 0.09
Nodes (24): Outcome, Apply, Close, Confirmed, ExportRules, ImportRules, InstallService, IpInfo (+16 more)

### Community 74 - "latency.rs"
Cohesion: 0.11
Nodes (26): BLUE, calendar(), camera(), column_count(), columns(), columns_keep_the_extremes_and_average_the_rest(), day_shift(), export() (+18 more)

### Community 75 - "proc.rs"
Cohesion: 0.04
Nodes (26): a_long_script_runs_from_the_environment_and_a_long_command_line_falls_back(), Child, command_line(), dir_ptr_or(), environment(), environment_changes_are_applied_and_nothing_means_inherit(), inheritable(), MAX_LINE (+18 more)

### Community 76 - "ha/src/lib.rs"
Cohesion: 0.11
Nodes (26): event(), explain(), Ha, headers(), known(), LOGO, lookup(), next_due() (+18 more)

### Community 77 - "speed.rs"
Cohesion: 0.10
Nodes (13): query_speed(), arc_mesh(), dial_frac(), DIAL_START, DIAL_SWEEP, down(), MARKS, RANGES (+5 more)

### Community 78 - "notes.rs"
Cohesion: 0.14
Nodes (13): ScannerLoad, ScannerState, Device, DeviceNote, ScanState, Annotator, device_kind(), device_url() (+5 more)

### Community 79 - "opnsense/src/lib.rs"
Cohesion: 0.06
Nodes (53): flag(), a_leftover_alias_is_reported(), a_read_check_keeps_the_earlier_write_result(), a_read_only_key_cannot_push(), a_read_only_key_is_told_apart(), a_writable_key_creates_then_removes_the_test_alias(), Added, Denied (+45 more)

### Community 80 - "scandetect.rs"
Cohesion: 0.18
Nodes (12): a_burst_from_many_sources_is_a_flood(), Detector, Finding, PortScan, SynFlood, FLOOD_PER_SEC, ip(), many_ports_from_one_source_is_a_scan_reported_once() (+4 more)

### Community 81 - "watch.rs"
Cohesion: 0.14
Nodes (9): device_use(), open(), root_certs(), RUN_KEYS, service_names(), snapshots_read_the_registry(), startup_entries(), subkeys() (+1 more)

### Community 82 - "map.rs"
Cohesion: 0.22
Nodes (13): ARC, blocked_color(), clamp_center(), home_dot(), land(), land_active(), land_edge(), land_hover() (+5 more)

### Community 83 - "QuotaStatus"
Cohesion: 0.12
Nodes (10): ProtectLoad, EngineState, Ready, Unavailable, WindowsFirewallOff, FirewallInfo, QuotaStatus, demo_quotas() (+2 more)

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
Cohesion: 0.35
Nodes (13): action_none_only_warns(), block_is_asked_for_until_it_happens(), clock_moved_back_starts_a_fresh_period(), deleted_disabled_or_retargeted_quotas_orphan_their_track(), jumping_straight_over_alerts_once(), quota(), raising_the_limit_lifts_the_block(), rollover_releases_the_block_and_rearms_alerts() (+5 more)

### Community 88 - "arc"
Cohesion: 0.14
Nodes (13): a_slow_client_cannot_hold_the_endpoint(), bind_retrying(), Endpoint, exchange(), handle(), label(), LOG, metrics_answers_loopback_requests() (+5 more)

### Community 89 - "services.rs"
Cohesion: 0.15
Nodes (8): by_pid(), label(), lists_running_services(), one_service_is_named_with_its_short_name(), SC_MANAGER_ENUMERATE_SERVICE, Service, shared_hosts_are_keyed_in_a_stable_order(), svc()

### Community 90 - "connections.rs"
Cohesion: 0.10
Nodes (22): ConnsState, Act, Block, Capture, Kill, conn(), ConnGroup, .ALL (+14 more)

### Community 91 - "PluginFeed"
Cohesion: 0.16
Nodes (3): query_samples(), Missing, PluginFeed

### Community 93 - "tray_menu.rs"
Cohesion: 0.06
Nodes (33): FirewallMode, .ALL, AskToConnect, BlockAll, ClickToBlock, PROMPT_FOR, prompt_for_label(), mode_confirm() (+25 more)

### Community 94 - "live/traffic.rs"
Cohesion: 0.18
Nodes (17): KIND_LAN, KIND_UNKNOWN, a_tls_server_name_names_its_own_programs_traffic(), aggregator_sums_by_key(), ev(), Flow, flow_of(), ip() (+9 more)

### Community 95 - "ask.rs"
Cohesion: 0.19
Nodes (12): count(), fw_closed_since(), IN_FLIGHT, is_noise(), lookups_on(), MAX_IN_FLIGHT, MAX_OPEN_ASKS, note_engine_drop() (+4 more)

### Community 96 - ".memory"
Cohesion: 0.08
Nodes (27): add_column(), alert_chain_survives_reads_and_names_the_first_change(), alert_hash(), alerts_round_trip_and_mark_read(), app_records_and_missing_state(), BASE_LEARNED, blocked_attempts_add_up_prune_and_clear(), chained() (+19 more)

### Community 97 - "netpkt.rs"
Cohesion: 0.14
Nodes (16): pkt(), limited_ports(), addresses_can_be_swapped_in_ipv4_only(), FlowKey, ipv4_tcp(), parse(), Parsed, reads_ipv4_tcp_and_both_directions_share_one_flow() (+8 more)

### Community 98 - "alertrules.rs"
Cohesion: 0.15
Nodes (17): AlertInfo, AlertRule, ALL_DAYS, conditions_all_have_to_hold(), contains_nocase(), DAY_NAMES, decide(), Effect (+9 more)

### Community 99 - "Priority"
Cohesion: 0.12
Nodes (10): LimitDir, .ALL, Both, Down, Up, Priority, .ALL, High (+2 more)

### Community 100 - "sys/qos.rs"
Cohesion: 0.21
Nodes (9): add_exclusion(), remove_exclusion(), apply(), list(), parse_policy(), Policy, powershell(), remove() (+1 more)

### Community 101 - "window_at"
Cohesion: 0.23
Nodes (8): app_in(), each_window(), is_frame_host(), proc(), Search, State, window_at(), with()

### Community 102 - "live/dns.rs"
Cohesion: 0.13
Nodes (15): a_failed_feed_keeps_only_its_own_names(), cache_path(), check(), clean(), domain_of(), download(), MAX_DOMAINS, merge() (+7 more)

### Community 103 - ".notify"
Cohesion: 0.16
Nodes (7): Confirm, firewall_toggle_confirm(), virustotal_upload_confirm(), RustWarden, set_mode_and_enable(), RustWarden, service()

### Community 104 - "Dialog"
Cohesion: 0.08
Nodes (24): Dialog, About, Confirm, Info, InstallService, NewProfile, Password, Rename (+16 more)

### Community 105 - "run"
Cohesion: 0.19
Nodes (15): Active, HELD, load_saved(), Pages, preview(), redraw(), render(), run() (+7 more)

### Community 106 - ".tick"
Cohesion: 0.30
Nodes (3): used_by(), Worker, Quota

### Community 108 - "capture.rs"
Cohesion: 0.17
Nodes (3): Capture, Session, CaptureStatus

### Community 109 - "tray.rs"
Cohesion: 0.19
Nodes (5): icon(), Tray, TrayCmd, Menu, Toggle

### Community 110 - "super"
Cohesion: 0.04
Nodes (36): BLOCK_AFTER_MINS, DomainDraft, fit_window(), HwSeries, REFRESH_EVERY, Slot, UpdateEvent, Checked (+28 more)

### Community 111 - "RangeSet"
Cohesion: 0.11
Nodes (20): block_mode_never_touches_the_local_network(), blocked_set(), complement_covers_everything_else(), decode_all(), encode_all(), ip(), local_ranges(), long_lists_are_split_into_rules_within_the_limits() (+12 more)

### Community 112 - "dnstunnel.rs"
Cohesion: 0.09
Nodes (21): BASE_ALERTED, BASE_NORMAL, a_domain_marked_normal_stays_quiet(), ANY_APP, DIM, entropy(), LONG, many_random_names_under_one_domain_are_a_tunnel() (+13 more)

### Community 113 - "feed"
Cohesion: 0.24
Nodes (9): a_steady_timer_is_reported_once(), Beat, cfg(), Config, feed(), ip(), regular(), Series (+1 more)

### Community 114 - "windows_extras.rs"
Cohesion: 0.21
Nodes (9): expand(), Group, GROUPS, is_protected(), matches(), PROTECTED, resolve(), t() (+1 more)

### Community 115 - "guest.rs"
Cohesion: 0.13
Nodes (36): blocked_addresses(), browser_fetch(), browser_sign_in(), browser_sign_out(), config_get(), config_set(), db_exec(), db_query() (+28 more)

### Community 116 - "report.rs"
Cohesion: 0.17
Nodes (18): a_report_is_due_once_per_slot(), build(), build_finds_new_hosts_only_with_older_history(), country_of(), due(), KV_LAST, last_slot(), LISTED (+10 more)

### Community 117 - "TcpState"
Cohesion: 0.13
Nodes (14): state_raw(), TcpState, Closed, CloseWait, Closing, DeleteTcb, Established, FinWait1 (+6 more)

### Community 118 - "ConfirmAction"
Cohesion: 0.10
Nodes (21): ConfirmAction, ApplyRules, BlockProgram, BlockWindowsExtras, CleanUp, ClearHistory, DeleteProfile, FirewallEnabled (+13 more)

### Community 119 - "Mode"
Cohesion: 0.50
Nodes (3): Mode, Block, OnlyAllow

### Community 120 - "Country"
Cohesion: 0.13
Nodes (12): ConnectAsk, Country, France, Germany, Ireland, Iso, Local, Netherlands (+4 more)

### Community 121 - "Collector"
Cohesion: 0.15
Nodes (8): Aggregator, Collector, is_vpn_outer(), Names, publish_geo_note(), recent_names(), run(), shared_label()

### Community 122 - "filedialog.rs"
Cohesion: 0.13
Nodes (5): filter_list(), filter_list_is_double_null_terminated_with_all_files_last(), MAX_TEXT_BYTES, open(), open_async()

### Community 123 - "shots.rs"
Cohesion: 0.14
Nodes (9): SCREENS, SETTLE, Setup, Shots, Window, Ask, Main, Popup (+1 more)

### Community 124 - "PWSTR"
Cohesion: 0.25
Nodes (8): handler(), launch_gui(), logon_hidden(), make_events(), report(), report_step(), run_dispatcher(), service_main()

### Community 125 - "err"
Cohesion: 0.19
Nodes (15): add_rule(), adopt_rule(), bool_variant(), default_outbound_blocked(), enable_windows_firewall(), err(), interfaces_variant(), policy() (+7 more)

### Community 126 - "host.rs"
Cohesion: 0.10
Nodes (13): a_keypair_is_32_bytes_each_and_the_public_key_follows_from_the_private(), a_pinned_ca_is_checked_and_its_file_removed(), a_pinned_ca_skips_the_revocation_lookup_a_private_ca_cannot_answer(), a_value_cannot_break_out_of_the_curl_config(), answer(), CaFile, curl_config(), DB_CALL_LIMIT (+5 more)

### Community 127 - "show"
Cohesion: 0.26
Nodes (15): SpeedPage, card_frame(), chart(), gauge(), live_chart(), mbps(), nice_ceil(), reload() (+7 more)

### Community 128 - "migrate.rs"
Cohesion: 0.26
Nodes (12): DONE, merge_dir(), merge_keeps_what_the_new_folder_has(), move_program_files(), move_user_data(), OLD, rename_in_db(), run() (+4 more)

### Community 129 - "plugins.rs"
Cohesion: 0.14
Nodes (20): beta_hidden(), beta_shows_hidden_plugins_and_locking_uninstalls_them(), card(), CREATE_URL, files(), listed(), mark(), Modal (+12 more)

### Community 130 - "Creating a RustWarden plugin"
Cohesion: 0.13
Nodes (15): 1. Set up, 2. Create the crate, 3. Write the plugin, 4. Keep state, 5. Talk to the network (optional), 6. Run in the background (optional), 7. Ask for permissions (optional), 8. Build (+7 more)

### Community 131 - "upnp.rs"
Cohesion: 0.24
Nodes (7): discover(), Gateway, lan_addr(), local_networks(), location_of(), private(), SEARCH

### Community 133 - "docs.yml"
Cohesion: 0.14
Nodes (13): concurrency, cancel-in-progress, group, name, on, push, workflow_dispatch, permissions (+5 more)

### Community 134 - "pathbuf"
Cohesion: 0.39
Nodes (8): disable(), disables_the_features_that_use_downloads(), remove(), removes_files_and_folders_and_ignores_missing(), run(), size(), targets(), warning()

### Community 135 - "quota.rs"
Cohesion: 0.15
Nodes (15): QuotaLevel, Ok, Over, Warn, Decision, KV_KEY, level(), MB (+7 more)

### Community 136 - "netparse.rs"
Cohesion: 0.25
Nodes (10): client_hello(), dns(), DnsMessage, finds_the_server_name_and_refuses_junk(), host_ok(), name_at(), query(), reads_queries_and_answers_with_compressed_names() (+2 more)

### Community 137 - "UiTree"
Cohesion: 0.10
Nodes (22): add_form(), chart(), CHART_SQL, clean(), demo_row(), demo_rows_are_sane_and_stable(), DEMO_SPAN, event() (+14 more)

### Community 138 - "Direction"
Cohesion: 0.13
Nodes (16): a_service_rule_is_a_separate_row_with_its_own_name(), allow_rules_are_ours_outbound_and_distinct_from_block_rules(), allow_spec(), block_spec(), block_specs_are_scoped_to_one_program_and_direction(), Drift, icmp_specs(), lan_block_is_its_own_outbound_rule() (+8 more)

### Community 139 - "bucket.rs"
Cohesion: 0.15
Nodes (15): TrafficSample, align(), fill(), fill_pads_and_converts_to_rates(), range_buckets(), range_ends_in_the_current_bucket(), Scale, .ALL (+7 more)

### Community 141 - "sys/apps.rs"
Cohesion: 0.08
Nodes (8): current_process_has_a_path(), file_icon_rgba(), has_valid_embedded_signature(), notepad_like_system_binary_has_version_info(), pid_path(), running_paths(), version_info(), VersionInfo

### Community 142 - "UiTree"
Cohesion: 0.08
Nodes (26): UiTree, Button, Card, Column, Copy, Disabled, Dropdown, FileButton (+18 more)

### Community 143 - "LiveConn"
Cohesion: 0.14
Nodes (4): LiveConn, demo_connections(), demo_connections_have_sample_rows(), live_conn_search()

### Community 144 - "PlanPeriod"
Cohesion: 0.17
Nodes (11): PeriodKind, Day, Month, Week, period_kind(), period_word(), PlanPeriod, .ALL (+3 more)

### Community 145 - "legacy.rs"
Cohesion: 0.14
Nodes (24): ha_config(), migrate_tables(), NOTIFICATIONS, old_ping_rows_move_into_the_plugin_table_once(), old_speedtest_rows_move_into_the_plugin_table(), old_thinkbroadband_samples_move_into_the_plugin_table(), old_values(), old_values_are_found_trimmed_and_empty_ones_skipped() (+16 more)

### Community 146 - ".default"
Cohesion: 0.14
Nodes (14): a_secret_sealed_for_someone_else_is_not_imported(), alert_rules_are_sanitized_and_survive_a_save(), app_mode_defaults_to_normal_and_round_trips(), baseline_settings_are_clamped(), export_round_trips_and_leaves_out_the_password(), import_keeps_what_the_file_lacks_and_skips_what_it_cannot_read(), nan_scale_is_reset(), pending_blocks_survive_a_save_and_load() (+6 more)

### Community 147 - "export.rs"
Cohesion: 0.26
Nodes (9): a_value_that_looks_like_a_formula_is_made_text(), AlertRow, alerts_csv(), csv_keeps_awkward_values_in_one_cell(), json(), json_uses_field_names(), traffic_csv(), traffic_csv_has_one_line_per_row_after_the_header() (+1 more)

### Community 148 - "util.rs"
Cohesion: 0.08
Nodes (21): app_icon_rgba(), async_memo_answers_none_until_the_read_lands_then_keeps_it(), AsyncMemo, AsyncMemo<K, V>, Bg, bg_runs_the_latest_waiting_request_and_reports_a_panic_once(), Bg<T>, BIT_UNITS (+13 more)

### Community 149 - "store.rs"
Cohesion: 0.13
Nodes (14): a_mute_rule_records_the_alert_but_shows_nothing(), a_quiet_alert_is_logged_read_without_a_popup_even_when_escalated(), ALERT_SINK, an_escalate_rule_makes_an_alert_important_with_a_popup(), blocked_addresses(), country_of(), HwNow, install_alert_sink() (+6 more)

### Community 150 - "pcwstr"
Cohesion: 0.18
Nodes (4): W, Writer, EVENT_ID, write()

### Community 151 - "Geo"
Cohesion: 0.23
Nodes (4): asn_networks(), country_networks_cover_addresses_the_database_places_there(), Geo, shared_reader()

### Community 152 - "DeviceKind"
Cohesion: 0.20
Nodes (9): DeviceKind, Generic, Laptop, Raspberry, SmartDevice, WiFi, guess_kind(), kind_from_i64() (+1 more)

### Community 153 - "hashmap"
Cohesion: 0.22
Nodes (5): Counters, delta(), IF_OPER_STATUS_UP, IF_TYPE_SOFTWARE_LOOPBACK, read()

### Community 154 - "vt.rs"
Cohesion: 0.11
Nodes (17): a_hash_virustotal_has_not_seen_is_never_uploaded_by_itself(), API, curl(), HOLD, HOLD_AFTER, key(), KV_HOLD, lookup() (+9 more)

### Community 155 - "hashset"
Cohesion: 0.11
Nodes (9): a_domain_covers_everything_below_it_but_not_lookalikes(), decode_all(), DomainRule, DomainView, encode_all(), MAX_LIST, MAX_RULES, normalize() (+1 more)

### Community 156 - "NetInfoSource"
Cohesion: 0.33
Nodes (5): NetInfoSource, .ALL, Http, Off, TeamCymru

### Community 157 - "tcp_row"
Cohesion: 0.24
Nodes (10): ConnRow, filetime_to_unix(), fill_bytes(), kill(), killable(), read_bytes(), row_uses_network_byte_order(), set_collection() (+2 more)

### Community 158 - "HostCall"
Cohesion: 0.07
Nodes (29): HostCall, BlockedAddresses, BrowserFetch, BrowserSignIn, BrowserSignOut, ConfigGet, ConfigSet, DbExec (+21 more)

### Community 159 - "Rule"
Cohesion: 0.39
Nodes (8): enabled_outbound_allows(), enabled_outbound_blocks(), read_rule(), reading_rules_works_without_administrator(), Rule, rules_in_group(), rules_named(), rules_where()

### Community 160 - "steps"
Cohesion: 0.12
Nodes (18): runs-on, steps, environment, needs, runs-on, steps, name, url (+10 more)

### Community 161 - "Writing a RustWarden plugin"
Cohesion: 0.22
Nodes (9): Build, Calls into your plugin, Install, Notification services, Pages, Rules your plugin must follow, The code, What you may ask RustWarden for (+1 more)

### Community 162 - "Ui"
Cohesion: 0.12
Nodes (26): Ui, BarRow, bars(), changelog(), release_notes(), report_charts(), startup_controls(), brand_menu_row() (+18 more)

### Community 163 - "Priority"
Cohesion: 0.24
Nodes (6): Line, Plan, At, Drop, Pass, the_line_serves_high_first_and_squeezes_the_rest()

### Community 164 - "tlsprint.rs"
Cohesion: 0.20
Nodes (17): grease(), Hello, hello(), ja3(), ja3_drops_grease_and_is_the_md5_of_its_text(), ja3_text(), ja4(), ja4_follows_the_layout() (+9 more)

### Community 165 - "QuotaAction"
Cohesion: 0.17
Nodes (7): QuotaAction, AlertOnly, .ALL, Block, None, Throttle, ThrottleBlock

### Community 166 - "RustWarden"
Cohesion: 0.25
Nodes (8): Acknowledgements, Build from source, Built to be safe, Download, Project layout, Rescue: remove every RustWarden firewall rule, RustWarden, What it does

### Community 167 - "listeners"
Cohesion: 0.20
Nodes (8): Conn, fetch(), fetch_class(), is_listening(), Listener, listeners(), port_of(), tcp()

### Community 168 - "VirusTotal"
Cohesion: 0.29
Nodes (6): Demo mode, Reading the score, Setting it up, Uploading a file, VirusTotal, What is sent

### Community 169 - "accent.rs"
Cohesion: 0.36
Nodes (3): dword(), windows_accent(), windows_dark()

### Community 170 - "src/geo.rs"
Cohesion: 0.26
Nodes (7): Country, load(), no_giant_triangles(), Poly, Reader, world(), WORLD_BIN

### Community 171 - "countries.rs"
Cohesion: 0.27
Nodes (6): by_a2(), Entry, table!, parse_a2(), parse_name_or_a2(), search()

### Community 172 - "bundled.rs"
Cohesion: 0.20
Nodes (16): every_built_in_plugin_loads_with_its_own_id(), found(), load(), bundle!, the_abuseipdb_plugin_scores_addresses_in_alerts(), the_cloudflare_plugin_pretends_in_demo(), the_home_assistant_plugin_keeps_its_settings_and_waits_for_a_token(), the_opnsense_plugin_gates_its_options_on_a_probe() (+8 more)

### Community 173 - ".handle"
Cohesion: 0.33
Nodes (9): event(), finish(), is_demo(), num(), page(), Speedtest, start_test(), tick() (+1 more)

### Community 174 - "tamper.rs"
Cohesion: 0.16
Nodes (10): copy_path(), digest(), hash(), hex(), recall(), remember(), ROUNDS, salt() (+2 more)

### Community 175 - "AlertLevel"
Cohesion: 0.33
Nodes (4): AlertLevel, .ALL, Important, Logs

### Community 176 - ".start"
Cohesion: 0.17
Nodes (9): EtwSession, inject(), NetEvent, Data, Dns, Sni, Props, sink() (+1 more)

### Community 177 - "pcap.rs"
Cohesion: 0.19
Nodes (7): LINKTYPE_RAW, MAX_BYTES, MAX_SECS, tcp_filter(), the_filter_names_both_directions_of_one_connection(), Writer<W>, writes_the_pcap_header_and_records()

### Community 179 - "quiet"
Cohesion: 0.23
Nodes (14): authorize_stop(), end_other_instances(), end_processes(), ensure_service_running(), ok(), prepare_debug(), quiet(), remove_legacy_service() (+6 more)

### Community 180 - "StatusNote"
Cohesion: 0.20
Nodes (5): NoteLevel, Info, Vpn, Warn, StatusNote

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
Cohesion: 0.29
Nodes (5): GB, HISTORY_STEP, MB, run(), HW_WINDOW

### Community 186 - "ExtrasAct"
Cohesion: 0.29
Nodes (4): ExtrasAct, Pause, Resume, Unblock

### Community 187 - "Target"
Cohesion: 0.20
Nodes (6): only_allow_needs_a_program(), seen_from_text(), Target, Asn, Country, Domain

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
Cohesion: 0.25
Nodes (6): DataPlan, PlanDirection, .ALL, In, Out, Total

### Community 194 - "OPNsense plugin"
Cohesion: 0.14
Nodes (13): Demo mode, Device names, Gateways and the firewall log, History, Names and prefixes, OPNsense plugin, Permissions, Privacy and safety (+5 more)

### Community 195 - "Manual checks on a real machine"
Cohesion: 0.29
Nodes (6): Automated, Elevated (use "Restart as administrator"), Helper programs without administrator rights (elevated window, service installed and not), Manual checks on a real machine, Testing RustWarden, Unelevated (a normal user)

### Community 196 - "Vt"
Cohesion: 0.14
Nodes (13): Vt, Analysing, Failed, None, NotFound, OnHold, Pending, Result (+5 more)

### Community 197 - "install_service"
Cohesion: 0.18
Nodes (16): adopt_legacy_entries(), desktop_lnk(), downloads_exe(), file_version(), install_service(), installed_exe(), lnk_in(), own_version() (+8 more)

### Community 198 - ".run"
Cohesion: 0.25
Nodes (4): a_hash_with_a_final_answer_is_not_looked_up_or_sent_again(), nap(), Scanner, upload_queues_only_when_asked_and_only_once()

### Community 199 - "The Firewall tab"
Cohesion: 0.15
Nodes (13): Backing up and moving rules, Block after N minutes, Block an app by clicking it, Firewall modes, Firewall rulesets, Importing rules from another firewall app, Letting RustWarden's own helpers through, Prompt (+5 more)

### Community 200 - "alert_rules.rs"
Cohesion: 0.29
Nodes (5): parse_minute(), draft_becomes_a_rule_or_says_why_not(), labelled(), RuleDraft, RustWarden

### Community 201 - "Urgency"
Cohesion: 0.40
Nodes (4): Urgency, Important, Normal, Quiet

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

### Community 207 - "RuleAction"
Cohesion: 0.25
Nodes (6): RuleAction, .ALL, Escalate, KeepLocal, Limit, Mute

### Community 210 - "plugin-sdk"
Cohesion: 0.11
Nodes (19): example-hello, plugin-abuseipdb, plugin-cloudflare, plugin-discord, plugin-gotify, plugin-ha, plugin-ntfy, plugin-opnsense (+11 more)

### Community 212 - "AccountChange"
Cohesion: 0.29
Nodes (7): account_and_task_changes(), AccountChange, Activated, Created, Deactivated, Deleted, diff_accounts()

### Community 213 - "check"
Cohesion: 0.20
Nodes (14): UpdateChannel, Dev, Release, check(), check_url(), Checked, Latest, Newer (+6 more)

### Community 214 - "data.rs"
Cohesion: 0.06
Nodes (35): ProtectState, TrafficState, ActiveCountries, DetailRow, Glyph, App, Flag, More (+27 more)

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

### Community 226 - "AppIcon"
Cohesion: 0.08
Nodes (22): AppCategory, AiAssistants, .ALL, Browsers, CloudSync, DevTools, Other, RemoteAccess (+14 more)

### Community 227 - "Updates, backup and upkeep"
Cohesion: 0.20
Nodes (10): Backup and restore, Clean up, History and storage, Snapshots, Tamper protection, The Windows service, Uninstalling RustWarden, Updates (+2 more)

### Community 228 - "Job"
Cohesion: 0.25
Nodes (7): Job, Alert, Call, Event, Render, Stop, page()

### Community 229 - "Speedtest"
Cohesion: 0.22
Nodes (9): Adding hosts, Charts, First use, Ping Monitor, Ping Monitor and Speedtest, Removing it, Running a test, Settings (+1 more)

### Community 230 - "PCWSTR"
Cohesion: 0.18
Nodes (12): answer_stop(), DISPLAY, EV_ACK, EV_ASK, EV_NO, EV_OK, open_event(), SHOW_EVENT (+4 more)

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

### Community 239 - "AppGroup"
Cohesion: 0.29
Nodes (6): AppGroup, Active, .ALL, Inactive, Uninstalled, Windows

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

### Community 247 - "wizard.rs"
Cohesion: 0.24
Nodes (12): alerts(), databases(), firewall(), firewall_note(), show(), Step, Finish, Keep (+4 more)

### Community 248 - "Host"
Cohesion: 0.13
Nodes (14): HostReply, Err, Ok, a_plugin_cannot_keep_a_transaction_open_or_run_for_ever(), config_and_secrets_round_trip_and_gated_calls_fail(), connect_address(), Host, host_allowed() (+6 more)

### Community 249 - "Live Connections"
Cohesion: 0.40
Nodes (5): Actions, Demo mode, Driver mode extras, Live Connections, The table

### Community 250 - "DNS Log"
Cohesion: 0.40
Nodes (5): DNS Log, How it works, Settings, The table, What uses the DNS log

### Community 251 - "Behaviour baseline"
Cohesion: 0.33
Nodes (6): Behaviour baseline, Teaching it, The alerts, Turning it on, What it learns, While it learns

### Community 252 - "HistoryData"
Cohesion: 0.29
Nodes (6): HistoryData, Alerts, Traffic, HistoryFormat, Csv, Json

### Community 253 - "install_elevated"
Cohesion: 0.50
Nodes (4): ensure_recovery(), install_elevated(), remove_service(), set_recovery()

### Community 254 - "RustWarden user guide"
Cohesion: 0.50
Nodes (4): Built to be safe, RustWarden user guide, What RustWarden does, Where to start

### Community 255 - "SpeedLive"
Cohesion: 0.25
Nodes (8): SpeedLive, SpeedPhase, Download, Ping, Upload, demo_live(), demo_readings_ramp_up_through_the_three_phases(), progress_of()

### Community 256 - "Found"
Cohesion: 0.23
Nodes (10): a_changed_hash_is_not_approved(), Found, inspect(), scan_dir(), Source, Bundled, File, trusted() (+2 more)

### Community 257 - "device_events"
Cohesion: 0.25
Nodes (9): a_reused_dhcp_address_is_not_spoofing(), device_events(), device_events_find_new_changed_multi_and_returned(), DeviceEvent, MacChanged, MultiIp, New, Returned (+1 more)

### Community 258 - "Hardware"
Cohesion: 0.67
Nodes (3): Hardware, History, Per-program view

### Community 260 - "dpapi.rs"
Cohesion: 0.25
Nodes (4): protect(), round_trips_and_rejects_garbage(), take(), unprotect()

### Community 261 - "curl.rs"
Cohesion: 0.14
Nodes (8): a_full_log_moves_aside_and_restarts(), append(), line(), MAX, globbing_is_off(), PROTO, refuses_other_protocols(), run()

### Community 263 - "with_reader"
Cohesion: 0.50
Nodes (3): open_demo_db(), READERS, with_reader()

### Community 264 - "Report"
Cohesion: 0.25
Nodes (5): new_line(), Report, sample(), text_lists_every_section(), text_says_when_history_is_too_short_and_stays_under_the_limit()

### Community 265 - ".load"
Cohesion: 0.15
Nodes (10): config_dir(), config_path(), env_dir(), Mode, Demo, Live, plugin_decisions_survive_the_admin_copy_and_junk_reads_as_none(), plugins_copy_path() (+2 more)

### Community 266 - "Third-party data and credits"
Cohesion: 0.40
Nodes (5): Blocklists, Data from your own accounts, Databases, Programs and drivers, Third-party data and credits

### Community 267 - "DnsEntry"
Cohesion: 0.21
Nodes (6): DnsState, DnsEntry, each_program_and_name_is_reported_once(), hits(), is_listed(), row()

### Community 268 - "__call"
Cohesion: 0.50
Nodes (4): __alloc(), __call(), pack(), stash()

### Community 270 - "Place"
Cohesion: 0.29
Nodes (4): Place, Country, Local, Unknown

### Community 271 - "Answer"
Cohesion: 0.22
Nodes (7): Answer, Allow, Block, Direction, In, Local, Out

### Community 274 - "HardwareSample"
Cohesion: 0.18
Nodes (3): HardwareSample, HardwareSnapshot, noise()

### Community 276 - "ApiAsset"
Cohesion: 0.40
Nodes (3): Api, ApiAsset, find_asset()

### Community 278 - "AppMode"
Cohesion: 0.50
Nodes (3): AppMode, Driver, Normal

## Knowledge Gaps
- **482 isolated node(s):** `System`, `Notification`, `Label`, `Heading`, `Weak` (+477 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2258 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **24 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `RustWarden` connect `RustWarden` to `Report`, `dialogs.rs`, `DnsEntry`, `picker.rs`, `LiveConn`, `Backend`, `util.rs`, `demo.rs`, `traffic_load.rs`, `popup.rs`, `data.rs`, `driver.rs`, `ui/traffic.rs`, `StatusNote`, `.ui`, `alert_rules.rs`, `notes.rs`, `map.rs`, `QuotaStatus`, `check`, `data.rs`, `arc`, `connections.rs`, `tray_menu.rs`, `.notify`, `Dialog`, `tray.rs`, `super`, `Country`, `shots.rs`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **Are the 155 inferred relationships involving `Ui` (e.g. with `app.rs` and `.alert_tabs()`) actually correct?**
  _`Ui` has 155 INFERRED edges - model-reasoned connections that need verification._
- **What connects `System`, `Notification`, `Label` to the rest of the system?**
  _482 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `live/firewall.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.04018987341772152 - nodes in this community are weakly interconnected._
- **Why does `Db` connect `Db` to `LiveBackend`, `Event`, `curl.rs`, `quota.rs`, `bucket.rs`, `baseline.rs`, `HardwareSample`, `export.rs`, `live/apps.rs`, `store.rs`, `FwController`, `vt.rs`, `dest.rs`, `lease.rs`, `live/qos.rs`, `monitors.rs`, `domains.rs`, `Vt`, `.run`, `Scale`, `latency.rs`, `notes.rs`, `toast.rs`, `PluginFeed`, `Monitors`, `live/traffic.rs`, `.memory`, `live/dns.rs`, `.tick`, `dnstunnel.rs`, `report.rs`, `Collector`?**
  _High betweenness centrality (0.035) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Db` (e.g. with `.target_ranges()` and `.views()`) actually correct?**
  _`Db` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Should `LiveBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.03614457831325301 - nodes in this community are weakly interconnected._