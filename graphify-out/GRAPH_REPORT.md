# Graph Report - RustWarden  (2026-11-10)

## Corpus Check
- 227 files · ~309,648 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 2, .ico 1, .tsv 1)

## Summary
- 5934 nodes · 12618 edges · 243 communities (218 shown, 25 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 626 edges (avg confidence: 0.64)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `e1471195`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- live/firewall.rs
- LiveBackend
- toast.rs
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
- settings.rs
- update.rs
- guard.rs
- Backend
- manager.rs
- .memory
- Settings
- live/apps.rs
- speedtest/src/lib.rs
- live/scanner.rs
- Db
- demo.rs
- FwController
- Bg
- popup.rs
- Icon
- src/notify.rs
- pdh.rs
- alerts.rs
- AlertKind
- autostart.rs
- .bandwidth_tab
- sys/mod.rs
- icmp.rs
- sys/firewall.rs
- AlertPeriod
- wfp.rs
- QosLimit
- abuseipdb/src/lib.rs
- Context
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
- icons.rs
- asn.rs
- notify.rs
- steps
- live/qos.rs
- Call
- p2p.rs
- sys/apps.rs
- steps
- dnsguard.rs
- net.rs
- RustWarden
- monitors.rs
- clock.rs
- domains.rs
- metrics.rs
- steps
- data.rs
- beacon.rs
- store.rs
- tab
- picker.rs
- ha/src/lib.rs
- speed.rs
- sniff.rs
- opnsense/src/lib.rs
- loader.rs
- watch.rs
- map.rs
- modal.rs
- Windows system changes
- Host
- ConfirmAction
- quota.rs
- util.rs
- services.rs
- alertrules.rs
- ping/src/lib.rs
- Monitors
- arc
- live/traffic.rs
- RuleSpec
- log.rs
- netpkt.rs
- Outcome
- Priority
- scandetect.rs
- plugins.rs
- live/dns.rs
- alert_rules.rs
- Dialog
- wizard.rs
- .tick
- capture.rs
- tray.rs
- protect.rs
- RangeSet
- dnstunnel.rs
- super
- windows_extras.rs
- guest.rs
- live/geo.rs
- TcpState
- traffic_load.rs
- tab
- Alert
- sys/qos.rs
- filedialog.rs
- shots.rs
- show
- err
- host.rs
- ask.rs
- migrate.rs
- window_at
- Creating a RustWarden plugin
- upnp.rs
- wallpaper.rs
- docs.yml
- pathbuf
- QuotaStatus
- netparse.rs
- UiTree
- .apply_verdict
- notes.rs
- connections.rs
- audit.rs
- PWSTR
- PlanPeriod
- duration
- .handle
- export.rs
- render.rs
- RuleAction
- W
- toggle_beta
- pcwstr
- hashmap
- vt.rs
- StatusNote
- NetInfoSource
- Scale
- HostCall
- Rule
- steps
- Writing a RustWarden plugin
- feed
- Priority
- db.rs
- QuotaAction
- RustWarden
- run
- Card
- Dim
- __call
- countries.rs
- bundled.rs
- install_service
- quiet
- AlertLevel
- Target
- profile_state
- v1.21.3.md
- accent.rs
- Security Policy
- upnp/src/lib.rs
- PCWSTR
- ExtrasAct
- Notifications
- AGENTS.md
- Troubleshooting and FAQ
- build.rs
- PlanDirection
- OPNsense plugin
- Manual checks on a real machine
- .start
- The Firewall tab
- DlJob
- plan-release.sh
- Settings reference
- Held
- Traffic
- main.rs
- pcap.rs
- flag_data.rs
- plugin-sdk
- installed_exe
- HistoryData
- DeviceEvent
- Driver mode
- Built-in plugins
- Installing and first run
- State
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
- Live Connections
- DNS Log
- Behaviour baseline
- RustWarden user guide
- SpeedLive
- DestRule
- Hardware
- v1.20.0.md

## God Nodes (most connected - your core abstractions)
1. `Db` - 137 edges
2. `RustWarden` - 125 edges
3. `LiveBackend` - 113 edges
4. `Settings` - 111 edges
5. `Backend` - 103 edges
6. `MockBackend` - 91 edges
7. `Context` - 75 edges
8. `FwController` - 72 edges
9. `UiTree` - 71 edges
10. `AlertKind` - 68 edges

## Surprising Connections (you probably didn't know these)
- `Writer` --references--> `W`  [INFERRED]
  src/pcap.rs → build.rs
- `read_cache()` --calls--> `valid()`  [INFERRED]
  src/live/threat.rs → plugin-sdk/src/notify.rs
- `ha_config()` --calls--> `token()`  [INFERRED]
  src/plugins/legacy.rs → plugins/ha/src/lib.rs
- `packet_loop()` --calls--> `known()`  [INFERRED]
  src/live/sniff.rs → plugins/ha/src/lib.rs
- `log_lines()` --calls--> `end()`  [INFERRED]
  plugins/opnsense/src/lib.rs → src/live/lease.rs

## Import Cycles
- 1-file cycle: `src/ui/dialogs.rs -> src/ui/dialogs.rs`
- 1-file cycle: `src/ui/map.rs -> src/ui/map.rs`
- 1-file cycle: `src/data.rs -> src/data.rs`
- 1-file cycle: `src/ui/mod.rs -> src/ui/mod.rs`
- 2-file cycle: `src/plugins/wasm/manager.rs -> src/plugins/wasm/ui_tree.rs -> src/plugins/wasm/manager.rs`

## Communities (243 total, 25 thin omitted)

### Community 0 - "live/firewall.rs"
Cohesion: 0.04
Nodes (65): ACTIVE_PROFILE_KEY, adopt_legacy_rules(), allow_engine_traffic(), ASK_KEY, ask_marker_exists(), ask_marker_path(), audit_prev_path(), block_all_exceptions() (+57 more)

### Community 1 - "LiveBackend"
Cohesion: 0.04
Nodes (8): db_path(), hosts_with_the_same_label_merge_into_one_row(), LiveBackend, MAX_HOSTS, merge_hosts(), row(), share(), verdict_shown()

### Community 2 - "toast.rs"
Cohesion: 0.06
Nodes (55): ANIM_SECS, app_tile(), button(), button_colors(), checkbox(), CHEVRON_W, chrome(), chrome_edged() (+47 more)

### Community 3 - "theme.rs"
Cohesion: 0.08
Nodes (54): accent(), ACCENT, accent_default(), accent_replaces_the_defaults_and_clears(), accent_rgb(), accent_soft(), accent_text(), acrylic() (+46 more)

### Community 4 - "threat.rs"
Cohesion: 0.10
Nodes (33): a_failed_list_keeps_only_its_own_last_good_entries(), act(), add_name(), ALLOW_KEY, cache_keeps_list_names(), cache_path(), download(), feed_name() (+25 more)

### Community 5 - "MockBackend"
Cohesion: 0.05
Nodes (5): demo_bandwidth_limits_can_be_added_changed_and_cleared(), demo_destination_rules_add_replace_remove_and_reset(), demo_networks_keep_separate_devices_and_threat_lists(), demo_traffic_filter_narrows_the_sample_data(), MockBackend

### Community 6 - "widgets.rs"
Cohesion: 0.09
Nodes (46): fit_text(), area(), area_faded(), area_faded_to(), area_impl(), area_soft_to(), brand_menu_row(), check_item() (+38 more)

### Community 7 - "thinkbroadband/src/lib.rs"
Cohesion: 0.08
Nodes (51): alert_pct(), attr(), backfill(), BASE, chart(), CHART_SQL, civil_from_days(), date() (+43 more)

### Community 8 - "cloudflare/src/lib.rs"
Cohesion: 0.10
Nodes (35): args_for(), begin(), cfg(), Cloudflare, demo_step(), each_step_runs_the_right_command(), event(), EXE (+27 more)

### Community 9 - "engine.rs"
Cohesion: 0.08
Nodes (33): a_limit_only_paces_the_directions_it_names(), die(), DROP_LIMIT, DROP_WINDOW_MS, Engine, filter_loop(), filter_needs_swap(), flow_loop() (+25 more)

### Community 10 - "dialogs.rs"
Cohesion: 0.12
Nodes (48): ThreatLists, P2pApp, ABOUT_PNG, accent_picker(), ACCENTS, ALERT_JUMP, alert_settings(), Autostart (+40 more)

### Community 11 - "webview.rs"
Cohesion: 0.10
Nodes (15): CHECK, CHECK_SECS, fetch(), GIVE_UP_SECS, helper(), HOST, LOGIN, NEED_LOGIN (+7 more)

### Community 12 - "baseline.rs"
Cohesion: 0.06
Nodes (36): active_days_by_hour(), ASN_WAIT_SCANS, BUSY_HOUR, DAY, DIM_ASN, DIM_COUNTRY, DIM_HOUR, DIM_VOLUME (+28 more)

### Community 13 - "settings.rs"
Cohesion: 0.06
Nodes (29): alert_rules_are_sanitized_and_survive_a_save(), app_mode_defaults_to_normal_and_round_trips(), baseline_settings_are_clamped(), config_dir(), DataPlan, deserialize(), DNS_FEED_DEFAULT, DNS_FEED_RETIRED (+21 more)

### Community 14 - "update.rs"
Cohesion: 0.06
Nodes (43): UpdateView, Available, CheckFailed, Checking, InstallFailed, Installing, Latest, UpdateChannel (+35 more)

### Community 15 - "guard.rs"
Cohesion: 0.11
Nodes (32): fingerprint(), GUARD_PREFIX, adapter(), ARMED_KEY, DOH_ADDRS, DOH_PREFIX, doh_specs(), ENDPOINTS_KEY (+24 more)

### Community 16 - "Backend"
Cohesion: 0.04
Nodes (3): Backend, Capabilities, HardwareSnapshot

### Community 17 - "manager.rs"
Cohesion: 0.05
Nodes (71): table_prefix(), a_changed_hash_is_not_approved(), Active, annotates(), annotator(), annotator_ids(), any_notification_plugin(), apply() (+63 more)

### Community 18 - ".memory"
Cohesion: 0.16
Nodes (11): app_records_and_missing_state(), blocked_attempts_add_up_prune_and_clear(), delta(), filter_narrows_reads(), history_export_joins_names_and_respects_the_window(), report_queries_split_the_week_from_what_came_before(), retention_prunes_each_scale_separately(), service_rows_keep_their_service() (+3 more)

### Community 19 - "Settings"
Cohesion: 0.10
Nodes (11): AppMode, Driver, Normal, config_path(), Mode, Demo, Live, parse_hex() (+3 more)

### Community 20 - "live/apps.rs"
Cohesion: 0.10
Nodes (19): core_services_are_refused_and_other_services_are_not(), CRITICAL_SERVICES, describe_change(), ensure_record(), ensure_service_record(), is_svchost(), is_vpn_client(), key_for_path() (+11 more)

### Community 21 - "speedtest/src/lib.rs"
Cohesion: 0.09
Nodes (22): demo_history(), demo_result(), DEMO_STEP_MS, DEMO_TEST_SECS, EXE, EXE_SHA256, KEEP_SECS, PAGE_SQL (+14 more)

### Community 22 - "live/scanner.rs"
Cohesion: 0.07
Nodes (39): DeviceKind, Generic, Laptop, Raspberry, SmartDevice, WiFi, progress(), arp_probe() (+31 more)

### Community 23 - "Db"
Cohesion: 0.06
Nodes (7): HardwareSample, row(), Db, .APP_COLS, DeviceRow, devices_keep_user_names_and_go_offline(), dns_log_round_trips_and_prunes()

### Community 24 - "demo.rs"
Cohesion: 0.08
Nodes (27): bump(), demo_alerts(), demo_apps(), demo_block_all_shows_active(), demo_connections(), demo_connections_have_sample_rows(), demo_dest_rules(), demo_dns() (+19 more)

### Community 25 - "FwController"
Cohesion: 0.12
Nodes (13): enable_audit(), extras_paused(), extras_rules(), FwController, is_aux(), is_ours(), paused_extras(), profile_since() (+5 more)

### Community 26 - "Bg"
Cohesion: 0.16
Nodes (10): async_memo_answers_none_until_the_read_lands_then_keeps_it(), AsyncMemo, AsyncMemo<K, V>, Bg, bg_runs_the_latest_waiting_request_and_reports_a_panic_once(), Bg<T>, Memo, Memo<K, V> (+2 more)

### Community 27 - "popup.rs"
Cohesion: 0.08
Nodes (27): ThreatAct, Block, Unblock, Unwhitelist, Whitelist, ALERT_INFO_TITLE, ALERT_TITLE, ALERTS_SECTION (+19 more)

### Community 28 - "Icon"
Cohesion: 0.05
Nodes (40): Icon, Alerts, ArrowDown, ArrowUp, Bell, Bulb, Camera, Check (+32 more)

### Community 29 - "src/notify.rs"
Cohesion: 0.05
Nodes (48): simplify(), Discord, .FIELDS, .HOSTS, .ID, .NAME, DISCORD_URLS, Field (+40 more)

### Community 30 - "pdh.rs"
Cohesion: 0.09
Nodes (12): engine_type(), expand(), gpu_load(), GpuQuery, Handle, Pdh, ProcQuery, Query (+4 more)

### Community 31 - "alerts.rs"
Cohesion: 0.08
Nodes (25): account_and_task_changes(), AccountChange, Activated, Created, Deactivated, Deleted, anomaly_kinds_have_keys_and_switches(), arp_mac_change_is_reported_once() (+17 more)

### Community 32 - "AlertKind"
Cohesion: 0.05
Nodes (40): AlertKind, .ALL, AnomalyContact, AnomalyHour, AnomalyVolume, AppChanged, Arp, Away (+32 more)

### Community 33 - "autostart.rs"
Cohesion: 0.07
Nodes (15): CHILD, claim_instance(), EVENTS, LAUNCH, LAUNCH_HIDDEN, MOVED_TO, REFUSED, RUN_KEY (+7 more)

### Community 35 - "sys/mod.rs"
Cohesion: 0.08
Nodes (23): file_icon_rgba(), has_valid_embedded_signature(), service_has_sid(), from_wide(), hidden_start(), home_region(), message(), NO_WINDOW (+15 more)

### Community 36 - "icmp.rs"
Cohesion: 0.10
Nodes (9): AT_ONCE, echo(), echoes(), MAX_ADDRS, ping_v4(), ping_v6(), Round, round() (+1 more)

### Community 37 - "sys/firewall.rs"
Cohesion: 0.06
Nodes (5): PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC, PROFILES, PROTO_ANY

### Community 38 - "AlertPeriod"
Cohesion: 0.06
Nodes (32): LogState, AlertDest, .ALL, Any, Local, Remote, AlertFilter, All (+24 more)

### Community 39 - "wfp.rs"
Cohesion: 0.09
Nodes (6): app_name(), decode(), is_icmp(), on_event(), RPC_C_AUTHN_DEFAULT, Subscription

### Community 40 - "QosLimit"
Cohesion: 0.08
Nodes (16): decode_all(), directions_round_trip_and_old_lines_still_read(), encode_all(), fmt_rate(), limit(), MAX_DELAY_MS, MAX_KBPS, MAX_LIMITS (+8 more)

### Community 41 - "abuseipdb/src/lib.rs"
Cohesion: 0.17
Nodes (18): AbuseIpDb, DEFAULT_ALERT_SCORE, demo_verdict(), FRESH_SECS, is_public(), KEEP, key_ok(), lookup() (+10 more)

### Community 42 - "Context"
Cohesion: 0.10
Nodes (7): Confirm, About, Context, firewall_toggle_confirm(), virustotal_upload_confirm(), RustWarden, set_mode_and_enable()

### Community 43 - "driver.rs"
Cohesion: 0.06
Nodes (49): BLOCKED_HELP, dir(), DLL, DriverState, Blocked, Missing, Ready, folder_state_tells_missing_ready_and_blocked_apart() (+41 more)

### Community 44 - "netinfo.rs"
Cohesion: 0.08
Nodes (12): adapters(), adapters_and_neighbors_are_readable(), host_routes(), idle_seconds(), is_tunnel(), is_virtual(), Neighbor, neighbors() (+4 more)

### Community 45 - "etw.rs"
Cohesion: 0.05
Nodes (34): cached_path(), decode(), dns_answer_maps_name_to_addresses(), DNS_CLIENT, dns_payload(), DROPPED, failed_lookup_is_logged_without_addresses(), forget_dead() (+26 more)

### Community 46 - "ui/traffic.rs"
Cohesion: 0.16
Nodes (7): tick_step(), command_card(), command_card_id(), kind_icon(), popup_fit(), RustWarden, fmt_bytes()

### Community 47 - "dest.rs"
Cohesion: 0.12
Nodes (15): DestRuleView, Dest, DNS_WINDOW, firewall_rules_belong_to_their_destination_rule(), id_of(), load(), name_changes_with_the_address_list_program_and_mode_only(), rule() (+7 more)

### Community 48 - "windivert.rs"
Cohesion: 0.06
Nodes (24): Address, ChecksumFn, CloseFn, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED, FLAG_DROP, FLAG_RECV_ONLY, FLAG_SNIFF (+16 more)

### Community 49 - "conns.rs"
Cohesion: 0.06
Nodes (22): Conn, ConnRow, ENABLED, fetch(), fetch_class(), filetime_to_unix(), fill_bytes(), is_listening() (+14 more)

### Community 50 - "rules_file.rs"
Cohesion: 0.17
Nodes (13): a_file_survives_writing_and_reading(), AppRule, current_of(), destination_rules_are_added_once_and_get_fresh_ids(), file(), FORMAT, matching_state_plans_nothing(), old_files_without_settings_or_lists_still_load() (+5 more)

### Community 51 - "helper.rs"
Cohesion: 0.13
Nodes (21): a_program_that_isnt_downloaded_is_refused_before_anything_runs(), adopt(), adopt_user_copy(), adopts_only_a_genuine_copy(), cached_sha(), CHECKED, confirmed(), dir() (+13 more)

### Community 52 - "RustWarden features"
Cohesion: 0.12
Nodes (17): 🚨 Alerts and log analysis, 🧭 Behaviour baseline, Clean up, 📏 Data quotas, 🔎 DNS Log, ⚙️ Everything else, 🛡️ Firewall: your firewall, simplified, 📈 Hardware resources (+9 more)

### Community 53 - "lease.rs"
Cohesion: 0.14
Nodes (21): before_spawn(), check_again_at(), decode(), due(), encode(), end(), end_all(), GROUP (+13 more)

### Community 54 - "icons.rs"
Cohesion: 0.10
Nodes (28): line(), AppIcon, Bitwarden, Chrome, Claude, ClaudeCode, Drive, Gear (+20 more)

### Community 55 - "asn.rs"
Cohesion: 0.14
Nodes (16): curl_url(), cymru(), cymru_name(), cymru_names_are_reversed(), format_info(), from_json(), http(), json_find() (+8 more)

### Community 56 - "notify.rs"
Cohesion: 0.08
Nodes (6): balloon(), copy(), copy_truncates_and_terminates(), icon(), LINGER, worker()

### Community 57 - "steps"
Cohesion: 0.07
Nodes (27): run, GH_TOKEN, RUSTFLAGS, TAG_MATCH, UPDATE_SIGNING_KEY, jobs, release, name (+19 more)

### Community 58 - "live/qos.rs"
Cohesion: 0.13
Nodes (10): KEY, load(), NEEDS_ADMIN, Qos, remove_orphans(), run(), saved_limits_round_trip_through_the_store(), store() (+2 more)

### Community 59 - "Call"
Cohesion: 0.04
Nodes (53): Guest, API_VERSION, Call, Alert, Event, HelperDone, HelperLine, Manifest (+45 more)

### Community 60 - "p2p.rs"
Cohesion: 0.14
Nodes (19): P2P_PREFIX, blocked_keys(), blocks_only_with_detection_on_and_no_vpn(), BROWSERS, CLIENTS, Detector, ip(), is_peer_port() (+11 more)

### Community 61 - "sys/apps.rs"
Cohesion: 0.09
Nodes (6): current_process_has_a_path(), notepad_like_system_binary_has_version_info(), pid_path(), running_paths(), version_info(), VersionInfo

### Community 62 - "steps"
Cohesion: 0.07
Nodes (26): run, GH_TOKEN, RUSTFLAGS, UPDATE_SIGNING_KEY, jobs, release, name, on (+18 more)

### Community 63 - "dnsguard.rs"
Cohesion: 0.17
Nodes (14): Action, Pass, Redirect, Restore, decide(), FILTER, Guard, KEEP (+6 more)

### Community 64 - "net.rs"
Cohesion: 0.14
Nodes (18): classify(), classify_v4(), classify_v6(), dns_results_are_scanned_for_addresses(), ip(), ips_in_dns_results(), is_cgnat(), Locality (+10 more)

### Community 65 - "RustWarden"
Cohesion: 0.06
Nodes (24): BLOCK_AFTER_MINS, ConnsState, default_window(), DestDraft, DomainDraft, fit_window(), HwSeries, make_backend() (+16 more)

### Community 66 - "monitors.rs"
Cohesion: 0.10
Nodes (22): adapter_ignored(), Debounce, diff_files(), diff_tasks(), per_user_base(), plan_level(), PlanLevel, Over (+14 more)

### Community 67 - "clock.rs"
Cohesion: 0.14
Nodes (13): civil_from_days(), day_label(), days_from_civil(), file_stamp(), fmt_date(), fmt_stamp(), fmt_time_lower(), local_offset_at() (+5 more)

### Community 68 - "domains.rs"
Cohesion: 0.07
Nodes (22): a_domain_covers_everything_below_it_but_not_lookalikes(), decode_all(), DomainRule, DomainView, encode_all(), Matcher, MAX_LIST, MAX_RULES (+14 more)

### Community 69 - "metrics.rs"
Cohesion: 0.16
Nodes (13): a_slow_client_cannot_hold_the_endpoint(), bind_retrying(), Endpoint, exchange(), handle(), label(), LOG, metrics_answers_loopback_requests() (+5 more)

### Community 70 - "steps"
Cohesion: 0.08
Nodes (23): run, GALLIUM_DRIVER, MESA_SHA256, RUSTWARDEN_SHOTS, jobs, screenshots, name, on (+15 more)

### Community 71 - "data.rs"
Cohesion: 0.05
Nodes (44): TrafficState, ActiveCountries, DetailRow, EngineState, Ready, Unavailable, WindowsFirewallOff, Glyph (+36 more)

### Community 72 - "beacon.rs"
Cohesion: 0.09
Nodes (23): a_browser_is_not_exempt(), a_cdn_suffix_lowers_the_level_without_hiding_it(), an_unsigned_program_with_tiny_uniform_payloads_to_a_rare_host_is_reported(), BULK_PER_MIN, chrome_polling_a_live_video_cdn_is_not_reported(), ctx(), DEFAULT_CDN, FORGET_AFTER (+15 more)

### Community 73 - "store.rs"
Cohesion: 0.15
Nodes (10): a_mute_rule_records_the_alert_but_shows_nothing(), ALERT_SINK, an_escalate_rule_makes_an_alert_important_with_a_popup(), blocked_addresses(), country_of(), install_alert_sink(), lock(), raise_plugin_alert() (+2 more)

### Community 74 - "tab"
Cohesion: 0.17
Nodes (18): BLUE, camera(), column_count(), columns(), columns_keep_the_extremes_and_average_the_rest(), day_shift(), export(), FLASH_SECS (+10 more)

### Community 75 - "picker.rs"
Cohesion: 0.12
Nodes (3): Pick, run(), start()

### Community 76 - "ha/src/lib.rs"
Cohesion: 0.11
Nodes (26): event(), explain(), Ha, headers(), known(), LOGO, lookup(), next_due() (+18 more)

### Community 77 - "speed.rs"
Cohesion: 0.10
Nodes (15): query_speed(), arc_mesh(), dial_frac(), DIAL_START, DIAL_SWEEP, down(), MARKS, RANGES (+7 more)

### Community 78 - "sniff.rs"
Cohesion: 0.07
Nodes (40): a_udp_flow_filter_names_both_directions_and_one_ip_version(), dhcp_reply(), FILTER, flow_loop(), Flows, kill_udp(), MAX_FLOWS, packet_loop() (+32 more)

### Community 79 - "opnsense/src/lib.rs"
Cohesion: 0.06
Nodes (53): flag(), a_leftover_alias_is_reported(), a_read_check_keeps_the_earlier_write_result(), a_read_only_key_cannot_push(), a_read_only_key_is_told_apart(), a_writable_key_creates_then_removes_the_test_alias(), Added, Denied (+45 more)

### Community 80 - "loader.rs"
Cohesion: 0.11
Nodes (21): a_wrong_api_version_is_refused(), an_infinite_loop_is_stopped_by_the_fuel_limit(), call_tick(), engine(), FUEL, hash_of(), host_calls_are_checked_by_the_host(), host_import() (+13 more)

### Community 81 - "watch.rs"
Cohesion: 0.14
Nodes (9): device_use(), open(), root_certs(), RUN_KEYS, service_names(), snapshots_read_the_registry(), startup_entries(), subkeys() (+1 more)

### Community 82 - "map.rs"
Cohesion: 0.21
Nodes (13): ARC, blocked_color(), clamp_center(), home_dot(), land(), land_active(), land_edge(), land_hover() (+5 more)

### Community 83 - "modal.rs"
Cohesion: 0.09
Nodes (3): find(), find_all(), MAIN

### Community 84 - "Windows system changes"
Cohesion: 0.05
Nodes (42): Alert types, Application info monitor, ARP spoofing detection, Beaconing detection, Behaviour baseline, Behaviour: new country or network, Behaviour: traffic spike, Behaviour: unusual hour (+34 more)

### Community 85 - "Host"
Cohesion: 0.13
Nodes (14): HostReply, Err, Ok, a_plugin_cannot_keep_a_transaction_open_or_run_for_ever(), config_and_secrets_round_trip_and_gated_calls_fail(), connect_address(), Host, host_allowed() (+6 more)

### Community 86 - "ConfirmAction"
Cohesion: 0.10
Nodes (21): ConfirmAction, ApplyRules, BlockProgram, BlockWindowsExtras, CleanUp, ClearHistory, DeleteProfile, FirewallEnabled (+13 more)

### Community 87 - "quota.rs"
Cohesion: 0.23
Nodes (17): action_none_only_warns(), block_is_asked_for_until_it_happens(), clock_moved_back_starts_a_fresh_period(), Decision, deleted_disabled_or_retargeted_quotas_orphan_their_track(), jumping_straight_over_alerts_once(), KV_KEY, level() (+9 more)

### Community 88 - "util.rs"
Cohesion: 0.12
Nodes (12): app_icon_rgba(), BIT_UNITS, BITS, decode_png(), fmt_clock(), fmt_clock_secs(), fmt_rate(), fmt_size() (+4 more)

### Community 89 - "services.rs"
Cohesion: 0.15
Nodes (8): by_pid(), label(), lists_running_services(), one_service_is_named_with_its_short_name(), SC_MANAGER_ENUMERATE_SERVICE, Service, shared_hosts_are_keyed_in_a_stable_order(), svc()

### Community 90 - "alertrules.rs"
Cohesion: 0.19
Nodes (14): AlertInfo, AlertRule, conditions_all_have_to_hold(), contains_nocase(), decide(), Effect, first_enabled_match_wins(), in_window() (+6 more)

### Community 91 - "ping/src/lib.rs"
Cohesion: 0.07
Nodes (22): Event, Bool, ChartMissing, Click, File, Index, Number, TabOpened (+14 more)

### Community 93 - "arc"
Cohesion: 0.06
Nodes (36): FirewallMode, .ALL, AskToConnect, BlockAll, ClickToBlock, PROMPT_FOR, prompt_for_label(), Theme (+28 more)

### Community 94 - "live/traffic.rs"
Cohesion: 0.12
Nodes (22): TrafficDelta, kernel_service(), a_tls_server_name_names_its_own_programs_traffic(), Aggregator, aggregator_sums_by_key(), Collector, ev(), Flow (+14 more)

### Community 95 - "RuleSpec"
Cohesion: 0.22
Nodes (8): a_service_rule_is_a_separate_row_with_its_own_name(), block_spec(), block_specs_are_scoped_to_one_program_and_direction(), icmp_specs(), lan_block_is_its_own_outbound_rule(), lan_specs(), ping_rules_are_ours_allow_icmp_and_stay_off_the_program_list(), RuleSpec

### Community 96 - "log.rs"
Cohesion: 0.07
Nodes (21): every_tab_has_its_own_key_that_reads_back(), Tab, AlertRules, .ALL, Bandwidth, Connections, DestRules, Dns (+13 more)

### Community 97 - "netpkt.rs"
Cohesion: 0.14
Nodes (16): pkt(), limited_ports(), addresses_can_be_swapped_in_ipv4_only(), FlowKey, ipv4_tcp(), parse(), Parsed, reads_ipv4_tcp_and_both_directions_share_one_flow() (+8 more)

### Community 98 - "Outcome"
Cohesion: 0.07
Nodes (27): about_click_hits(), Outcome, Apply, Close, Confirmed, ExportRules, ImportRules, InstallService (+19 more)

### Community 99 - "Priority"
Cohesion: 0.12
Nodes (10): LimitDir, .ALL, Both, Down, Up, Priority, .ALL, High (+2 more)

### Community 100 - "scandetect.rs"
Cohesion: 0.18
Nodes (12): a_burst_from_many_sources_is_a_flood(), Detector, Finding, PortScan, SynFlood, FLOOD_PER_SEC, ip(), many_ports_from_one_source_is_a_scan_reported_once() (+4 more)

### Community 101 - "plugins.rs"
Cohesion: 0.17
Nodes (15): card(), CREATE_URL, files(), Modal, modal(), Approve, modal_id(), Install (+7 more)

### Community 102 - "live/dns.rs"
Cohesion: 0.10
Nodes (18): DnsState, DnsEntry, a_failed_feed_keeps_only_its_own_names(), cache_path(), check(), clean(), domain_of(), download() (+10 more)

### Community 103 - "alert_rules.rs"
Cohesion: 0.17
Nodes (8): ALL_DAYS, DAY_NAMES, parse_minute(), draft_becomes_a_rule_or_says_why_not(), kind_title(), labelled(), RuleDraft, RustWarden

### Community 104 - "Dialog"
Cohesion: 0.11
Nodes (16): Dialog, Confirm, Info, InstallService, NewProfile, Password, Rename, Report (+8 more)

### Community 105 - "wizard.rs"
Cohesion: 0.24
Nodes (12): alerts(), databases(), firewall(), firewall_note(), show(), Step, Finish, Keep (+4 more)

### Community 106 - ".tick"
Cohesion: 0.21
Nodes (8): orphaned(), run(), Track, tracks_from_text(), tracks_round_trip_through_text(), tracks_to_text(), user_blocked(), Worker

### Community 108 - "capture.rs"
Cohesion: 0.16
Nodes (3): Capture, Session, CaptureStatus

### Community 109 - "tray.rs"
Cohesion: 0.11
Nodes (12): Country, load(), no_giant_triangles(), Poly, Reader, world(), WORLD_BIN, icon() (+4 more)

### Community 110 - "protect.rs"
Cohesion: 0.04
Nodes (27): FirewallInfo, png(), texture(), PendingBlock, ROW_H, RustWarden, Chart, RANGES (+19 more)

### Community 111 - "RangeSet"
Cohesion: 0.11
Nodes (19): block_mode_never_touches_the_local_network(), blocked_set(), complement_covers_everything_else(), ip(), local_ranges(), long_lists_are_split_into_rules_within_the_limits(), MAX_CHARS_PER_RULE, MAX_RANGES_PER_RULE (+11 more)

### Community 112 - "dnstunnel.rs"
Cohesion: 0.13
Nodes (14): entropy(), LONG, many_random_names_under_one_domain_are_a_tunnel(), MAX_DOMAINS, MIN_NAMES, odd(), QUIET_AFTER_REPORT, RANDOM_BITS (+6 more)

### Community 113 - "super"
Cohesion: 0.17
Nodes (7): a_full_log_moves_aside_and_restarts(), append(), MAX, globbing_is_off(), PROTO, refuses_other_protocols(), run()

### Community 114 - "windows_extras.rs"
Cohesion: 0.21
Nodes (9): expand(), Group, GROUPS, is_protected(), matches(), PROTECTED, resolve(), t() (+1 more)

### Community 115 - "guest.rs"
Cohesion: 0.13
Nodes (36): blocked_addresses(), browser_fetch(), browser_sign_in(), browser_sign_out(), config_get(), config_set(), db_exec(), db_query() (+28 more)

### Community 116 - "live/geo.rs"
Cohesion: 0.05
Nodes (42): KIND_WAN, asn_db_path(), asn_networks(), city_db_path(), country_networks_cover_addresses_the_database_places_there(), DATABASES, db_path(), DbInfo (+34 more)

### Community 117 - "TcpState"
Cohesion: 0.12
Nodes (15): state_raw(), tcp6_row(), TcpState, Closed, CloseWait, Closing, DeleteTcb, Established (+7 more)

### Community 118 - "traffic_load.rs"
Cohesion: 0.10
Nodes (20): Scope, .ALL, Both, Lan, Wan, TrafficDir, .ALL, Both (+12 more)

### Community 119 - "tab"
Cohesion: 0.21
Nodes (7): calendar(), Feed, Line, refresh_status(), reload(), State, tab()

### Community 120 - "Alert"
Cohesion: 0.07
Nodes (23): Alert, AppGroup, Active, .ALL, Inactive, Uninstalled, Windows, Country (+15 more)

### Community 121 - "sys/qos.rs"
Cohesion: 0.21
Nodes (9): add_exclusion(), remove_exclusion(), apply(), list(), parse_policy(), Policy, powershell(), remove() (+1 more)

### Community 122 - "filedialog.rs"
Cohesion: 0.13
Nodes (5): filter_list(), filter_list_is_double_null_terminated_with_all_files_last(), MAX_TEXT_BYTES, open(), open_async()

### Community 123 - "shots.rs"
Cohesion: 0.15
Nodes (8): SCREENS, SETTLE, Setup, Shots, Window, Ask, Main, Threat

### Community 124 - "show"
Cohesion: 0.30
Nodes (14): SpeedPage, card_frame(), chart(), gauge(), live_chart(), mbps(), nice_ceil(), results_card() (+6 more)

### Community 125 - "err"
Cohesion: 0.24
Nodes (12): add_rule(), adopt_rule(), bool_variant(), default_outbound_blocked(), enable_windows_firewall(), err(), interfaces_variant(), policy() (+4 more)

### Community 126 - "host.rs"
Cohesion: 0.10
Nodes (13): a_keypair_is_32_bytes_each_and_the_public_key_follows_from_the_private(), a_pinned_ca_is_checked_and_its_file_removed(), a_pinned_ca_skips_the_revocation_lookup_a_private_ca_cannot_answer(), a_value_cannot_break_out_of_the_curl_config(), answer(), CaFile, curl_config(), DB_CALL_LIMIT (+5 more)

### Community 127 - "ask.rs"
Cohesion: 0.17
Nodes (14): file_name(), icon_for(), count(), fw_closed_since(), IN_FLIGHT, is_noise(), lookups_on(), MAX_IN_FLIGHT (+6 more)

### Community 128 - "migrate.rs"
Cohesion: 0.18
Nodes (14): DONE, merge_dir(), merge_keeps_what_the_new_folder_has(), move_program_files(), move_user_data(), OLD, rename_in_db(), run() (+6 more)

### Community 129 - "window_at"
Cohesion: 0.23
Nodes (8): app_in(), each_window(), is_frame_host(), proc(), Search, State, window_at(), with()

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

### Community 135 - "QuotaStatus"
Cohesion: 0.17
Nodes (8): QuotaLevel, Ok, Over, Warn, QuotaStatus, demo_quotas(), used_by(), Quota

### Community 136 - "netparse.rs"
Cohesion: 0.25
Nodes (10): client_hello(), dns(), DnsMessage, finds_the_server_name_and_refuses_junk(), host_ok(), name_at(), query(), reads_queries_and_answers_with_compressed_names() (+2 more)

### Community 137 - "UiTree"
Cohesion: 0.05
Nodes (48): UiTree, Button, Card, Column, Copy, Disabled, Dropdown, FileButton (+40 more)

### Community 138 - ".apply_verdict"
Cohesion: 0.10
Nodes (22): Answer, Allow, Block, Direction, In, Local, Out, critical_reason() (+14 more)

### Community 139 - "notes.rs"
Cohesion: 0.18
Nodes (12): Device, DeviceNote, demo_devices(), demo_networks(), Annotator, device_kind(), device_url(), display_name() (+4 more)

### Community 141 - "connections.rs"
Cohesion: 0.07
Nodes (23): LiveConn, Act, Block, Capture, Kill, compare(), conn(), ConnGroup (+15 more)

### Community 142 - "audit.rs"
Cohesion: 0.22
Nodes (9): auditpol(), blocked_since(), data(), failure_audit_on(), parse_events(), reads_outbound_drops_only(), set_failure_audit(), SUBCATEGORY (+1 more)

### Community 143 - "PWSTR"
Cohesion: 0.25
Nodes (8): handler(), launch_gui(), logon_hidden(), make_events(), report(), report_step(), run_dispatcher(), service_main()

### Community 144 - "PlanPeriod"
Cohesion: 0.17
Nodes (11): PeriodKind, Day, Month, Week, period_kind(), period_word(), PlanPeriod, .ALL (+3 more)

### Community 145 - "duration"
Cohesion: 0.29
Nodes (5): GB, HISTORY_STEP, MB, run(), HW_WINDOW

### Community 146 - ".handle"
Cohesion: 0.29
Nodes (10): event(), finish(), is_demo(), num(), page(), settings(), Speedtest, start_test() (+2 more)

### Community 147 - "export.rs"
Cohesion: 0.23
Nodes (9): a_value_that_looks_like_a_formula_is_made_text(), AlertRow, alerts_csv(), csv_keeps_awkward_values_in_one_cell(), json(), json_uses_field_names(), traffic_csv(), traffic_csv_has_one_line_per_row_after_the_header() (+1 more)

### Community 149 - "RuleAction"
Cohesion: 0.25
Nodes (6): RuleAction, .ALL, Escalate, KeepLocal, Limit, Mute

### Community 150 - "W"
Cohesion: 0.18
Nodes (4): W, Writer, EVENT_ID, write()

### Community 151 - "toggle_beta"
Cohesion: 0.38
Nodes (6): every_built_in_plugin_loads_with_its_own_id(), found(), beta_hidden(), beta_shows_hidden_plugins_and_locking_uninstalls_them(), listed(), toggle_beta()

### Community 152 - "pcwstr"
Cohesion: 0.25
Nodes (4): protect(), round_trips_and_rejects_garbage(), take(), unprotect()

### Community 153 - "hashmap"
Cohesion: 0.22
Nodes (5): Counters, delta(), IF_OPER_STATUS_UP, IF_TYPE_SOFTWARE_LOOPBACK, read()

### Community 154 - "vt.rs"
Cohesion: 0.07
Nodes (33): Vt, Analysing, Failed, None, NotFound, OnHold, Pending, Result (+25 more)

### Community 155 - "StatusNote"
Cohesion: 0.18
Nodes (5): NoteLevel, Info, Vpn, Warn, StatusNote

### Community 156 - "NetInfoSource"
Cohesion: 0.33
Nodes (5): NetInfoSource, .ALL, Http, Off, TeamCymru

### Community 157 - "Scale"
Cohesion: 0.17
Nodes (8): Scale, .ALL, S1, S30, S600, inspect_db(), inspect_detail(), UsageEntry

### Community 158 - "HostCall"
Cohesion: 0.07
Nodes (29): HostCall, BlockedAddresses, BrowserFetch, BrowserSignIn, BrowserSignOut, ConfigGet, ConfigSet, DbExec (+21 more)

### Community 159 - "Rule"
Cohesion: 0.33
Nodes (9): rules_to_suspend(), enabled_outbound_allows(), enabled_outbound_blocks(), read_rule(), reading_rules_works_without_administrator(), Rule, rules_in_group(), rules_named() (+1 more)

### Community 160 - "steps"
Cohesion: 0.12
Nodes (18): runs-on, steps, environment, needs, runs-on, steps, name, url (+10 more)

### Community 161 - "Writing a RustWarden plugin"
Cohesion: 0.22
Nodes (9): Build, Calls into your plugin, Install, Notification services, Pages, Rules your plugin must follow, The code, What you may ask RustWarden for (+1 more)

### Community 162 - "feed"
Cohesion: 0.24
Nodes (9): a_steady_timer_is_reported_once(), Beat, cfg(), Config, feed(), ip(), regular(), Series (+1 more)

### Community 163 - "Priority"
Cohesion: 0.24
Nodes (6): Line, Plan, At, Drop, Pass, the_line_serves_high_first_and_squeezes_the_rest()

### Community 164 - "db.rs"
Cohesion: 0.10
Nodes (18): AlertCheck, add_column(), alert_chain_survives_reads_and_names_the_first_change(), alert_hash(), alerts_round_trip_and_mark_read(), BASE_ALERTED, BASE_LEARNED, BASE_NORMAL (+10 more)

### Community 165 - "QuotaAction"
Cohesion: 0.17
Nodes (7): QuotaAction, AlertOnly, .ALL, Block, None, Throttle, ThrottleBlock

### Community 166 - "RustWarden"
Cohesion: 0.25
Nodes (8): Acknowledgements, Build from source, Built to be safe, Download, Project layout, Rescue: remove every RustWarden firewall rule, RustWarden, What it does

### Community 167 - "run"
Cohesion: 0.40
Nodes (6): Ev, GiveUp, Loaded, Msg, run(), mark()

### Community 169 - "Dim"
Cohesion: 0.40
Nodes (4): Dim, App, Proto, Remote

### Community 170 - "__call"
Cohesion: 0.50
Nodes (4): __alloc(), __call(), pack(), stash()

### Community 171 - "countries.rs"
Cohesion: 0.27
Nodes (6): by_a2(), Entry, table!, parse_a2(), parse_name_or_a2(), search()

### Community 172 - "bundled.rs"
Cohesion: 0.25
Nodes (14): load(), bundle!, the_abuseipdb_plugin_scores_addresses_in_alerts(), the_cloudflare_plugin_pretends_in_demo(), the_home_assistant_plugin_keeps_its_settings_and_waits_for_a_token(), the_opnsense_plugin_gates_its_options_on_a_probe(), the_ping_plugin_stores_rounds_and_serves_its_chart(), the_ping_toolbar_opens_add_and_manage_windows() (+6 more)

### Community 173 - "install_service"
Cohesion: 0.43
Nodes (6): adopt_legacy_entries(), desktop_lnk(), install_service(), lnk_in(), shortcut(), start_menu_lnk()

### Community 174 - "quiet"
Cohesion: 0.20
Nodes (16): authorize_stop(), end_other_instances(), end_processes(), ensure_service_running(), ok(), prepare_debug(), quiet(), remove_legacy_service() (+8 more)

### Community 175 - "AlertLevel"
Cohesion: 0.33
Nodes (4): AlertLevel, .ALL, Important, Logs

### Community 176 - "Target"
Cohesion: 0.29
Nodes (5): only_allow_needs_a_program(), Target, Asn, Country, Domain

### Community 179 - "accent.rs"
Cohesion: 0.36
Nodes (3): dword(), windows_accent(), windows_dark()

### Community 182 - "Security Policy"
Cohesion: 0.29
Nodes (6): Design notes, Reporting a vulnerability, Scope, Security Policy, Supported versions, What to expect

### Community 183 - "upnp/src/lib.rs"
Cohesion: 0.05
Nodes (60): clean(), click(), CONFLICT, control_of(), DESC, envelope(), find_router(), finds_the_internet_service_and_makes_its_address_absolute() (+52 more)

### Community 184 - "PCWSTR"
Cohesion: 0.18
Nodes (12): answer_stop(), DISPLAY, EV_ACK, EV_ASK, EV_NO, EV_OK, open_event(), SHOW_EVENT (+4 more)

### Community 186 - "ExtrasAct"
Cohesion: 0.29
Nodes (4): ExtrasAct, Pause, Resume, Unblock

### Community 188 - "Notifications"
Cohesion: 0.13
Nodes (13): Choosing which alerts are sent, Notifications, Setting one up, Snooze, Weekly summary, When the internet is down, Windows event log, Demo mode (+5 more)

### Community 189 - "AGENTS.md"
Cohesion: 0.33
Nodes (5): File updates, graphify, Project rules, Version control, Versioning

### Community 190 - "Troubleshooting and FAQ"
Cohesion: 0.14
Nodes (14): A program (or everything) lost its internet, Bandwidth limits don't affect downloads, I forgot the tamper-protection password, I got a "Firewall rule monitor" alert, Microsoft Defender flagged the driver, No country flags or map, Reporting a bug, The DNS log doesn't show my browser's lookups (+6 more)

### Community 191 - "build.rs"
Cohesion: 0.28
Nodes (7): BG, bundle_plugins(), graph_pixels(), H, main(), PALETTE, PLUGINS

### Community 193 - "PlanDirection"
Cohesion: 0.33
Nodes (5): PlanDirection, .ALL, In, Out, Total

### Community 194 - "OPNsense plugin"
Cohesion: 0.14
Nodes (13): Demo mode, Device names, Gateways and the firewall log, History, Names and prefixes, OPNsense plugin, Permissions, Privacy and safety (+5 more)

### Community 195 - "Manual checks on a real machine"
Cohesion: 0.33
Nodes (5): Automated, Elevated (use "Restart as administrator"), Manual checks on a real machine, Testing RustWarden, Unelevated (a normal user)

### Community 198 - ".start"
Cohesion: 0.31
Nodes (3): EtwSession, Props, stop_by_name()

### Community 199 - "The Firewall tab"
Cohesion: 0.15
Nodes (13): Backing up and moving rules, Block after N minutes, Block an app by clicking it, Firewall modes, Firewall rulesets, Importing rules from another firewall app, Letting RustWarden's own helpers through, Prompt (+5 more)

### Community 202 - "plan-release.sh"
Cohesion: 0.83
Nodes (3): section(), plan-release.sh script, skip()

### Community 203 - "Settings reference"
Cohesion: 0.15
Nodes (13): Alerts, Countries & Network, Data Plan, Firewall, General, Malicious IPs, Network Scanner, Other (+5 more)

### Community 205 - "Traffic"
Cohesion: 0.15
Nodes (13): Alert pins, Common controls, Filter, Graph view, History and retention, Kernel & System split, Map view, Program details (+5 more)

### Community 207 - "pcap.rs"
Cohesion: 0.15
Nodes (7): LINKTYPE_RAW, MAX_BYTES, MAX_SECS, tcp_filter(), the_filter_names_both_directions_of_one_connection(), Writer<W>, writes_the_pcap_header_and_records()

### Community 210 - "plugin-sdk"
Cohesion: 0.10
Nodes (20): example-hello, plugin-abuseipdb, plugin-cloudflare, plugin-discord, plugin-gotify, plugin-ha, plugin-ntfy, plugin-opnsense (+12 more)

### Community 213 - "installed_exe"
Cohesion: 0.17
Nodes (14): downloads_exe(), ensure_recovery(), file_version(), in_program_files(), install_elevated(), installed_exe(), own_version(), refresh_stale_service() (+6 more)

### Community 214 - "HistoryData"
Cohesion: 0.29
Nodes (6): HistoryData, Alerts, Traffic, HistoryFormat, Csv, Json

### Community 215 - "DeviceEvent"
Cohesion: 0.25
Nodes (9): a_reused_dhcp_address_is_not_spoofing(), device_events(), device_events_find_new_changed_multi_and_returned(), DeviceEvent, MacChanged, MultiIp, New, Returned (+1 more)

### Community 216 - "Driver mode"
Cohesion: 0.17
Nodes (12): Demo mode, Driver mode, Force DNS, Host names, Line speed, Logs, Microsoft Defender, QUIC fallback (+4 more)

### Community 217 - "Built-in plugins"
Cohesion: 0.18
Nodes (11): AbuseIPDB, Built-in plugins, Cloudflare Tunnel, Home Assistant, Notification plugins, Ping Monitor, Prometheus Metrics, Shodan InternetDB (+3 more)

### Community 218 - "Installing and first run"
Cohesion: 0.20
Nodes (10): Administrator rights, Building from source, Checking the download (optional), Download, Installing and first run, Next steps, Run as administrator without a prompt every time, Running it (+2 more)

### Community 226 - "State"
Cohesion: 0.14
Nodes (7): ConnectAsk, only_the_made_up_threat_is_a_test(), Threat, .TEST_IP, HwNow, State, TrafficNow

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
Cohesion: 0.33
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
Cohesion: 0.40
Nodes (5): Behaviour baseline, Teaching it, The alerts, Turning it on, What it learns

### Community 254 - "RustWarden user guide"
Cohesion: 0.50
Nodes (4): Built to be safe, RustWarden user guide, What RustWarden does, Where to start

### Community 255 - "SpeedLive"
Cohesion: 0.25
Nodes (8): SpeedLive, SpeedPhase, Download, Ping, Upload, demo_live(), demo_readings_ramp_up_through_the_three_phases(), progress_of()

### Community 256 - "DestRule"
Cohesion: 0.15
Nodes (7): demo_dest_status(), decode_all(), DestRule, encode_all(), Mode, Block, OnlyAllow

### Community 258 - "Hardware"
Cohesion: 0.67
Nodes (3): Hardware, History, Per-program view

## Knowledge Gaps
- **479 isolated node(s):** `rustwarden`, `System`, `Notification`, `Label`, `Heading` (+474 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2195 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **25 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Settings` connect `Settings` to `LiveBackend`, `toast.rs`, `MockBackend`, `pathbuf`, `QuotaStatus`, `dialogs.rs`, `baseline.rs`, `settings.rs`, `update.rs`, `Backend`, `manager.rs`, `toggle_beta`, `demo.rs`, `NetInfoSource`, `alerts.rs`, `AlertKind`, `QuotaAction`, `Context`, `driver.rs`, `rules_file.rs`, `asn.rs`, `RustWarden`, `data.rs`, `store.rs`, `alertrules.rs`, `arc`, `Outcome`, `plugins.rs`, `Dialog`, `wizard.rs`, `protect.rs`, `live/geo.rs`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Db` (e.g. with `.target_ranges()` and `.views()`) actually correct?**
  _`Db` has 11 INFERRED edges - model-reasoned connections that need verification._
- **What connects `rustwarden`, `System`, `Notification` to the rest of the system?**
  _479 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `live/firewall.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.04036036036036036 - nodes in this community are weakly interconnected._
- **Why does `Db` connect `Db` to `LiveBackend`, `toast.rs`, `QuotaStatus`, `notes.rs`, `baseline.rs`, `.memory`, `export.rs`, `live/apps.rs`, `FwController`, `vt.rs`, `Scale`, `db.rs`, `dest.rs`, `lease.rs`, `live/qos.rs`, `monitors.rs`, `domains.rs`, `store.rs`, `tab`, `pcap.rs`, `quota.rs`, `ping/src/lib.rs`, `Monitors`, `live/traffic.rs`, `live/dns.rs`, `.tick`, `live/geo.rs`, `tab`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Are the 26 inferred relationships involving `RustWarden` (e.g. with `Alert` and `AlertCheck`) actually correct?**
  _`RustWarden` has 26 INFERRED edges - model-reasoned connections that need verification._
- **Should `LiveBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.037654320987654324 - nodes in this community are weakly interconnected._