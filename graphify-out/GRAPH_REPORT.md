# Graph Report - RustWarden  (2026-11-06)

## Corpus Check
- 180 files · ~258,675 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 2, .ico 1, .tsv 1)

## Summary
- 5185 nodes · 11315 edges · 215 communities (194 shown, 21 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 546 edges (avg confidence: 0.66)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `581633be`
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
- AppIcon
- Backend
- manager.rs
- RustWarden
- Settings
- live/apps.rs
- speedtest/src/lib.rs
- live/scanner.rs
- Db
- demo.rs
- FwController
- util.rs
- popup.rs
- Icon
- src/notify.rs
- pdh.rs
- alerts.rs
- AlertKind
- autostart.rs
- RustWarden
- sys/mod.rs
- icmp.rs
- sys/firewall.rs
- AlertPeriod
- wfp.rs
- QosLimit
- report.rs
- .notify
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
- TrayAct
- monitors.rs
- clock.rs
- State
- metrics.rs
- steps
- data.rs
- FirewallMode
- Shared
- tab
- modal.rs
- ha/src/lib.rs
- speed.rs
- sniff.rs
- opnsense/src/lib.rs
- loader.rs
- watch.rs
- map.rs
- run
- latency.rs
- ui_tree.rs
- ConfirmAction
- quota.rs
- live/geo.rs
- services.rs
- domains.rs
- ping/src/lib.rs
- Monitors
- shots.rs
- live/traffic.rs
- picker.rs
- RangeSet
- netpkt.rs
- Outcome
- Priority
- scandetect.rs
- protect.rs
- live/dns.rs
- alert_rules.rs
- Dialog
- wizard.rs
- .tick
- store.rs
- capture.rs
- tray.rs
- pos2
- RangeSet
- DestRule
- pcap.rs
- windows_extras.rs
- guest.rs
- AppRecord
- TcpState
- traffic_load.rs
- Country
- alertrules.rs
- sys/qos.rs
- .memory
- .handle
- tamper.rs
- err
- host.rs
- ask.rs
- migrate.rs
- UsageEntry
- legacy.rs
- upnp.rs
- wallpaper.rs
- Tab
- pathbuf
- QuotaStatus
- netparse.rs
- HistoryData
- SpeedLive
- notes.rs
- connections.rs
- tcp_row
- PWSTR
- PlanPeriod
- HardwareSample
- render.rs
- export.rs
- src/geo.rs
- .ui
- curl.rs
- pcwstr
- hashmap
- vt.rs
- StatusNote
- Vt
- Bg
- HostCall
- Rule
- window_at
- DeviceKind
- HardwareSample
- Line
- db.rs
- QuotaAction
- listeners
- Direction
- Card
- check
- Found
- countries.rs
- IconCache
- AsyncMemo
- UpdateView
- AlertLevel
- accent.rs
- FirewallInfo
- audit.rs
- AlertCheck
- SpeedRoute
- Threat
- Security Policy
- upnp/src/lib.rs
- download_sha
- path
- ExtrasAct
- AccountChange
- RuleSpec
- AGENTS.md
- Deserialize
- build.rs
- NetInfoSource
- PlanDirection
- Serialize
- Manual checks on a real machine
- Dim
- with
- ApiAsset
- plan-release.sh
- Held
- main.rs
- flag_data.rs
- plugin-sdk
- DeviceEvent
- tcp6_row

## God Nodes (most connected - your core abstractions)
1. `Db` - 132 edges
2. `RustWarden` - 125 edges
3. `LiveBackend` - 113 edges
4. `Settings` - 106 edges
5. `Backend` - 103 edges
6. `MockBackend` - 88 edges
7. `FwController` - 67 edges
8. `AlertKind` - 64 edges
9. `Icon` - 62 edges
10. `UiTree` - 58 edges

## Surprising Connections (you probably didn't know these)
- `Writer` --references--> `W`  [INFERRED]
  src/pcap.rs → build.rs
- `badge()` --references--> `UiTree`  [EXTRACTED]
  plugins/opnsense/src/lib.rs → plugin-sdk/src/lib.rs
- `read_cache()` --calls--> `valid()`  [INFERRED]
  src/live/threat.rs → plugin-sdk/src/notify.rs
- `ha_config()` --calls--> `url()`  [INFERRED]
  src/plugins/legacy.rs → plugins/ha/src/lib.rs
- `check()` --calls--> `url()`  [INFERRED]
  src/update.rs → plugins/ha/src/lib.rs

## Import Cycles
- 1-file cycle: `src/ui/plugins.rs -> src/ui/plugins.rs`
- 1-file cycle: `src/ui/map.rs -> src/ui/map.rs`
- 1-file cycle: `src/data.rs -> src/data.rs`
- 1-file cycle: `src/ui/mod.rs -> src/ui/mod.rs`
- 2-file cycle: `src/plugins/wasm/manager.rs -> src/plugins/wasm/ui_tree.rs -> src/plugins/wasm/manager.rs`

## Communities (215 total, 21 thin omitted)

### Community 0 - "live/firewall.rs"
Cohesion: 0.04
Nodes (64): ACTIVE_PROFILE_KEY, adopt_legacy_rules(), allow_engine_traffic(), ASK_KEY, ask_marker_exists(), ask_marker_path(), audit_prev_path(), block_all_exceptions() (+56 more)

### Community 1 - "LiveBackend"
Cohesion: 0.04
Nodes (6): db_path(), LiveBackend, MAX_HOSTS, row(), share(), verdict_shown()

### Community 2 - "toast.rs"
Cohesion: 0.06
Nodes (55): ANIM_SECS, app_tile(), button(), button_colors(), checkbox(), CHEVRON_W, chrome(), chrome_edged() (+47 more)

### Community 3 - "theme.rs"
Cohesion: 0.08
Nodes (54): accent(), ACCENT, accent_default(), accent_replaces_the_defaults_and_clears(), accent_rgb(), accent_soft(), accent_text(), acrylic() (+46 more)

### Community 4 - "threat.rs"
Cohesion: 0.10
Nodes (32): a_failed_list_keeps_only_its_own_last_good_entries(), act(), add_name(), ALLOW_KEY, cache_keeps_list_names(), cache_path(), download(), feed_name() (+24 more)

### Community 5 - "MockBackend"
Cohesion: 0.05
Nodes (5): demo_bandwidth_limits_can_be_added_changed_and_cleared(), demo_destination_rules_add_replace_remove_and_reset(), demo_networks_keep_separate_devices_and_threat_lists(), demo_traffic_filter_narrows_the_sample_data(), MockBackend

### Community 6 - "widgets.rs"
Cohesion: 0.09
Nodes (45): fit_text(), area(), area_faded(), area_faded_to(), area_impl(), area_soft_to(), brand_menu_row(), check_item() (+37 more)

### Community 7 - "thinkbroadband/src/lib.rs"
Cohesion: 0.09
Nodes (50): alert_pct(), attr(), backfill(), BASE, chart(), CHART_SQL, civil_from_days(), date() (+42 more)

### Community 8 - "cloudflare/src/lib.rs"
Cohesion: 0.10
Nodes (32): args_for(), begin(), cfg(), Cloudflare, demo_step(), event(), EXE, finished() (+24 more)

### Community 9 - "engine.rs"
Cohesion: 0.08
Nodes (18): a_limit_only_paces_the_directions_it_names(), DROP_LIMIT, DROP_WINDOW_MS, held_packets_come_out_earliest_first(), is_flood(), LOG, MAX_DELAY_MS, MAX_FILTER_PORTS (+10 more)

### Community 10 - "dialogs.rs"
Cohesion: 0.09
Nodes (46): P2pApp, about_click_hits(), ABOUT_CLICKS, ABOUT_PNG, accent_picker(), ACCENTS, ALERT_JUMP, alert_settings() (+38 more)

### Community 11 - "webview.rs"
Cohesion: 0.06
Nodes (35): CHECK, CHECK_SECS, Ev, GiveUp, Loaded, Msg, fetch(), GIVE_UP_SECS (+27 more)

### Community 12 - "baseline.rs"
Cohesion: 0.07
Nodes (26): active_days_by_hour(), BUSY_HOUR, DAY, DIM_ASN, DIM_COUNTRY, DIM_HOUR, DIM_VOLUME, hour_why() (+18 more)

### Community 13 - "settings.rs"
Cohesion: 0.07
Nodes (28): alert_rules_are_sanitized_and_survive_a_save(), app_mode_defaults_to_normal_and_round_trips(), baseline_settings_are_clamped(), config_dir(), deserialize(), DNS_FEED_DEFAULT, DNS_FEED_RETIRED, dns_log_defaults_and_clamp() (+20 more)

### Community 14 - "update.rs"
Cohesion: 0.09
Nodes (12): ASSET_STEMS, CHECK_QUERY, check_signature(), cleanup(), der_to_raw(), MAX_NOTES, MIN_NOTES, PROGRESS (+4 more)

### Community 15 - "AppIcon"
Cohesion: 0.07
Nodes (23): AppCategory, AiAssistants, .ALL, Browsers, CloudSync, DevTools, Other, RemoteAccess (+15 more)

### Community 16 - "Backend"
Cohesion: 0.03
Nodes (4): AlertCheck, Backend, Capabilities, ScanState

### Community 17 - "manager.rs"
Cohesion: 0.10
Nodes (36): annotates(), annotator(), annotator_ids(), any_notification_plugin(), apply(), broadcast_alert(), drop_tables(), erase() (+28 more)

### Community 18 - "RustWarden"
Cohesion: 0.06
Nodes (23): BLOCK_AFTER_MINS, ConnsState, default_window(), DestDraft, DnsState, DomainDraft, fit_window(), HwSeries (+15 more)

### Community 19 - "Settings"
Cohesion: 0.10
Nodes (9): AppMode, Driver, Normal, config_path(), Mode, Demo, Live, parse_hex() (+1 more)

### Community 20 - "live/apps.rs"
Cohesion: 0.11
Nodes (20): core_services_are_refused_and_other_services_are_not(), CRITICAL_SERVICES, describe_change(), ensure_record(), ensure_service_record(), file_name(), is_svchost(), is_vpn_client() (+12 more)

### Community 21 - "speedtest/src/lib.rs"
Cohesion: 0.10
Nodes (18): DEMO_STEP_MS, DEMO_TEST_SECS, EXE, EXE_SHA256, KEEP_SECS, PAGE_SQL, parse(), reads_a_result_and_converts_bytes_to_megabits() (+10 more)

### Community 22 - "live/scanner.rs"
Cohesion: 0.09
Nodes (30): progress(), arp_probe(), Found, MAX_PREFIX_HOSTS, nbstat(), nbstat_request(), networks(), oui_map() (+22 more)

### Community 23 - "Db"
Cohesion: 0.06
Nodes (7): row(), app_records_and_missing_state(), Db, .APP_COLS, DeviceRow, devices_keep_user_names_and_go_offline(), dns_log_round_trips_and_prunes()

### Community 24 - "demo.rs"
Cohesion: 0.08
Nodes (29): FirewallApp, demo_alerts(), demo_apps(), demo_block_all_shows_active(), demo_connections(), demo_connections_have_sample_rows(), demo_dest_rules(), demo_devices() (+21 more)

### Community 25 - "FwController"
Cohesion: 0.13
Nodes (11): extras_paused(), extras_rules(), FwController, is_aux(), is_ours(), paused_extras(), profile_since(), removed_apps() (+3 more)

### Community 26 - "util.rs"
Cohesion: 0.13
Nodes (10): app_icon_rgba(), BIT_UNITS, BITS, decode_png(), fmt_rate(), fmt_size(), scale(), scale_in() (+2 more)

### Community 27 - "popup.rs"
Cohesion: 0.10
Nodes (22): ALERT_INFO_TITLE, ALERT_TITLE, ALERTS_SECTION, ask_buttons(), ASK_INFO_TITLE, ask_size(), ASK_TITLE, ASK_W (+14 more)

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
Cohesion: 0.09
Nodes (20): anomaly_kinds_have_keys_and_switches(), arp_mac_change_is_reported_once(), ArpChange, device_events(), device_events_find_new_changed_multi_and_returned(), device_use_reports_new_and_later_uses(), diff_arp(), diff_dns() (+12 more)

### Community 32 - "AlertKind"
Cohesion: 0.05
Nodes (35): AlertKind, .ALL, AnomalyContact, AnomalyHour, AnomalyVolume, AppChanged, Arp, Away (+27 more)

### Community 33 - "autostart.rs"
Cohesion: 0.05
Nodes (55): adopt_legacy_entries(), authorize_stop(), CHILD, claim_instance(), desktop_lnk(), DISPLAY, downloads_exe(), end_other_instances() (+47 more)

### Community 34 - "RustWarden"
Cohesion: 0.18
Nodes (5): cell(), labelled(), profile_confirm(), RustWarden, screen_size()

### Community 35 - "sys/mod.rs"
Cohesion: 0.08
Nodes (22): file_icon_rgba(), has_valid_embedded_signature(), service_has_sid(), from_wide(), hidden_start(), home_region(), is_elevated(), message() (+14 more)

### Community 36 - "icmp.rs"
Cohesion: 0.11
Nodes (9): AT_ONCE, echo(), echoes(), MAX_ADDRS, ping_v4(), ping_v6(), Round, round() (+1 more)

### Community 37 - "sys/firewall.rs"
Cohesion: 0.06
Nodes (5): PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC, PROFILES, PROTO_ANY

### Community 38 - "AlertPeriod"
Cohesion: 0.08
Nodes (21): AlertDest, .ALL, Any, Local, Remote, AlertFilter, All, Important (+13 more)

### Community 39 - "wfp.rs"
Cohesion: 0.09
Nodes (7): app_name(), decode(), dos_path(), is_icmp(), on_event(), RPC_C_AUTHN_DEFAULT, swap_device()

### Community 40 - "QosLimit"
Cohesion: 0.08
Nodes (15): decode_all(), directions_round_trip_and_old_lines_still_read(), encode_all(), fmt_rate(), limit(), MAX_DELAY_MS, MAX_KBPS, MAX_LOSS_PCT (+7 more)

### Community 41 - "report.rs"
Cohesion: 0.12
Nodes (23): a_report_is_due_once_per_slot(), build(), build_finds_new_hosts_only_with_older_history(), country_of(), due(), KV_LAST, last_slot(), LISTED (+15 more)

### Community 42 - ".notify"
Cohesion: 0.22
Nodes (3): Confirm, RustWarden, set_mode_and_enable()

### Community 43 - "driver.rs"
Cohesion: 0.09
Nodes (25): BLOCKED_HELP, dir(), DLL, DriverState, Blocked, Missing, Ready, folder_state_tells_missing_ready_and_blocked_apart() (+17 more)

### Community 44 - "netinfo.rs"
Cohesion: 0.09
Nodes (10): adapters(), adapters_and_neighbors_are_readable(), idle_seconds(), is_tunnel(), Neighbor, neighbors(), proxy_snapshot(), sockaddr_ip() (+2 more)

### Community 45 - "etw.rs"
Cohesion: 0.05
Nodes (36): cached_path(), decode(), dns_answer_maps_name_to_addresses(), DNS_CLIENT, dns_payload(), DROPPED, EtwSession, failed_lookup_is_logged_without_addresses() (+28 more)

### Community 46 - "ui/traffic.rs"
Cohesion: 0.12
Nodes (11): blur_averages_and_keeps_length(), box_blur(), row_in(), tick_step(), command_card(), command_card_id(), kind_icon(), popup_fit() (+3 more)

### Community 47 - "dest.rs"
Cohesion: 0.14
Nodes (14): Dest, DNS_WINDOW, firewall_rules_belong_to_their_destination_rule(), id_of(), load(), name_changes_with_the_address_list_program_and_mode_only(), rule(), RULES_KEY (+6 more)

### Community 48 - "windivert.rs"
Cohesion: 0.06
Nodes (23): Address, ChecksumFn, CloseFn, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED, FLAG_RECV_ONLY, FLAG_SNIFF, flow_address() (+15 more)

### Community 49 - "conns.rs"
Cohesion: 0.07
Nodes (3): ENABLED, STATE_ESTABLISHED, STATE_SYN_SENT

### Community 50 - "rules_file.rs"
Cohesion: 0.16
Nodes (13): a_file_survives_writing_and_reading(), AppRule, destination_rules_are_added_once_and_get_fresh_ids(), DIRECTIONS, file(), FORMAT, matching_state_plans_nothing(), old_files_without_settings_or_lists_still_load() (+5 more)

### Community 51 - "helper.rs"
Cohesion: 0.16
Nodes (13): a_program_that_isnt_downloaded_is_refused_before_anything_runs(), adopt(), adopt_user_copy(), adopts_only_a_genuine_copy(), dir(), install(), ready(), run_tool() (+5 more)

### Community 52 - "RustWarden features"
Cohesion: 0.05
Nodes (34): 🚨 Alerts and log analysis, 🧭 Behaviour baseline, Clean up, 📏 Data quotas, 🔎 DNS Log, ⚙️ Everything else, 🛡️ Firewall: your firewall, simplified, 📈 Hardware resources (+26 more)

### Community 53 - "lease.rs"
Cohesion: 0.14
Nodes (21): before_spawn(), check_again_at(), decode(), due(), encode(), end(), end_all(), GROUP (+13 more)

### Community 54 - "icons.rs"
Cohesion: 0.32
Nodes (11): a_ring_has_no_repeated_end_point(), app_icon(), app_icon_for(), arc_points(), flag(), flag_texture(), glyph(), outline() (+3 more)

### Community 55 - "asn.rs"
Cohesion: 0.14
Nodes (16): curl_url(), cymru(), cymru_name(), cymru_names_are_reversed(), format_info(), from_json(), http(), json_val() (+8 more)

### Community 56 - "notify.rs"
Cohesion: 0.09
Nodes (6): balloon(), copy(), copy_truncates_and_terminates(), icon(), LINGER, worker()

### Community 57 - "steps"
Cohesion: 0.07
Nodes (27): run, GH_TOKEN, RUSTFLAGS, TAG_MATCH, UPDATE_SIGNING_KEY, jobs, release, name (+19 more)

### Community 58 - "live/qos.rs"
Cohesion: 0.14
Nodes (10): KEY, load(), NEEDS_ADMIN, Qos, run(), saved_limits_round_trip_through_the_store(), store(), without_administrator_rights_a_limit_is_refused() (+2 more)

### Community 59 - "Call"
Cohesion: 0.06
Nodes (35): Guest, API_VERSION, Call, Alert, Event, HelperDone, HelperLine, Manifest (+27 more)

### Community 60 - "p2p.rs"
Cohesion: 0.13
Nodes (20): fingerprint(), P2P_PREFIX, blocked_keys(), blocks_only_with_detection_on_and_no_vpn(), BROWSERS, CLIENTS, Detector, ip() (+12 more)

### Community 61 - "sys/apps.rs"
Cohesion: 0.09
Nodes (6): current_process_has_a_path(), notepad_like_system_binary_has_version_info(), pid_path(), running_paths(), version_info(), VersionInfo

### Community 62 - "steps"
Cohesion: 0.07
Nodes (26): run, GH_TOKEN, RUSTFLAGS, UPDATE_SIGNING_KEY, jobs, release, name, on (+18 more)

### Community 63 - "dnsguard.rs"
Cohesion: 0.15
Nodes (14): Action, Pass, Redirect, Restore, decide(), FILTER, Guard, KEEP (+6 more)

### Community 64 - "net.rs"
Cohesion: 0.14
Nodes (18): classify(), classify_v4(), classify_v6(), dns_results_are_scanned_for_addresses(), ip(), ips_in_dns_results(), is_cgnat(), Locality (+10 more)

### Community 65 - "TrayAct"
Cohesion: 0.09
Nodes (20): Gated, Exit, Restart, ServiceStop, Settings, prompt_for_label(), RustWarden, TrayAct (+12 more)

### Community 66 - "monitors.rs"
Cohesion: 0.10
Nodes (23): adapter_ignored(), Debounce, diff_files(), diff_tasks(), dns_leaks(), DnsAdapter, per_user_base(), plan_level() (+15 more)

### Community 67 - "clock.rs"
Cohesion: 0.14
Nodes (13): civil_from_days(), day_label(), days_from_civil(), file_stamp(), fmt_date(), fmt_stamp(), fmt_time_lower(), local_offset_at() (+5 more)

### Community 68 - "State"
Cohesion: 0.19
Nodes (16): die(), Engine, filter_loop(), filter_needs_swap(), flow_loop(), Limit, limited_ports(), log() (+8 more)

### Community 69 - "metrics.rs"
Cohesion: 0.16
Nodes (12): bind_retrying(), Endpoint, exchange(), handle(), label(), LOG, metrics_answers_loopback_requests(), render() (+4 more)

### Community 70 - "steps"
Cohesion: 0.08
Nodes (23): run, GALLIUM_DRIVER, MESA_SHA256, RUSTWARDEN_SHOTS, jobs, screenshots, name, on (+15 more)

### Community 71 - "data.rs"
Cohesion: 0.06
Nodes (41): ActiveCountries, DetailRow, Glyph, App, Flag, More, Window, MapConnection (+33 more)

### Community 72 - "FirewallMode"
Cohesion: 0.20
Nodes (7): FirewallMode, .ALL, AskToConnect, BlockAll, ClickToBlock, mode_confirm(), prompt_step()

### Community 73 - "Shared"
Cohesion: 0.17
Nodes (6): a_mute_rule_records_the_alert_but_shows_nothing(), an_escalate_rule_makes_an_alert_important_with_a_popup(), lock(), raise_plugin_alert(), Shared, shared()

### Community 74 - "tab"
Cohesion: 0.17
Nodes (8): day_shift(), Feed, Line, refresh_status(), reload(), State, tab(), view_of()

### Community 75 - "modal.rs"
Cohesion: 0.09
Nodes (3): find(), find_all(), MAIN

### Community 76 - "ha/src/lib.rs"
Cohesion: 0.11
Nodes (26): event(), explain(), Ha, headers(), known(), LOGO, lookup(), next_due() (+18 more)

### Community 77 - "speed.rs"
Cohesion: 0.11
Nodes (25): SpeedPage, query_speed(), arc_mesh(), card_frame(), chart(), dial_frac(), DIAL_START, DIAL_SWEEP (+17 more)

### Community 78 - "sniff.rs"
Cohesion: 0.20
Nodes (12): FILTER, flow_loop(), Flows, MAX_FLOWS, packet_loop(), refresh(), report(), run() (+4 more)

### Community 79 - "opnsense/src/lib.rs"
Cohesion: 0.08
Nodes (34): flag(), a_leftover_alias_is_reported(), a_read_check_keeps_the_earlier_write_result(), a_read_only_key_cannot_push(), a_read_only_key_is_told_apart(), a_writable_key_creates_then_removes_the_test_alias(), Added, Denied (+26 more)

### Community 80 - "loader.rs"
Cohesion: 0.12
Nodes (19): a_wrong_api_version_is_refused(), an_infinite_loop_is_stopped_by_the_fuel_limit(), call_tick(), engine(), FUEL, hash_of(), host_calls_are_checked_by_the_host(), host_import() (+11 more)

### Community 81 - "watch.rs"
Cohesion: 0.14
Nodes (9): device_use(), open(), root_certs(), RUN_KEYS, service_names(), snapshots_read_the_registry(), startup_entries(), subkeys() (+1 more)

### Community 82 - "map.rs"
Cohesion: 0.21
Nodes (13): ARC, blocked_color(), clamp_center(), home_dot(), land(), land_active(), land_edge(), land_hover() (+5 more)

### Community 83 - "run"
Cohesion: 0.13
Nodes (19): Active, Job, Alert, Call, Event, Render, Stop, load_saved() (+11 more)

### Community 84 - "latency.rs"
Cohesion: 0.18
Nodes (18): BLUE, calendar(), camera(), column_count(), columns(), columns_keep_the_extremes_and_average_the_rest(), export(), FLASH_SECS (+10 more)

### Community 85 - "ui_tree.rs"
Cohesion: 0.06
Nodes (28): CHART_DIALOG_CLOSE, CHART_LAYOUT, CHART_RANGE, CHART_REFRESH, CHART_SIGNIN, ChartLine, Event, Bool (+20 more)

### Community 86 - "ConfirmAction"
Cohesion: 0.07
Nodes (26): ConfirmAction, ApplyRules, BlockProgram, BlockWindowsExtras, CleanUp, ClearHistory, DeleteProfile, FirewallEnabled (+18 more)

### Community 87 - "quota.rs"
Cohesion: 0.25
Nodes (17): action_none_only_warns(), block_is_asked_for_until_it_happens(), clock_moved_back_starts_a_fresh_period(), Decision, deleted_disabled_or_retargeted_quotas_orphan_their_track(), jumping_straight_over_alerts_once(), KV_KEY, level() (+9 more)

### Community 88 - "live/geo.rs"
Cohesion: 0.08
Nodes (18): asn_db_path(), asn_networks(), city_db_path(), country_networks_cover_addresses_the_database_places_there(), DATABASES, db_path(), DbInfo, default_db_path() (+10 more)

### Community 89 - "services.rs"
Cohesion: 0.15
Nodes (8): by_pid(), label(), lists_running_services(), one_service_is_named_with_its_short_name(), SC_MANAGER_ENUMERATE_SERVICE, Service, shared_hosts_are_keyed_in_a_stable_order(), svc()

### Community 90 - "domains.rs"
Cohesion: 0.07
Nodes (22): a_domain_covers_everything_below_it_but_not_lookalikes(), decode_all(), DomainRule, DomainView, encode_all(), Matcher, MAX_LIST, MAX_RULES (+14 more)

### Community 91 - "ping/src/lib.rs"
Cohesion: 0.06
Nodes (43): UiTree, Button, Column, Copy, Disabled, Dropdown, Grid, Heading (+35 more)

### Community 93 - "shots.rs"
Cohesion: 0.14
Nodes (8): SCREENS, SETTLE, Setup, Shots, Window, Ask, Main, Threat

### Community 94 - "live/traffic.rs"
Cohesion: 0.12
Nodes (20): KIND_LAN, KIND_UNKNOWN, KIND_WAN, TrafficDelta, kernel_service(), Aggregator, aggregator_sums_by_key(), Collector (+12 more)

### Community 96 - "RangeSet"
Cohesion: 0.10
Nodes (15): ip(), MAX_CHARS_PER_RULE, MAX_RANGES_PER_RULE, MAX_RULES_PER_DEST, merge(), merge_seen(), only_allow_needs_a_program(), seen_addresses_expire() (+7 more)

### Community 97 - "netpkt.rs"
Cohesion: 0.15
Nodes (15): pkt(), addresses_can_be_swapped_in_ipv4_only(), FlowKey, ipv4_tcp(), parse(), Parsed, reads_ipv4_tcp_and_both_directions_share_one_flow(), reads_ipv6_udp_and_refuses_what_it_cannot_place() (+7 more)

### Community 98 - "Outcome"
Cohesion: 0.09
Nodes (27): ThreatLists, driver_rows(), other_section(), Outcome, Apply, Close, Confirmed, ExportRules (+19 more)

### Community 99 - "Priority"
Cohesion: 0.12
Nodes (10): LimitDir, .ALL, Both, Down, Up, Priority, .ALL, High (+2 more)

### Community 100 - "scandetect.rs"
Cohesion: 0.18
Nodes (12): a_burst_from_many_sources_is_a_flood(), Detector, Finding, PortScan, SynFlood, FLOOD_PER_SEC, ip(), many_ports_from_one_source_is_a_scan_reported_once() (+4 more)

### Community 101 - "protect.rs"
Cohesion: 0.15
Nodes (10): PendingBlock, block(), countdown_is_the_earliest_block_of_that_app(), countdown_of(), DEFAULT_COLS, held_row_keeps_its_place_while_others_move(), hold_in_place(), ROW_H (+2 more)

### Community 102 - "live/dns.rs"
Cohesion: 0.12
Nodes (15): DnsEntry, cache_path(), check(), clean(), domain_of(), download(), each_program_and_name_is_reported_once(), hits() (+7 more)

### Community 103 - "alert_rules.rs"
Cohesion: 0.11
Nodes (14): ALL_DAYS, DAY_NAMES, parse_minute(), RuleAction, .ALL, Escalate, KeepLocal, Limit (+6 more)

### Community 104 - "Dialog"
Cohesion: 0.15
Nodes (12): Dialog, About, Confirm, Info, InstallService, NewProfile, Password, Rename (+4 more)

### Community 105 - "wizard.rs"
Cohesion: 0.27
Nodes (12): alerts(), databases(), firewall(), firewall_note(), show(), Step, Finish, Keep (+4 more)

### Community 106 - ".tick"
Cohesion: 0.21
Nodes (8): orphaned(), run(), Track, tracks_from_text(), tracks_round_trip_through_text(), tracks_to_text(), user_blocked(), Worker

### Community 107 - "store.rs"
Cohesion: 0.24
Nodes (8): ALERT_SINK, country_of(), FwSnapshot, HwNow, install_alert_sink(), NetworkInfo, State, TrafficNow

### Community 108 - "capture.rs"
Cohesion: 0.20
Nodes (3): Capture, Session, CaptureStatus

### Community 109 - "tray.rs"
Cohesion: 0.17
Nodes (5): icon(), Tray, TrayCmd, Menu, Toggle

### Community 110 - "pos2"
Cohesion: 0.05
Nodes (27): PROMPT_FOR, Theme, Dark, Light, ROW_H, RustWarden, Chart, RANGES (+19 more)

### Community 111 - "RangeSet"
Cohesion: 0.26
Nodes (9): block_mode_never_touches_the_local_network(), blocked_set(), complement_covers_everything_else(), local_ranges(), long_lists_are_split_into_rules_within_the_limits(), RangeSet, set(), single_addresses_print_alone_and_mapped_v4_counts_as_v4() (+1 more)

### Community 112 - "DestRule"
Cohesion: 0.12
Nodes (8): demo_dest_status(), decode_all(), DestRule, DestRuleView, encode_all(), Mode, Block, OnlyAllow

### Community 113 - "pcap.rs"
Cohesion: 0.15
Nodes (7): LINKTYPE_RAW, MAX_BYTES, MAX_SECS, tcp_filter(), the_filter_names_both_directions_of_one_connection(), Writer<W>, writes_the_pcap_header_and_records()

### Community 114 - "windows_extras.rs"
Cohesion: 0.21
Nodes (9): expand(), Group, GROUPS, is_protected(), matches(), PROTECTED, resolve(), t() (+1 more)

### Community 115 - "guest.rs"
Cohesion: 0.12
Nodes (39): __alloc(), browser_fetch(), browser_sign_in(), browser_sign_out(), __call(), config_get(), config_set(), db_exec() (+31 more)

### Community 116 - "AppRecord"
Cohesion: 0.24
Nodes (8): learning(), local_day_hour(), new_item(), run(), throttled(), Worker, AppRecord, BaselineItem

### Community 117 - "TcpState"
Cohesion: 0.13
Nodes (14): state_raw(), TcpState, Closed, CloseWait, Closing, DeleteTcb, Established, FinWait1 (+6 more)

### Community 118 - "traffic_load.rs"
Cohesion: 0.09
Nodes (20): Scope, .ALL, Both, Lan, Wan, TrafficDir, .ALL, Both (+12 more)

### Community 119 - "Country"
Cohesion: 0.11
Nodes (12): Alert, Country, France, Germany, Ireland, Iso, Local, Netherlands (+4 more)

### Community 120 - "alertrules.rs"
Cohesion: 0.19
Nodes (14): AlertInfo, AlertRule, conditions_all_have_to_hold(), contains_nocase(), decide(), Effect, first_enabled_match_wins(), in_window() (+6 more)

### Community 121 - "sys/qos.rs"
Cohesion: 0.21
Nodes (9): add_exclusion(), remove_exclusion(), apply(), list(), parse_policy(), Policy, powershell(), remove() (+1 more)

### Community 122 - ".memory"
Cohesion: 0.23
Nodes (10): blocked_attempts_add_up_prune_and_clear(), delta(), filter_narrows_reads(), history_export_joins_names_and_respects_the_window(), report_queries_split_the_week_from_what_came_before(), retention_prunes_each_scale_separately(), service_rows_keep_their_service(), totals_split_wan_and_lan() (+2 more)

### Community 123 - ".handle"
Cohesion: 0.23
Nodes (14): demo_history(), demo_result(), event(), finish(), is_demo(), num(), page(), settings() (+6 more)

### Community 124 - "tamper.rs"
Cohesion: 0.18
Nodes (7): digest(), hash(), hex(), ROUNDS, salt(), verify(), checks_the_release_signature()

### Community 125 - "err"
Cohesion: 0.22
Nodes (13): add_rule(), adopt_rule(), bool_variant(), default_outbound_blocked(), enable_windows_firewall(), err(), policy(), profile_state() (+5 more)

### Community 126 - "host.rs"
Cohesion: 0.13
Nodes (15): a_value_cannot_break_out_of_the_curl_config(), answer(), config_and_secrets_round_trip_and_gated_calls_fail(), curl_config(), Host, host_allowed(), host_with_db(), http() (+7 more)

### Community 127 - "ask.rs"
Cohesion: 0.18
Nodes (13): icon_for(), count(), fw_closed_since(), IN_FLIGHT, is_noise(), lookups_on(), MAX_IN_FLIGHT, MAX_OPEN_ASKS (+5 more)

### Community 128 - "migrate.rs"
Cohesion: 0.33
Nodes (11): DONE, merge_dir(), merge_keeps_what_the_new_folder_has(), move_program_files(), move_user_data(), OLD, rename_in_db(), run() (+3 more)

### Community 129 - "UsageEntry"
Cohesion: 0.18
Nodes (8): Scale, .ALL, S1, S30, S600, inspect_db(), inspect_detail(), UsageEntry

### Community 130 - "legacy.rs"
Cohesion: 0.16
Nodes (22): ha_config(), migrate_tables(), NOTIFICATIONS, old_ping_rows_move_into_the_plugin_table_once(), old_speedtest_rows_move_into_the_plugin_table(), old_thinkbroadband_samples_move_into_the_plugin_table(), old_values(), old_values_are_found_trimmed_and_empty_ones_skipped() (+14 more)

### Community 131 - "upnp.rs"
Cohesion: 0.21
Nodes (6): discover(), Gateway, lan_addr(), location_of(), private(), SEARCH

### Community 133 - "Tab"
Cohesion: 0.10
Nodes (16): every_tab_has_its_own_key_that_reads_back(), Tab, AlertRules, .ALL, Bandwidth, Connections, DestRules, Dns (+8 more)

### Community 134 - "pathbuf"
Cohesion: 0.23
Nodes (9): disable(), disables_the_features_that_use_downloads(), remove(), removes_files_and_folders_and_ignores_missing(), run(), size(), targets(), warning() (+1 more)

### Community 135 - "QuotaStatus"
Cohesion: 0.15
Nodes (9): QuotaLevel, Ok, Over, Warn, QuotaStatus, demo_quotas(), used_by(), Quota (+1 more)

### Community 136 - "netparse.rs"
Cohesion: 0.28
Nodes (10): client_hello(), dns(), DnsMessage, finds_the_server_name_and_refuses_junk(), host_ok(), name_at(), query(), reads_queries_and_answers_with_compressed_names() (+2 more)

### Community 137 - "HistoryData"
Cohesion: 0.29
Nodes (6): HistoryData, Alerts, Traffic, HistoryFormat, Csv, Json

### Community 138 - "SpeedLive"
Cohesion: 0.25
Nodes (8): SpeedLive, SpeedPhase, Download, Ping, Upload, demo_live(), demo_readings_ramp_up_through_the_three_phases(), progress_of()

### Community 139 - "notes.rs"
Cohesion: 0.20
Nodes (10): Device, DeviceNote, Annotator, device_kind(), device_url(), display_name(), flag(), ICON (+2 more)

### Community 141 - "connections.rs"
Cohesion: 0.07
Nodes (23): LiveConn, Act, Block, Capture, Kill, compare(), conn(), ConnGroup (+15 more)

### Community 142 - "tcp_row"
Cohesion: 0.24
Nodes (10): ConnRow, filetime_to_unix(), fill_bytes(), kill(), killable(), read_bytes(), row_uses_network_byte_order(), set_collection() (+2 more)

### Community 143 - "PWSTR"
Cohesion: 0.15
Nodes (14): answer_stop(), handler(), launch_gui(), logon_hidden(), make_events(), open_event(), report(), report_step() (+6 more)

### Community 144 - "PlanPeriod"
Cohesion: 0.17
Nodes (11): PeriodKind, Day, Month, Week, period_kind(), period_word(), PlanPeriod, .ALL (+3 more)

### Community 145 - "HardwareSample"
Cohesion: 0.29
Nodes (5): GB, HISTORY_STEP, MB, run(), HW_WINDOW

### Community 146 - "render.rs"
Cohesion: 0.15
Nodes (4): png(), texture(), scene(), triangle()

### Community 147 - "export.rs"
Cohesion: 0.24
Nodes (8): AlertRow, alerts_csv(), csv_keeps_awkward_values_in_one_cell(), json(), json_uses_field_names(), traffic_csv(), traffic_csv_has_one_line_per_row_after_the_header(), TrafficRow

### Community 148 - "src/geo.rs"
Cohesion: 0.26
Nodes (7): Country, load(), no_giant_triangles(), Poly, Reader, world(), WORLD_BIN

### Community 150 - ".ui"
Cohesion: 0.15
Nodes (4): snap(), Plugin, RustWarden, service()

### Community 151 - "curl.rs"
Cohesion: 0.28
Nodes (3): PROTO, refuses_other_protocols(), run()

### Community 152 - "pcwstr"
Cohesion: 0.11
Nodes (8): W, Writer, protect(), round_trips_and_rejects_garbage(), take(), unprotect(), EVENT_ID, write()

### Community 153 - "hashmap"
Cohesion: 0.22
Nodes (5): Counters, delta(), IF_OPER_STATUS_UP, IF_TYPE_SOFTWARE_LOOPBACK, read()

### Community 154 - "vt.rs"
Cohesion: 0.12
Nodes (17): a_hash_virustotal_has_not_seen_is_never_uploaded_by_itself(), a_hash_with_a_final_answer_is_not_looked_up_or_sent_again(), API, curl(), HOLD, HOLD_AFTER, key(), lookup() (+9 more)

### Community 155 - "StatusNote"
Cohesion: 0.18
Nodes (5): NoteLevel, Info, Vpn, Warn, StatusNote

### Community 156 - "Vt"
Cohesion: 0.15
Nodes (12): Vt, Analysing, Failed, None, NotFound, OnHold, Pending, Result (+4 more)

### Community 157 - "Bg"
Cohesion: 0.26
Nodes (5): AsyncMemo<K, V>, Bg, bg_runs_the_latest_waiting_request_and_reports_a_panic_once(), Bg<T>, wait()

### Community 158 - "HostCall"
Cohesion: 0.07
Nodes (27): HostCall, BrowserFetch, BrowserSignIn, BrowserSignOut, ConfigGet, ConfigSet, DbExec, DbQuery (+19 more)

### Community 159 - "Rule"
Cohesion: 0.33
Nodes (9): rules_to_suspend(), enabled_outbound_allows(), enabled_outbound_blocks(), read_rule(), reading_rules_works_without_administrator(), Rule, rules_in_group(), rules_named() (+1 more)

### Community 160 - "window_at"
Cohesion: 0.26
Nodes (6): app_in(), is_frame_host(), proc(), Search, State, window_at()

### Community 161 - "DeviceKind"
Cohesion: 0.20
Nodes (9): DeviceKind, Generic, Laptop, Raspberry, SmartDevice, WiFi, guess_kind(), kind_from_i64() (+1 more)

### Community 162 - "HardwareSample"
Cohesion: 0.18
Nodes (3): HardwareSample, HardwareSnapshot, noise()

### Community 163 - "Line"
Cohesion: 0.24
Nodes (6): Line, Plan, At, Drop, Pass, the_line_serves_high_first_and_squeezes_the_rest()

### Community 164 - "db.rs"
Cohesion: 0.13
Nodes (15): add_column(), alert_chain_survives_reads_and_names_the_first_change(), alert_hash(), alerts_round_trip_and_mark_read(), BASE_ALERTED, BASE_LEARNED, BASE_NORMAL, chained() (+7 more)

### Community 165 - "QuotaAction"
Cohesion: 0.20
Nodes (7): QuotaAction, AlertOnly, .ALL, Block, None, Throttle, ThrottleBlock

### Community 166 - "listeners"
Cohesion: 0.22
Nodes (7): Conn, fetch(), fetch_class(), Listener, listeners(), port_of(), tcp()

### Community 167 - "Direction"
Cohesion: 0.10
Nodes (21): Answer, Allow, Block, Direction, In, Local, Out, Verdict (+13 more)

### Community 169 - "check"
Cohesion: 0.23
Nodes (12): UpdateChannel, Dev, Release, check(), check_url(), Checked, Latest, Newer (+4 more)

### Community 170 - "Found"
Cohesion: 0.25
Nodes (9): a_changed_hash_is_not_approved(), Found, inspect(), scan_dir(), Source, Bundled, File, trusted() (+1 more)

### Community 171 - "countries.rs"
Cohesion: 0.27
Nodes (6): by_a2(), Entry, table!, parse_a2(), parse_name_or_a2(), search()

### Community 172 - "IconCache"
Cohesion: 0.24
Nodes (4): IconCache, IconState, Done, Loading

### Community 173 - "AsyncMemo"
Cohesion: 0.31
Nodes (5): async_memo_answers_none_until_the_read_lands_then_keeps_it(), AsyncMemo, Memo, Memo<K, V>, memo_recomputes_on_key_change_or_expiry()

### Community 174 - "UpdateView"
Cohesion: 0.25
Nodes (9): UpdateView, Available, CheckFailed, Checking, InstallFailed, Installing, Latest, Note (+1 more)

### Community 175 - "AlertLevel"
Cohesion: 0.33
Nodes (4): AlertLevel, .ALL, Important, Logs

### Community 176 - "accent.rs"
Cohesion: 0.36
Nodes (3): dword(), windows_accent(), windows_dark()

### Community 177 - "FirewallInfo"
Cohesion: 0.25
Nodes (6): EngineState, Ready, Unavailable, WindowsFirewallOff, FirewallInfo, banner_text()

### Community 178 - "audit.rs"
Cohesion: 0.18
Nodes (10): auditpol(), blocked_since(), data(), failure_audit_on(), parse_events(), reads_outbound_drops_only(), set_failure_audit(), SUBCATEGORY (+2 more)

### Community 179 - "AlertCheck"
Cohesion: 0.29
Nodes (6): AppGroup, Active, .ALL, Inactive, Uninstalled, Windows

### Community 180 - "SpeedRoute"
Cohesion: 0.25
Nodes (4): Slot, SpeedRoute, SpeedUi, STATES

### Community 181 - "Threat"
Cohesion: 0.29
Nodes (3): only_the_made_up_threat_is_a_test(), Threat, .TEST_IP

### Community 182 - "Security Policy"
Cohesion: 0.29
Nodes (6): Design notes, Reporting a vulnerability, Scope, Security Policy, Supported versions, What to expect

### Community 183 - "upnp/src/lib.rs"
Cohesion: 0.08
Nodes (44): clean(), click(), CONFLICT, control_of(), DESC, envelope(), find_router(), finds_the_internet_service_and_makes_its_address_absolute() (+36 more)

### Community 184 - "download_sha"
Cohesion: 0.38
Nodes (7): download_sha(), expect_ok(), get(), install(), parse_sha(), signed_version(), verify()

### Community 185 - "path"
Cohesion: 0.47
Nodes (4): a_full_log_moves_aside_and_restarts(), append(), line(), MAX

### Community 186 - "ExtrasAct"
Cohesion: 0.29
Nodes (4): ExtrasAct, Pause, Resume, Unblock

### Community 187 - "AccountChange"
Cohesion: 0.29
Nodes (7): account_and_task_changes(), AccountChange, Activated, Created, Deactivated, Deleted, diff_accounts()

### Community 188 - "RuleSpec"
Cohesion: 0.18
Nodes (11): a_service_rule_is_a_separate_row_with_its_own_name(), block_spec(), block_specs_are_scoped_to_one_program_and_direction(), icmp_specs(), lan_block_is_its_own_outbound_rule(), lan_specs(), ping_rules_are_ours_allow_icmp_and_stay_off_the_program_list(), rule_name() (+3 more)

### Community 189 - "AGENTS.md"
Cohesion: 0.33
Nodes (5): File updates, graphify, Project rules, Version control, Versioning

### Community 191 - "build.rs"
Cohesion: 0.28
Nodes (7): BG, bundle_plugins(), graph_pixels(), H, main(), PALETTE, PLUGINS

### Community 192 - "NetInfoSource"
Cohesion: 0.33
Nodes (5): NetInfoSource, .ALL, Http, Off, TeamCymru

### Community 193 - "PlanDirection"
Cohesion: 0.25
Nodes (6): DataPlan, PlanDirection, .ALL, In, Out, Total

### Community 195 - "Manual checks on a real machine"
Cohesion: 0.33
Nodes (5): Automated, Elevated (use "Restart as administrator"), Manual checks on a real machine, Testing RustWarden, Unelevated (a normal user)

### Community 196 - "Dim"
Cohesion: 0.40
Nodes (4): Dim, App, Proto, Remote

### Community 197 - "with"
Cohesion: 0.50
Nodes (4): Pick, run(), start(), with()

### Community 198 - "ApiAsset"
Cohesion: 0.40
Nodes (3): Api, ApiAsset, find_asset()

### Community 202 - "plan-release.sh"
Cohesion: 0.83
Nodes (3): section(), plan-release.sh script, skip()

### Community 210 - "plugin-sdk"
Cohesion: 0.11
Nodes (18): example-hello, plugin-cloudflare, plugin-discord, plugin-gotify, plugin-ha, plugin-ntfy, plugin-opnsense, plugin-ping (+10 more)

### Community 215 - "DeviceEvent"
Cohesion: 0.40
Nodes (5): DeviceEvent, MacChanged, MultiIp, New, Returned

## Knowledge Gaps
- **465 isolated node(s):** `rustwarden`, `System`, `Notification`, `Label`, `Heading` (+460 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1794 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **21 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Db` connect `Db` to `UsageEntry`, `toast.rs`, `LiveBackend`, `QuotaStatus`, `notes.rs`, `baseline.rs`, `export.rs`, `live/apps.rs`, `FwController`, `vt.rs`, `Vt`, `HardwareSample`, `db.rs`, `report.rs`, `dest.rs`, `lease.rs`, `live/qos.rs`, `monitors.rs`, `Shared`, `tab`, `latency.rs`, `ui_tree.rs`, `quota.rs`, `domains.rs`, `Monitors`, `live/traffic.rs`, `live/dns.rs`, `.tick`, `store.rs`, `pcap.rs`, `AppRecord`, `.memory`?**
  _High betweenness centrality (0.064) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Db` (e.g. with `.target_ranges()` and `.views()`) actually correct?**
  _`Db` has 11 INFERRED edges - model-reasoned connections that need verification._
- **What connects `rustwarden`, `System`, `Notification` to the rest of the system?**
  _465 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `live/firewall.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.04035542391706775 - nodes in this community are weakly interconnected._
- **Why does `Settings` connect `Settings` to `LiveBackend`, `legacy.rs`, `toast.rs`, `MockBackend`, `pathbuf`, `QuotaStatus`, `dialogs.rs`, `webview.rs`, `baseline.rs`, `settings.rs`, `Backend`, `manager.rs`, `RustWarden`, `demo.rs`, `alerts.rs`, `AlertKind`, `RustWarden`, `report.rs`, `Found`, `check`, `asn.rs`, `NetInfoSource`, `PlanDirection`, `data.rs`, `Shared`, `Outcome`, `protect.rs`, `Dialog`, `wizard.rs`, `store.rs`, `pos2`, `AppRecord`, `alertrules.rs`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Are the 26 inferred relationships involving `RustWarden` (e.g. with `Alert` and `AlertCheck`) actually correct?**
  _`RustWarden` has 26 INFERRED edges - model-reasoned connections that need verification._
- **Should `LiveBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.038623823433950016 - nodes in this community are weakly interconnected._