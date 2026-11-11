# Graph Report - RustWarden  (2026-11-11)

## Corpus Check
- 230 files · ~318,184 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 2, .ico 1, .tsv 1)

## Summary
- 6045 nodes · 12897 edges · 254 communities (229 shown, 25 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 796 edges (avg confidence: 0.61)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `9754b10a`
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
- tlsprint.rs
- .load
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
- modal.rs
- sys/mod.rs
- icmp.rs
- sys/firewall.rs
- data.rs
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
- sniff.rs
- steps
- Scale
- beacon.rs
- store.rs
- tab
- proc.rs
- ha/src/lib.rs
- speed.rs
- notes.rs
- opnsense/src/lib.rs
- loader.rs
- watch.rs
- map.rs
- picker.rs
- Windows system changes
- live/geo.rs
- ConfirmAction
- quota.rs
- arc
- services.rs
- alert_rules.rs
- ping/src/lib.rs
- Monitors
- arc
- live/traffic.rs
- RuleSpec
- Collector
- netpkt.rs
- alertrules.rs
- Priority
- hashset
- store.rs
- live/dns.rs
- Glyph
- Dialog
- FirewallMode
- .tick
- capture.rs
- tray.rs
- Theme
- RangeSet
- dnstunnel.rs
- quiet
- windows_extras.rs
- guest.rs
- report.rs
- TcpState
- Query
- DestRule
- Alert
- feed
- filedialog.rs
- shots.rs
- UiTree
- err
- host.rs
- ask.rs
- migrate.rs
- plugins.rs
- Creating a RustWarden plugin
- upnp.rs
- wallpaper.rs
- docs.yml
- pathbuf
- QuotaLevel
- netparse.rs
- UiTree
- Direction
- Job
- connections.rs
- audit.rs
- NetEvent
- PlanPeriod
- legacy.rs
- AppRecord
- export.rs
- util.rs
- hashset
- pcwstr
- Geo
- DeviceKind
- hashmap
- vt.rs
- Report
- NetInfoSource
- tcp_row
- HostCall
- Rule
- steps
- Writing a RustWarden plugin
- AsyncMemo
- Priority
- db.rs
- QuotaAction
- RustWarden
- listeners
- VirusTotal
- Dim
- src/geo.rs
- countries.rs
- bundled.rs
- Place
- shodan/src/lib.rs
- AlertLevel
- Found
- pcap.rs
- v1.21.3.md
- accent.rs
- StatusNote
- .hardware_tab
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
- Answer
- remove_all_owned
- .start
- The Firewall tab
- ThreatAct
- Urgency
- plan-release.sh
- Settings reference
- Held
- Traffic
- main.rs
- path
- flag_data.rs
- plugin-sdk
- AccountChange
- theme_button_cycles_system_light_dark
- TimeRange
- 1.23.3: a quieter, smarter behaviour baseline
- Driver mode
- Built-in plugins
- Installing and first run
- tcp6_row
- Updates, backup and upkeep
- Deserialize
- Speedtest
- AppMode
- Network Scanner
- Subscription
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
- profile_state
- Live Connections
- DNS Log
- Behaviour baseline
- RustWarden user guide
- SpeedPhase
- Hardware
- v1.20.0.md

## God Nodes (most connected - your core abstractions)
1. `Ui` - 152 edges
2. `Db` - 139 edges
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
- `Host` --references--> `Call`  [INFERRED]
  src/plugins/wasm/host.rs → plugin-sdk/src/lib.rs
- `calendar()` --references--> `Ui`  [INFERRED]
  src/plugins/core/latency.rs → plugin-sdk/src/lib.rs
- `camera()` --references--> `Ui`  [INFERRED]
  src/plugins/core/latency.rs → plugin-sdk/src/lib.rs

## Import Cycles
- 1-file cycle: `src/ui/dialogs.rs -> src/ui/dialogs.rs`
- 1-file cycle: `src/ui/map.rs -> src/ui/map.rs`
- 1-file cycle: `src/ui/mod.rs -> src/ui/mod.rs`
- 1-file cycle: `src/data.rs -> src/data.rs`
- 2-file cycle: `src/plugins/wasm/manager.rs -> src/plugins/wasm/ui_tree.rs -> src/plugins/wasm/manager.rs`

## Communities (254 total, 25 thin omitted)

### Community 0 - "live/firewall.rs"
Cohesion: 0.04
Nodes (63): ACTIVE_PROFILE_KEY, adopt_legacy_rules(), allow_engine_traffic(), ASK_KEY, ask_marker_exists(), ask_marker_path(), audit_prev_path(), block_all_exceptions() (+55 more)

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
Cohesion: 0.11
Nodes (30): a_failed_list_keeps_only_its_own_last_good_entries(), act(), add_name(), ALLOW_KEY, cache_keeps_list_names(), cache_path(), download(), feeds_keep_only_public_addresses() (+22 more)

### Community 5 - "MockBackend"
Cohesion: 0.05
Nodes (6): demo_bandwidth_limits_can_be_added_changed_and_cleared(), demo_destination_rules_add_replace_remove_and_reset(), demo_networks_keep_separate_devices_and_threat_lists(), demo_snooze_net_info_and_virustotal_work(), demo_traffic_filter_narrows_the_sample_data(), MockBackend

### Community 6 - "widgets.rs"
Cohesion: 0.08
Nodes (46): snap(), fit_text(), area(), area_faded(), area_faded_to(), area_impl(), area_soft_to(), brand_menu_row() (+38 more)

### Community 7 - "thinkbroadband/src/lib.rs"
Cohesion: 0.08
Nodes (53): ALERT_MAX_AGE_SECS, alert_pct(), attr(), backfill(), BASE, chart(), CHART_SQL, civil_from_days() (+45 more)

### Community 8 - "cloudflare/src/lib.rs"
Cohesion: 0.10
Nodes (34): args_for(), begin(), cfg(), demo_step(), each_step_runs_the_right_command(), event(), EXE, finished() (+26 more)

### Community 9 - "engine.rs"
Cohesion: 0.08
Nodes (33): a_limit_only_paces_the_directions_it_names(), die(), DROP_LIMIT, DROP_WINDOW_MS, Engine, filter_loop(), filter_needs_swap(), flow_loop() (+25 more)

### Community 10 - "dialogs.rs"
Cohesion: 0.05
Nodes (78): Ui, ThreatLists, P2pApp, QuotaStatus, cell(), Settings, ABOUT_CLICKS, ABOUT_PNG (+70 more)

### Community 11 - "webview.rs"
Cohesion: 0.08
Nodes (22): CHECK, CHECK_SECS, Ev, GiveUp, Loaded, Msg, fetch(), GIVE_UP_SECS (+14 more)

### Community 12 - "baseline.rs"
Cohesion: 0.05
Nodes (25): active_days_by_hour(), ASN_WAIT_SCANS, BUSY_HOUR, DAY, DIM_ASN, DIM_COUNTRY, DIM_DOMAIN, DIM_HOUR (+17 more)

### Community 13 - "settings.rs"
Cohesion: 0.06
Nodes (30): a_secret_sealed_for_someone_else_is_not_imported(), alert_rules_are_sanitized_and_survive_a_save(), AlertSwitches, app_mode_defaults_to_normal_and_round_trips(), baseline_settings_are_clamped(), deserialize(), DNS_FEED_DEFAULT, DNS_FEED_RETIRED (+22 more)

### Community 14 - "update.rs"
Cohesion: 0.05
Nodes (43): UpdateView, Available, CheckFailed, Checking, InstallFailed, Installing, Latest, UpdateChannel (+35 more)

### Community 15 - "guard.rs"
Cohesion: 0.11
Nodes (32): fingerprint(), GUARD_PREFIX, adapter(), ARMED_KEY, DOH_ADDRS, DOH_PREFIX, doh_specs(), ENDPOINTS_KEY (+24 more)

### Community 16 - "Backend"
Cohesion: 0.04
Nodes (11): Backend, UsageBreakdown, Load, Loader, merge_adds_parts_and_takes_the_newer_values(), Query, query(), run() (+3 more)

### Community 17 - "manager.rs"
Cohesion: 0.07
Nodes (46): Active, annotates(), annotator(), annotator_ids(), any_notification_plugin(), broadcast_alert(), deliver_alert(), granted_settings() (+38 more)

### Community 18 - "tlsprint.rs"
Cohesion: 0.10
Nodes (27): copy_path(), digest(), hash(), hex(), recall(), remember(), ROUNDS, salt() (+19 more)

### Community 19 - ".load"
Cohesion: 0.15
Nodes (10): config_dir(), config_path(), env_dir(), Mode, Demo, Live, plugin_decisions_survive_the_admin_copy_and_junk_reads_as_none(), plugins_copy_path() (+2 more)

### Community 20 - "live/apps.rs"
Cohesion: 0.09
Nodes (20): core_services_are_refused_and_other_services_are_not(), CRITICAL_SERVICES, describe_change(), ensure_record(), ensure_service_record(), file_name(), icon_for(), is_svchost() (+12 more)

### Community 21 - "speedtest/src/lib.rs"
Cohesion: 0.08
Nodes (36): SpeedLive, demo_history(), demo_live(), demo_readings_ramp_up_through_the_three_phases(), demo_result(), DEMO_STEP_MS, DEMO_TEST_SECS, event() (+28 more)

### Community 22 - "live/scanner.rs"
Cohesion: 0.08
Nodes (29): progress(), arp_probe(), Found, MAX_PREFIX_HOSTS, nbstat(), nbstat_request(), networks(), oui_map() (+21 more)

### Community 23 - "Db"
Cohesion: 0.06
Nodes (7): row(), app_records_and_missing_state(), Db, .APP_COLS, DeviceRow, devices_keep_user_names_and_go_offline(), dns_log_round_trips_and_prunes()

### Community 24 - "demo.rs"
Cohesion: 0.07
Nodes (27): HardwareSnapshot, demo_apps(), demo_block_all_shows_active(), demo_connections(), demo_connections_have_sample_rows(), demo_dest_rules(), demo_devices(), demo_dns() (+19 more)

### Community 25 - "FwController"
Cohesion: 0.13
Nodes (10): extras_paused(), extras_rules(), FwController, is_aux(), paused_extras(), profile_since(), removed_apps(), run() (+2 more)

### Community 26 - "Bg"
Cohesion: 0.24
Nodes (6): async_memo_answers_none_until_the_read_lands_then_keeps_it(), AsyncMemo<K, V>, Bg, bg_runs_the_latest_waiting_request_and_reports_a_panic_once(), Bg<T>, wait()

### Community 27 - "popup.rs"
Cohesion: 0.10
Nodes (22): ALERT_INFO_TITLE, ALERT_TITLE, ALERTS_SECTION, ask_buttons(), ASK_INFO_TITLE, ask_size(), ASK_TITLE, ASK_W (+14 more)

### Community 28 - "Icon"
Cohesion: 0.05
Nodes (40): Icon, Alerts, ArrowDown, ArrowUp, Bell, Bulb, Camera, Check (+32 more)

### Community 29 - "src/notify.rs"
Cohesion: 0.05
Nodes (48): simplify(), Discord, .FIELDS, .HOSTS, .ID, .NAME, DISCORD_URLS, Field (+40 more)

### Community 31 - "alerts.rs"
Cohesion: 0.09
Nodes (26): a_reused_dhcp_address_is_not_spoofing(), anomaly_kinds_have_keys_and_switches(), arp_mac_change_is_reported_once(), ArpChange, device_events(), device_events_find_new_changed_multi_and_returned(), device_use_reports_new_and_later_uses(), DeviceEvent (+18 more)

### Community 32 - "AlertKind"
Cohesion: 0.05
Nodes (40): AlertKind, .ALL, AnomalyContact, AnomalyHour, AnomalyVolume, AppChanged, Arp, Away (+32 more)

### Community 33 - "autostart.rs"
Cohesion: 0.05
Nodes (51): answer_stop(), CHILD, claim_instance(), DISPLAY, downloads_exe(), end_other_instances(), end_processes(), ensure_recovery() (+43 more)

### Community 34 - "modal.rs"
Cohesion: 0.09
Nodes (3): find(), find_all(), MAIN

### Community 35 - "sys/mod.rs"
Cohesion: 0.06
Nodes (25): W, Writer, file_icon_rgba(), has_valid_embedded_signature(), EVENT_ID, write(), service_has_sid(), from_wide() (+17 more)

### Community 36 - "icmp.rs"
Cohesion: 0.10
Nodes (9): AT_ONCE, echo(), echoes(), MAX_ADDRS, ping_v4(), ping_v6(), Round, round() (+1 more)

### Community 37 - "sys/firewall.rs"
Cohesion: 0.06
Nodes (5): PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC, PROFILES, PROTO_ANY

### Community 38 - "data.rs"
Cohesion: 0.03
Nodes (49): ActiveCountries, AlertCheck, AlertDest, .ALL, Any, Local, Remote, AlertFilter (+41 more)

### Community 39 - "wfp.rs"
Cohesion: 0.09
Nodes (7): app_name(), decode(), dos_path(), is_icmp(), on_event(), RPC_C_AUTHN_DEFAULT, swap_device()

### Community 40 - "QosLimit"
Cohesion: 0.08
Nodes (16): decode_all(), directions_round_trip_and_old_lines_still_read(), encode_all(), fmt_rate(), limit(), MAX_DELAY_MS, MAX_KBPS, MAX_LIMITS (+8 more)

### Community 41 - "abuseipdb/src/lib.rs"
Cohesion: 0.16
Nodes (18): AbuseIpDb, DEFAULT_ALERT_SCORE, demo_verdict(), FRESH_SECS, is_public(), KEEP, key_ok(), lookup() (+10 more)

### Community 42 - "Context"
Cohesion: 0.07
Nodes (16): Confirm, Settings, Context, about_click_hits(), firewall_toggle_confirm(), Apply, Confirmed, Rename (+8 more)

### Community 43 - "driver.rs"
Cohesion: 0.09
Nodes (27): BLOCKED_HELP, dir(), DLL, DriverState, Blocked, Missing, Ready, folder_state_tells_missing_ready_and_blocked_apart() (+19 more)

### Community 44 - "netinfo.rs"
Cohesion: 0.08
Nodes (12): adapters(), adapters_and_neighbors_are_readable(), host_routes(), idle_seconds(), is_tunnel(), is_virtual(), Neighbor, neighbors() (+4 more)

### Community 45 - "etw.rs"
Cohesion: 0.07
Nodes (24): cached_path(), decode(), dns_answer_maps_name_to_addresses(), DNS_CLIENT, dns_payload(), DROPPED, failed_lookup_is_logged_without_addresses(), forget_dead() (+16 more)

### Community 46 - "ui/traffic.rs"
Cohesion: 0.10
Nodes (13): labelled(), RustWarden, blur_averages_and_keeps_length(), box_blur(), row_in(), tick_step(), command_card(), command_card_id() (+5 more)

### Community 47 - "dest.rs"
Cohesion: 0.13
Nodes (15): MAX_RULES_PER_DEST, Dest, DNS_WINDOW, firewall_rules_belong_to_their_destination_rule(), id_of(), load(), name_changes_with_the_address_list_program_and_mode_only(), rule() (+7 more)

### Community 48 - "windivert.rs"
Cohesion: 0.06
Nodes (24): Address, ChecksumFn, CloseFn, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED, FLAG_DROP, FLAG_RECV_ONLY, FLAG_SNIFF (+16 more)

### Community 49 - "conns.rs"
Cohesion: 0.07
Nodes (3): ENABLED, STATE_ESTABLISHED, STATE_SYN_SENT

### Community 50 - "rules_file.rs"
Cohesion: 0.15
Nodes (14): a_file_survives_writing_and_reading(), AppRule, current_of(), destination_rules_are_added_once_and_get_fresh_ids(), DIRECTIONS, file(), FORMAT, matching_state_plans_nothing() (+6 more)

### Community 51 - "helper.rs"
Cohesion: 0.06
Nodes (38): globbing_is_off(), PROTO, refuses_other_protocols(), run(), add_exclusion(), remove_exclusion(), a_program_that_isnt_downloaded_is_refused_before_anything_runs(), a_programs_folders_are_copied_with_their_files() (+30 more)

### Community 52 - "RustWarden features"
Cohesion: 0.12
Nodes (17): 🚨 Alerts and log analysis, 🧭 Behaviour baseline, Clean up, 📏 Data quotas, 🔎 DNS Log, ⚙️ Everything else, 🛡️ Firewall: your firewall, simplified, 📈 Hardware resources (+9 more)

### Community 53 - "lease.rs"
Cohesion: 0.14
Nodes (21): before_spawn(), check_again_at(), decode(), due(), encode(), end(), end_all(), GROUP (+13 more)

### Community 54 - "icons.rs"
Cohesion: 0.11
Nodes (27): AppIcon, Bitwarden, Chrome, Claude, ClaudeCode, Drive, Gear, Generic (+19 more)

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
Nodes (43): Guest, API_VERSION, Call, Alert, Event, HelperDone, HelperLine, Manifest (+35 more)

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
Cohesion: 0.04
Nodes (41): BLOCK_AFTER_MINS, ConnsState, default_window(), DestDraft, DnsState, DomainDraft, every_tab_has_its_own_key_that_reads_back(), fit_window() (+33 more)

### Community 66 - "monitors.rs"
Cohesion: 0.10
Nodes (22): adapter_ignored(), Debounce, diff_files(), diff_tasks(), per_user_base(), plan_level(), PlanLevel, Over (+14 more)

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
Cohesion: 0.16
Nodes (8): Scale, .ALL, S1, S30, S600, inspect_db(), inspect_detail(), UsageEntry

### Community 72 - "beacon.rs"
Cohesion: 0.09
Nodes (23): a_browser_is_not_exempt(), a_cdn_suffix_lowers_the_level_without_hiding_it(), an_unsigned_program_with_tiny_uniform_payloads_to_a_rare_host_is_reported(), BULK_PER_MIN, chrome_polling_a_live_video_cdn_is_not_reported(), ctx(), DEFAULT_CDN, FORGET_AFTER (+15 more)

### Community 73 - "store.rs"
Cohesion: 0.14
Nodes (9): a_mute_rule_records_the_alert_but_shows_nothing(), a_quiet_alert_is_logged_read_without_a_popup_even_when_escalated(), an_escalate_rule_makes_an_alert_important_with_a_popup(), blocked_addresses(), install_alert_sink(), lock(), raise_plugin_alert(), Shared (+1 more)

### Community 74 - "tab"
Cohesion: 0.07
Nodes (29): BLUE, calendar(), camera(), column_count(), columns(), columns_keep_the_extremes_and_average_the_rest(), day_shift(), export() (+21 more)

### Community 75 - "proc.rs"
Cohesion: 0.05
Nodes (26): a_long_script_runs_from_the_environment_and_a_long_command_line_falls_back(), Child, command_line(), dir_ptr_or(), environment(), environment_changes_are_applied_and_nothing_means_inherit(), inheritable(), MAX_LINE (+18 more)

### Community 76 - "ha/src/lib.rs"
Cohesion: 0.11
Nodes (26): event(), explain(), Ha, headers(), known(), LOGO, lookup(), next_due() (+18 more)

### Community 77 - "speed.rs"
Cohesion: 0.10
Nodes (29): SpeedPage, query_speed(), arc_mesh(), card_frame(), chart(), dial_frac(), DIAL_START, DIAL_SWEEP (+21 more)

### Community 78 - "notes.rs"
Cohesion: 0.18
Nodes (10): Device, DeviceNote, Annotator, device_kind(), device_url(), display_name(), flag(), ICON (+2 more)

### Community 79 - "opnsense/src/lib.rs"
Cohesion: 0.06
Nodes (54): flag(), a_leftover_alias_is_reported(), a_read_check_keeps_the_earlier_write_result(), a_read_only_key_cannot_push(), a_read_only_key_is_told_apart(), a_writable_key_creates_then_removes_the_test_alias(), Added, Denied (+46 more)

### Community 80 - "loader.rs"
Cohesion: 0.11
Nodes (19): a_wrong_api_version_is_refused(), an_infinite_loop_is_stopped_by_the_fuel_limit(), call_tick(), engine(), FUEL, hash_of(), host_calls_are_checked_by_the_host(), host_import() (+11 more)

### Community 81 - "watch.rs"
Cohesion: 0.14
Nodes (9): device_use(), open(), root_certs(), RUN_KEYS, service_names(), snapshots_read_the_registry(), startup_entries(), subkeys() (+1 more)

### Community 82 - "map.rs"
Cohesion: 0.24
Nodes (13): ARC, blocked_color(), clamp_center(), home_dot(), land(), land_active(), land_edge(), land_hover() (+5 more)

### Community 83 - "picker.rs"
Cohesion: 0.11
Nodes (11): app_in(), each_window(), is_frame_host(), Pick, proc(), run(), Search, start() (+3 more)

### Community 84 - "Windows system changes"
Cohesion: 0.05
Nodes (42): Alert types, Application info monitor, ARP spoofing detection, Beaconing detection, Behaviour baseline, Behaviour: new country, network or domain, Behaviour: traffic spike, Behaviour: unusual hour (+34 more)

### Community 85 - "live/geo.rs"
Cohesion: 0.18
Nodes (11): asn_db_path(), city_db_path(), DATABASES, db_path(), DbInfo, default_db_path(), download_dbip(), download_script() (+3 more)

### Community 86 - "ConfirmAction"
Cohesion: 0.06
Nodes (31): ConfirmAction, ApplyRules, BlockProgram, BlockWindowsExtras, CleanUp, ClearHistory, DeleteProfile, FirewallEnabled (+23 more)

### Community 87 - "quota.rs"
Cohesion: 0.23
Nodes (17): action_none_only_warns(), block_is_asked_for_until_it_happens(), clock_moved_back_starts_a_fresh_period(), Decision, deleted_disabled_or_retargeted_quotas_orphan_their_track(), jumping_straight_over_alerts_once(), KV_KEY, level() (+9 more)

### Community 88 - "arc"
Cohesion: 0.15
Nodes (13): a_slow_client_cannot_hold_the_endpoint(), bind_retrying(), Endpoint, exchange(), handle(), label(), LOG, metrics_answers_loopback_requests() (+5 more)

### Community 89 - "services.rs"
Cohesion: 0.15
Nodes (8): by_pid(), label(), lists_running_services(), one_service_is_named_with_its_short_name(), SC_MANAGER_ENUMERATE_SERVICE, Service, shared_hosts_are_keyed_in_a_stable_order(), svc()

### Community 90 - "alert_rules.rs"
Cohesion: 0.13
Nodes (12): ALL_DAYS, DAY_NAMES, parse_minute(), RuleAction, .ALL, Escalate, KeepLocal, Limit (+4 more)

### Community 91 - "ping/src/lib.rs"
Cohesion: 0.09
Nodes (20): Event, Bool, ChartMissing, Click, File, Index, Number, TabOpened (+12 more)

### Community 93 - "arc"
Cohesion: 0.08
Nodes (26): PROMPT_FOR, prompt_for_label(), GAP, monitor_at(), Out, PAD, RustWarden, Shared (+18 more)

### Community 94 - "live/traffic.rs"
Cohesion: 0.17
Nodes (20): KIND_LAN, KIND_UNKNOWN, KIND_WAN, a_tls_server_name_names_its_own_programs_traffic(), Aggregator, aggregator_sums_by_key(), ev(), Flow (+12 more)

### Community 95 - "RuleSpec"
Cohesion: 0.15
Nodes (14): a_service_rule_is_a_separate_row_with_its_own_name(), allow_rules_are_ours_outbound_and_distinct_from_block_rules(), allow_spec(), block_spec(), block_specs_are_scoped_to_one_program_and_direction(), icmp_specs(), lan_block_is_its_own_outbound_rule(), lan_specs() (+6 more)

### Community 96 - "Collector"
Cohesion: 0.18
Nodes (4): kernel_service(), Collector, publish_geo_note(), run()

### Community 97 - "netpkt.rs"
Cohesion: 0.14
Nodes (16): pkt(), limited_ports(), addresses_can_be_swapped_in_ipv4_only(), FlowKey, ipv4_tcp(), parse(), Parsed, reads_ipv4_tcp_and_both_directions_share_one_flow() (+8 more)

### Community 98 - "alertrules.rs"
Cohesion: 0.19
Nodes (14): AlertInfo, AlertRule, conditions_all_have_to_hold(), contains_nocase(), decide(), Effect, first_enabled_match_wins(), in_window() (+6 more)

### Community 99 - "Priority"
Cohesion: 0.12
Nodes (10): LimitDir, .ALL, Both, Down, Up, Priority, .ALL, High (+2 more)

### Community 100 - "hashset"
Cohesion: 0.11
Nodes (9): a_domain_covers_everything_below_it_but_not_lookalikes(), decode_all(), DomainRule, DomainView, encode_all(), MAX_LIST, MAX_RULES, normalize() (+1 more)

### Community 101 - "store.rs"
Cohesion: 0.17
Nodes (9): ConnectAsk, ScanState, ALERT_SINK, country_of(), FwSnapshot, HwNow, NetworkInfo, State (+1 more)

### Community 102 - "live/dns.rs"
Cohesion: 0.09
Nodes (20): DnsEntry, a_failed_feed_keeps_only_its_own_names(), cache_path(), check(), clean(), domain_of(), download(), each_program_and_name_is_reported_once() (+12 more)

### Community 103 - "Glyph"
Cohesion: 0.15
Nodes (14): DetailRow, Glyph, App, Flag, More, Window, UsageDetail, UsageKind (+6 more)

### Community 104 - "Dialog"
Cohesion: 0.12
Nodes (16): Dialog, About, Confirm, Info, InstallService, NewProfile, Password, Rename (+8 more)

### Community 105 - "FirewallMode"
Cohesion: 0.10
Nodes (21): FirewallInfo, FirewallMode, .ALL, AskToConnect, BlockAll, ClickToBlock, mode_confirm(), banner_text() (+13 more)

### Community 106 - ".tick"
Cohesion: 0.18
Nodes (10): orphaned(), run(), Track, tracks_from_text(), tracks_round_trip_through_text(), tracks_to_text(), used_by(), user_blocked() (+2 more)

### Community 108 - "capture.rs"
Cohesion: 0.17
Nodes (3): Capture, Session, CaptureStatus

### Community 109 - "tray.rs"
Cohesion: 0.19
Nodes (5): icon(), Tray, TrayCmd, Menu, Toggle

### Community 110 - "Theme"
Cohesion: 0.05
Nodes (22): png(), texture(), scene(), triangle(), Theme, Dark, Light, ROW_H (+14 more)

### Community 111 - "RangeSet"
Cohesion: 0.11
Nodes (18): block_mode_never_touches_the_local_network(), blocked_set(), complement_covers_everything_else(), ip(), local_ranges(), long_lists_are_split_into_rules_within_the_limits(), MAX_CHARS_PER_RULE, MAX_RANGES_PER_RULE (+10 more)

### Community 112 - "dnstunnel.rs"
Cohesion: 0.13
Nodes (14): entropy(), LONG, many_random_names_under_one_domain_are_a_tunnel(), MAX_DOMAINS, MIN_NAMES, odd(), QUIET_AFTER_REPORT, RANDOM_BITS (+6 more)

### Community 113 - "quiet"
Cohesion: 0.17
Nodes (20): adopt_legacy_entries(), authorize_stop(), desktop_lnk(), ensure_service_running(), install_service(), lnk_in(), ok(), prepare_debug() (+12 more)

### Community 114 - "windows_extras.rs"
Cohesion: 0.21
Nodes (9): expand(), Group, GROUPS, is_protected(), matches(), PROTECTED, resolve(), t() (+1 more)

### Community 115 - "guest.rs"
Cohesion: 0.12
Nodes (40): __alloc(), blocked_addresses(), browser_fetch(), browser_sign_in(), browser_sign_out(), __call(), config_get(), config_set() (+32 more)

### Community 116 - "report.rs"
Cohesion: 0.17
Nodes (17): a_report_is_due_once_per_slot(), build(), build_finds_new_hosts_only_with_older_history(), due(), KV_LAST, last_slot(), LISTED, MAX_CHARS (+9 more)

### Community 117 - "TcpState"
Cohesion: 0.13
Nodes (14): state_raw(), TcpState, Closed, CloseWait, Closing, DeleteTcb, Established, FinWait1 (+6 more)

### Community 118 - "Query"
Cohesion: 0.28
Nodes (7): expand(), GpuQuery, Handle, Pdh, ProcQuery, Query, Sample

### Community 119 - "DestRule"
Cohesion: 0.12
Nodes (8): demo_dest_status(), decode_all(), DestRule, DestRuleView, encode_all(), Mode, Block, OnlyAllow

### Community 120 - "Alert"
Cohesion: 0.04
Nodes (35): Alert, AppGroup, Active, .ALL, Inactive, Uninstalled, Windows, Country (+27 more)

### Community 121 - "feed"
Cohesion: 0.24
Nodes (9): a_steady_timer_is_reported_once(), Beat, cfg(), Config, feed(), ip(), regular(), Series (+1 more)

### Community 122 - "filedialog.rs"
Cohesion: 0.13
Nodes (5): filter_list(), filter_list_is_double_null_terminated_with_all_files_last(), MAX_TEXT_BYTES, open(), open_async()

### Community 123 - "shots.rs"
Cohesion: 0.17
Nodes (8): SCREENS, SETTLE, Setup, Shots, Window, Ask, Main, Threat

### Community 124 - "UiTree"
Cohesion: 0.08
Nodes (25): UiTree, Button, Card, Column, Copy, Disabled, Dropdown, FileButton (+17 more)

### Community 125 - "err"
Cohesion: 0.24
Nodes (13): add_rule(), adopt_rule(), bool_variant(), default_outbound_blocked(), enable_windows_firewall(), err(), interfaces_variant(), policy() (+5 more)

### Community 126 - "host.rs"
Cohesion: 0.07
Nodes (27): HostReply, Err, Ok, a_keypair_is_32_bytes_each_and_the_public_key_follows_from_the_private(), a_pinned_ca_is_checked_and_its_file_removed(), a_pinned_ca_skips_the_revocation_lookup_a_private_ca_cannot_answer(), a_plugin_cannot_keep_a_transaction_open_or_run_for_ever(), a_value_cannot_break_out_of_the_curl_config() (+19 more)

### Community 127 - "ask.rs"
Cohesion: 0.19
Nodes (12): count(), fw_closed_since(), IN_FLIGHT, is_noise(), lookups_on(), MAX_IN_FLIGHT, MAX_OPEN_ASKS, note_engine_drop() (+4 more)

### Community 128 - "migrate.rs"
Cohesion: 0.25
Nodes (13): DONE, merge_dir(), merge_keeps_what_the_new_folder_has(), move_program_files(), move_user_data(), OLD, rename_in_db(), run() (+5 more)

### Community 129 - "plugins.rs"
Cohesion: 0.16
Nodes (16): beta_hidden(), card(), CREATE_URL, files(), listed(), Modal, modal(), Approve (+8 more)

### Community 130 - "Creating a RustWarden plugin"
Cohesion: 0.13
Nodes (15): 1. Set up, 2. Create the crate, 3. Write the plugin, 4. Keep state, 5. Talk to the network (optional), 6. Run in the background (optional), 7. Ask for permissions (optional), 8. Build (+7 more)

### Community 131 - "upnp.rs"
Cohesion: 0.22
Nodes (7): discover(), Gateway, lan_addr(), local_networks(), location_of(), private(), SEARCH

### Community 133 - "docs.yml"
Cohesion: 0.14
Nodes (13): concurrency, cancel-in-progress, group, name, on, push, workflow_dispatch, permissions (+5 more)

### Community 134 - "pathbuf"
Cohesion: 0.23
Nodes (9): disable(), disables_the_features_that_use_downloads(), remove(), removes_files_and_folders_and_ignores_missing(), run(), size(), targets(), warning() (+1 more)

### Community 135 - "QuotaLevel"
Cohesion: 0.50
Nodes (4): QuotaLevel, Ok, Over, Warn

### Community 136 - "netparse.rs"
Cohesion: 0.25
Nodes (10): client_hello(), dns(), DnsMessage, finds_the_server_name_and_refuses_junk(), host_ok(), name_at(), query(), reads_queries_and_answers_with_compressed_names() (+2 more)

### Community 137 - "UiTree"
Cohesion: 0.12
Nodes (22): add_form(), chart(), CHART_SQL, clean(), demo_row(), demo_rows_are_sane_and_stable(), DEMO_SPAN, event() (+14 more)

### Community 138 - "Direction"
Cohesion: 0.15
Nodes (17): Direction, In, Local, Out, critical_reason(), service_key(), service_of_key(), Drift (+9 more)

### Community 139 - "Job"
Cohesion: 0.40
Nodes (5): Job, Alert, Call, Event, Stop

### Community 141 - "connections.rs"
Cohesion: 0.08
Nodes (23): LiveConn, Act, Block, Capture, Kill, compare(), conn(), ConnGroup (+15 more)

### Community 142 - "audit.rs"
Cohesion: 0.22
Nodes (9): auditpol(), blocked_since(), data(), failure_audit_on(), parse_events(), reads_outbound_drops_only(), set_failure_audit(), SUBCATEGORY (+1 more)

### Community 143 - "NetEvent"
Cohesion: 0.17
Nodes (11): inject(), NetEvent, Data, Dns, Sni, PATHS, set_spawn_hook(), sink() (+3 more)

### Community 144 - "PlanPeriod"
Cohesion: 0.17
Nodes (11): PeriodKind, Day, Month, Week, period_kind(), period_word(), PlanPeriod, .ALL (+3 more)

### Community 145 - "legacy.rs"
Cohesion: 0.16
Nodes (22): ha_config(), migrate_tables(), NOTIFICATIONS, old_ping_rows_move_into_the_plugin_table_once(), old_speedtest_rows_move_into_the_plugin_table(), old_thinkbroadband_samples_move_into_the_plugin_table(), old_values(), old_values_are_found_trimmed_and_empty_ones_skipped() (+14 more)

### Community 146 - "AppRecord"
Cohesion: 0.11
Nodes (20): domain_of(), hour_why(), learning(), learning_note(), mad(), median(), network_of(), new_item() (+12 more)

### Community 147 - "export.rs"
Cohesion: 0.23
Nodes (9): a_value_that_looks_like_a_formula_is_made_text(), AlertRow, alerts_csv(), csv_keeps_awkward_values_in_one_cell(), json(), json_uses_field_names(), traffic_csv(), traffic_csv_has_one_line_per_row_after_the_header() (+1 more)

### Community 148 - "util.rs"
Cohesion: 0.13
Nodes (10): app_icon_rgba(), BIT_UNITS, BITS, decode_png(), fmt_rate(), fmt_size(), scale(), scale_in() (+2 more)

### Community 149 - "hashset"
Cohesion: 0.18
Nodes (12): a_burst_from_many_sources_is_a_flood(), Detector, Finding, PortScan, SynFlood, FLOOD_PER_SEC, ip(), many_ports_from_one_source_is_a_scan_reported_once() (+4 more)

### Community 150 - "pcwstr"
Cohesion: 0.25
Nodes (4): protect(), round_trips_and_rejects_garbage(), take(), unprotect()

### Community 151 - "Geo"
Cohesion: 0.23
Nodes (4): asn_networks(), country_networks_cover_addresses_the_database_places_there(), Geo, country_of()

### Community 152 - "DeviceKind"
Cohesion: 0.20
Nodes (9): DeviceKind, Generic, Laptop, Raspberry, SmartDevice, WiFi, guess_kind(), kind_from_i64() (+1 more)

### Community 153 - "hashmap"
Cohesion: 0.22
Nodes (5): Counters, delta(), IF_OPER_STATUS_UP, IF_TYPE_SOFTWARE_LOOPBACK, read()

### Community 154 - "vt.rs"
Cohesion: 0.07
Nodes (34): Vt, Analysing, Failed, None, NotFound, OnHold, Pending, Result (+26 more)

### Community 155 - "Report"
Cohesion: 0.25
Nodes (5): new_line(), Report, sample(), text_lists_every_section(), text_says_when_history_is_too_short_and_stays_under_the_limit()

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
Cohesion: 0.29
Nodes (7): enabled_outbound_allows(), enabled_outbound_blocks(), read_rule(), reading_rules_works_without_administrator(), rules_in_group(), rules_named(), rules_where()

### Community 160 - "steps"
Cohesion: 0.12
Nodes (18): runs-on, steps, environment, needs, runs-on, steps, name, url (+10 more)

### Community 161 - "Writing a RustWarden plugin"
Cohesion: 0.22
Nodes (9): Build, Calls into your plugin, Install, Notification services, Pages, Rules your plugin must follow, The code, What you may ask RustWarden for (+1 more)

### Community 162 - "AsyncMemo"
Cohesion: 0.36
Nodes (4): AsyncMemo, Memo, Memo<K, V>, memo_recomputes_on_key_change_or_expiry()

### Community 163 - "Priority"
Cohesion: 0.24
Nodes (6): Line, Plan, At, Drop, Pass, the_line_serves_high_first_and_squeezes_the_rest()

### Community 164 - "db.rs"
Cohesion: 0.10
Nodes (25): add_column(), alert_chain_survives_reads_and_names_the_first_change(), alert_hash(), alerts_round_trip_and_mark_read(), BASE_ALERTED, BASE_LEARNED, BASE_NORMAL, blocked_attempts_add_up_prune_and_clear() (+17 more)

### Community 165 - "QuotaAction"
Cohesion: 0.20
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

### Community 169 - "Dim"
Cohesion: 0.40
Nodes (4): Dim, App, Proto, Remote

### Community 170 - "src/geo.rs"
Cohesion: 0.26
Nodes (7): Country, load(), no_giant_triangles(), Poly, Reader, world(), WORLD_BIN

### Community 171 - "countries.rs"
Cohesion: 0.31
Nodes (6): by_a2(), Entry, table!, parse_a2(), parse_name_or_a2(), search()

### Community 172 - "bundled.rs"
Cohesion: 0.15
Nodes (21): every_built_in_plugin_loads_with_its_own_id(), found(), load(), bundle!, the_abuseipdb_plugin_scores_addresses_in_alerts(), the_cloudflare_plugin_pretends_in_demo(), the_home_assistant_plugin_keeps_its_settings_and_waits_for_a_token(), the_opnsense_plugin_gates_its_options_on_a_probe() (+13 more)

### Community 173 - "Place"
Cohesion: 0.29
Nodes (4): Place, Country, Local, Unknown

### Community 174 - "shodan/src/lib.rs"
Cohesion: 0.21
Nodes (9): DEMO_ADDRESS, demo_reply(), describe(), lists_what_shodan_found(), lookup(), page(), public_ip(), run() (+1 more)

### Community 175 - "AlertLevel"
Cohesion: 0.33
Nodes (4): AlertLevel, .ALL, Important, Logs

### Community 176 - "Found"
Cohesion: 0.16
Nodes (17): table_prefix(), apply(), drop_tables(), erase(), Found, inspect(), install(), plugin_dir() (+9 more)

### Community 177 - "pcap.rs"
Cohesion: 0.15
Nodes (7): LINKTYPE_RAW, MAX_BYTES, MAX_SECS, tcp_filter(), the_filter_names_both_directions_of_one_connection(), Writer<W>, writes_the_pcap_header_and_records()

### Community 179 - "accent.rs"
Cohesion: 0.36
Nodes (3): dword(), windows_accent(), windows_dark()

### Community 180 - "StatusNote"
Cohesion: 0.20
Nodes (5): NoteLevel, Info, Vpn, Warn, StatusNote

### Community 181 - ".hardware_tab"
Cohesion: 0.50
Nodes (3): value(), range_label(), RustWarden

### Community 182 - "Security Policy"
Cohesion: 0.29
Nodes (6): Design notes, Reporting a vulnerability, Scope, Security Policy, Supported versions, What to expect

### Community 183 - "upnp/src/lib.rs"
Cohesion: 0.12
Nodes (33): clean(), click(), CONFLICT, control_of(), DESC, envelope(), find_router(), finds_the_internet_service_and_makes_its_address_absolute() (+25 more)

### Community 184 - "arc"
Cohesion: 0.14
Nodes (6): HardwareSample, GB, HISTORY_STEP, MB, run(), HW_WINDOW

### Community 186 - "ExtrasAct"
Cohesion: 0.29
Nodes (4): ExtrasAct, Pause, Resume, Unblock

### Community 187 - "Target"
Cohesion: 0.33
Nodes (5): only_allow_needs_a_program(), Target, Asn, Country, Domain

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

### Community 196 - "Answer"
Cohesion: 0.40
Nodes (3): Answer, Allow, Block

### Community 197 - "remove_all_owned"
Cohesion: 0.50
Nodes (4): Removal, remove_all_owned(), LOG, run()

### Community 198 - ".start"
Cohesion: 0.31
Nodes (3): EtwSession, Props, stop_by_name()

### Community 199 - "The Firewall tab"
Cohesion: 0.15
Nodes (13): Backing up and moving rules, Block after N minutes, Block an app by clicking it, Firewall modes, Firewall rulesets, Importing rules from another firewall app, Letting RustWarden's own helpers through, Prompt (+5 more)

### Community 200 - "ThreatAct"
Cohesion: 0.29
Nodes (5): ThreatAct, Block, Unblock, Unwhitelist, Whitelist

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

### Community 207 - "path"
Cohesion: 0.47
Nodes (4): a_full_log_moves_aside_and_restarts(), append(), line(), MAX

### Community 210 - "plugin-sdk"
Cohesion: 0.11
Nodes (19): example-hello, plugin-abuseipdb, plugin-cloudflare, plugin-discord, plugin-gotify, plugin-ha, plugin-ntfy, plugin-opnsense (+11 more)

### Community 212 - "AccountChange"
Cohesion: 0.29
Nodes (7): account_and_task_changes(), AccountChange, Activated, Created, Deactivated, Deleted, diff_accounts()

### Community 214 - "TimeRange"
Cohesion: 0.08
Nodes (22): TimeRange, Day, FifteenMinutes, FiveMinutes, OneHour, OneMinute, TenMinutes, ThirtyMinutes (+14 more)

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

### Community 227 - "Updates, backup and upkeep"
Cohesion: 0.20
Nodes (10): Backup and restore, Clean up, History and storage, Snapshots, Tamper protection, The Windows service, Uninstalling RustWarden, Updates (+2 more)

### Community 229 - "Speedtest"
Cohesion: 0.22
Nodes (9): Adding hosts, Charts, First use, Ping Monitor, Ping Monitor and Speedtest, Removing it, Running a test, Settings (+1 more)

### Community 230 - "AppMode"
Cohesion: 0.50
Nodes (3): AppMode, Driver, Normal

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
Cohesion: 0.33
Nodes (6): Behaviour baseline, Teaching it, The alerts, Turning it on, What it learns, While it learns

### Community 254 - "RustWarden user guide"
Cohesion: 0.50
Nodes (4): Built to be safe, RustWarden user guide, What RustWarden does, Where to start

### Community 255 - "SpeedPhase"
Cohesion: 0.50
Nodes (4): SpeedPhase, Download, Ping, Upload

### Community 258 - "Hardware"
Cohesion: 0.67
Nodes (3): Hardware, History, Per-program view

## Knowledge Gaps
- **481 isolated node(s):** `System`, `Notification`, `Label`, `Heading`, `Weak` (+476 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2249 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **25 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Db` connect `Db` to `LiveBackend`, `toast.rs`, `baseline.rs`, `AppRecord`, `export.rs`, `live/apps.rs`, `FwController`, `vt.rs`, `db.rs`, `dest.rs`, `pcap.rs`, `lease.rs`, `arc`, `live/qos.rs`, `monitors.rs`, `domains.rs`, `Scale`, `store.rs`, `tab`, `notes.rs`, `quota.rs`, `ping/src/lib.rs`, `Monitors`, `live/traffic.rs`, `Collector`, `store.rs`, `live/dns.rs`, `.tick`, `report.rs`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **Are the 151 inferred relationships involving `Ui` (e.g. with `app.rs` and `.alert_tabs()`) actually correct?**
  _`Ui` has 151 INFERRED edges - model-reasoned connections that need verification._
- **What connects `System`, `Notification`, `Label` to the rest of the system?**
  _481 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `live/firewall.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.04490106544901065 - nodes in this community are weakly interconnected._
- **Why does `RustWarden` connect `RustWarden` to `dialogs.rs`, `connections.rs`, `update.rs`, `Backend`, `Bg`, `Report`, `popup.rs`, `AsyncMemo`, `data.rs`, `Context`, `driver.rs`, `ui/traffic.rs`, `StatusNote`, `ThreatAct`, `map.rs`, `picker.rs`, `ConfirmAction`, `arc`, `alert_rules.rs`, `arc`, `store.rs`, `live/dns.rs`, `Dialog`, `FirewallMode`, `tray.rs`, `Theme`, `Alert`, `shots.rs`?**
  _High betweenness centrality (0.038) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Db` (e.g. with `.target_ranges()` and `.views()`) actually correct?**
  _`Db` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Should `LiveBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.03896103896103896 - nodes in this community are weakly interconnected._