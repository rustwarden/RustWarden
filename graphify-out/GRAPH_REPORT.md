# Graph Report - RustWarden  (2026-11-06)

## Corpus Check
- 158 files · ~229,869 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 2, .ico 1, .tsv 1)

## Summary
- 4662 nodes · 10084 edges · 212 communities (192 shown, 20 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 530 edges (avg confidence: 0.65)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `16bdb99e`
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
- arc
- Theme
- engine.rs
- dialogs.rs
- browser.rs
- baseline.rs
- settings.rs
- update.rs
- db.rs
- Backend
- external_notifications/mod.rs
- RustWarden
- Settings
- live/apps.rs
- data.rs
- live/scanner.rs
- Db
- demo.rs
- FwController
- util.rs
- popup.rs
- Icon
- discord.rs
- pdh.rs
- alerts.rs
- AlertKind
- autostart.rs
- .show_dialog
- sys/mod.rs
- ping/worker.rs
- sys/firewall.rs
- Alert
- wfp.rs
- QosLimit
- Geo
- .notify
- driver.rs
- netinfo.rs
- etw.rs
- ui/traffic.rs
- dest.rs
- windivert.rs
- conns.rs
- rules_file.rs
- cli.rs
- RustWarden features
- lease.rs
- icons.rs
- asn.rs
- notify.rs
- steps
- live/qos.rs
- report.rs
- p2p.rs
- sys/apps.rs
- steps
- dnsguard.rs
- net.rs
- FirewallMode
- monitors.rs
- clock.rs
- app.rs
- metrics.rs
- steps
- Scale
- netpkt.rs
- Shared
- tab
- modal.rs
- ask.rs
- speedtest/ui.rs
- sniff.rs
- Tab
- ha/client.rs
- watch.rs
- map.rs
- opnsense/client.rs
- .ui
- latency.rs
- ConfirmAction
- quota.rs
- thinkbroadband/ui.rs
- services.rs
- hashset
- domains.rs
- Monitors
- shots.rs
- live/traffic.rs
- alertrules.rs
- RangeSet
- vt.rs
- Integration
- Priority
- scandetect.rs
- Address
- Collector
- alert_rules.rs
- Dialog
- destrules.rs
- .tick
- Tbb
- capture.rs
- tray.rs
- external_notifications/ui.rs
- protect.rs
- DestRule
- TrafficFilter
- windows_extras.rs
- Domains
- speedtest/worker.rs
- TcpState
- traffic_load.rs
- .log_tab
- netparse.rs
- sys/qos.rs
- install_service
- quiet
- tamper.rs
- err
- ordering
- Vt
- migrate.rs
- UsageEntry
- .speedtest_tab
- PCWSTR
- wallpaper.rs
- super
- pathbuf
- QuotaStatus
- live/store.rs
- Country
- Caps
- audit.rs
- connections.rs
- tcp_row
- PWSTR
- PlanPeriod
- AppCategory
- AppIcon
- export.rs
- src/geo.rs
- pcwstr
- curl.rs
- dpapi.rs
- ifstats.rs
- pcap.rs
- NetEvent
- Scanner
- .start
- render.rs
- Rule
- StatusNote
- DeviceKind
- Target
- Line
- thinkbroadband/store.rs
- QuotaAction
- listeners
- .connections_tab
- Card
- paths
- FirewallInfo
- countries.rs
- Direction
- LiveConn
- SpeedResult
- AlertLevel
- accent.rs
- instant
- RuleAction
- ConnGroup
- HistoryData
- hashmap
- Security Policy
- AppGroup
- SpeedStatus
- Threat
- ExtrasAct
- AccountChange
- RuleSpec
- AGENTS.md
- decode
- path
- NetInfoSource
- PlanDirection
- parse_dns
- Manual checks on a real machine
- install_elevated
- Capabilities
- DeviceEvent
- Writer<W>
- parse_add
- Phase
- plan-release.sh
- tcp6_row
- Held
- .new
- main.rs
- profile_state
- flag_data.rs
- rustwarden

## God Nodes (most connected - your core abstractions)
1. `Settings` - 162 edges
2. `Db` - 139 edges
3. `RustWarden` - 127 edges
4. `LiveBackend` - 116 edges
5. `Backend` - 104 edges
6. `MockBackend` - 90 edges
7. `Icon` - 67 edges
8. `FwController` - 66 edges
9. `AlertKind` - 64 edges
10. `Outcome` - 34 edges

## Surprising Connections (you probably didn't know these)
- `Writer` --references--> `W`  [INFERRED]
  src/pcap.rs → build.rs
- `RustWarden` --references--> `Dlg`  [INFERRED]
  src/app.rs → src/plugins/ping/ui.rs
- `write()` --calls--> `wide()`  [INFERRED]
  src/sys/eventlog.rs → src/sys/mod.rs
- `Settings` --references--> `AlertRule`  [INFERRED]
  src/settings.rs → src/alertrules.rs
- `TrafficState` --references--> `TrafficFilter`  [INFERRED]
  src/app.rs → src/data.rs

## Import Cycles
- 1-file cycle: `src/ui/map.rs -> src/ui/map.rs`
- 1-file cycle: `src/data.rs -> src/data.rs`
- 1-file cycle: `src/ui/mod.rs -> src/ui/mod.rs`

## Communities (212 total, 20 thin omitted)

### Community 0 - "live/firewall.rs"
Cohesion: 0.04
Nodes (74): a_service_rule_is_a_separate_row_with_its_own_name(), ACTIVE_PROFILE_KEY, adopt_legacy_rules(), allow_engine_traffic(), allow_rules_are_ours_outbound_and_distinct_from_block_rules(), allow_spec(), ASK_KEY, ask_marker_exists() (+66 more)

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
Cohesion: 0.06
Nodes (47): DnsState, DnsEntry, cache_path(), check(), clean(), domain_of(), download(), each_program_and_name_is_reported_once() (+39 more)

### Community 5 - "MockBackend"
Cohesion: 0.05
Nodes (4): demo_bandwidth_limits_can_be_added_changed_and_cleared(), demo_destination_rules_add_replace_remove_and_reset(), demo_networks_keep_separate_devices_and_threat_lists(), MockBackend

### Community 6 - "widgets.rs"
Cohesion: 0.09
Nodes (47): fit_text(), area(), area_faded(), area_faded_to(), area_impl(), area_soft_to(), brand_menu_row(), check_item() (+39 more)

### Community 7 - "arc"
Cohesion: 0.06
Nodes (33): device_kind(), editor(), ICON, LOGO, logo(), mark(), paint_badges(), Test (+25 more)

### Community 8 - "Theme"
Cohesion: 0.05
Nodes (27): PROMPT_FOR, Theme, Dark, Light, ROW_H, RustWarden, Chart, RANGES (+19 more)

### Community 9 - "engine.rs"
Cohesion: 0.08
Nodes (33): a_limit_only_paces_the_directions_it_names(), die(), DROP_LIMIT, DROP_WINDOW_MS, Engine, filter_loop(), filter_needs_swap(), flow_loop() (+25 more)

### Community 10 - "dialogs.rs"
Cohesion: 0.09
Nodes (47): ThreatLists, P2pApp, cell(), ABOUT_CLICKS, ABOUT_PNG, accent_picker(), ACCENTS, ALERT_JUMP (+39 more)

### Community 11 - "browser.rs"
Cohesion: 0.05
Nodes (37): Config, demo_samples(), demo_samples_are_ordered_inside_the_span_and_sane(), Host, sanitize(), tab_visible(), CHECK, CHECK_SECS (+29 more)

### Community 12 - "baseline.rs"
Cohesion: 0.07
Nodes (34): active_days_by_hour(), BUSY_HOUR, DAY, DIM_ASN, DIM_COUNTRY, DIM_HOUR, DIM_VOLUME, hour_why() (+26 more)

### Community 13 - "settings.rs"
Cohesion: 0.06
Nodes (30): alert_rules_are_sanitized_and_survive_a_save(), app_mode_defaults_to_normal_and_round_trips(), baseline_settings_are_clamped(), config_dir(), config_path(), DataPlan, deserialize(), DNS_FEED_DEFAULT (+22 more)

### Community 14 - "update.rs"
Cohesion: 0.06
Nodes (42): UpdateView, Available, CheckFailed, Checking, InstallFailed, Installing, Latest, UpdateChannel (+34 more)

### Community 15 - "db.rs"
Cohesion: 0.08
Nodes (29): AlertCheck, alert_chain_survives_reads_and_names_the_first_change(), alert_hash(), alerts_round_trip_and_mark_read(), app_records_and_missing_state(), BASE_ALERTED, BASE_LEARNED, BASE_NORMAL (+21 more)

### Community 17 - "external_notifications/mod.rs"
Cohesion: 0.06
Nodes (14): Gotify, ANY, config(), json(), present(), Req, requests(), requests_follow_configuration() (+6 more)

### Community 18 - "RustWarden"
Cohesion: 0.10
Nodes (4): default_window(), DestDraft, make_backend(), RustWarden

### Community 19 - "Settings"
Cohesion: 0.06
Nodes (25): active(), Integration, sanitize(), device_url(), display_name(), Config, sanitize(), tab_visible() (+17 more)

### Community 20 - "live/apps.rs"
Cohesion: 0.08
Nodes (26): core_services_are_refused_and_other_services_are_not(), critical_reason(), CRITICAL_SERVICES, describe_change(), ensure_record(), ensure_service_record(), file_name(), is_svchost() (+18 more)

### Community 21 - "data.rs"
Cohesion: 0.07
Nodes (32): TrafficState, ActiveCountries, DetailRow, Glyph, App, Flag, More, Window (+24 more)

### Community 22 - "live/scanner.rs"
Cohesion: 0.08
Nodes (29): progress(), arp_probe(), Found, MAX_PREFIX_HOSTS, nbstat(), nbstat_request(), networks(), oui_map() (+21 more)

### Community 23 - "Db"
Cohesion: 0.06
Nodes (8): HardwareSample, row(), add_column(), Db, .APP_COLS, DeviceRow, devices_keep_user_names_and_go_offline(), dns_log_round_trips_and_prunes()

### Community 24 - "demo.rs"
Cohesion: 0.07
Nodes (33): Device, demo_alerts(), demo_apps(), demo_block_all_shows_active(), demo_connections(), demo_connections_have_sample_rows(), demo_dest_rules(), demo_devices() (+25 more)

### Community 25 - "FwController"
Cohesion: 0.13
Nodes (12): enable_audit(), extras_paused(), extras_rules(), FwController, is_aux(), is_ours(), paused_extras(), profile_since() (+4 more)

### Community 26 - "util.rs"
Cohesion: 0.08
Nodes (22): app_icon_rgba(), async_memo_answers_none_until_the_read_lands_then_keeps_it(), AsyncMemo, AsyncMemo<K, V>, Bg, bg_runs_the_latest_waiting_request_and_reports_a_panic_once(), Bg<T>, BIT_UNITS (+14 more)

### Community 27 - "popup.rs"
Cohesion: 0.08
Nodes (27): ThreatAct, Block, Unblock, Unwhitelist, Whitelist, ALERT_INFO_TITLE, ALERT_TITLE, ALERTS_SECTION (+19 more)

### Community 28 - "Icon"
Cohesion: 0.05
Nodes (41): Icon, Alerts, ArrowDown, ArrowUp, Bell, Bulb, Camera, Check (+33 more)

### Community 29 - "discord.rs"
Cohesion: 0.06
Nodes (7): simplify(), Discord, HOSTS, GREEN, RED, Pushbullet, Slack

### Community 30 - "pdh.rs"
Cohesion: 0.09
Nodes (12): engine_type(), expand(), gpu_load(), GpuQuery, Handle, Pdh, ProcQuery, Query (+4 more)

### Community 31 - "alerts.rs"
Cohesion: 0.08
Nodes (24): adapter_ignored(), anomaly_kinds_have_keys_and_switches(), arp_mac_change_is_reported_once(), ArpChange, device_events(), device_events_find_new_changed_multi_and_returned(), device_use_reports_new_and_later_uses(), diff_arp() (+16 more)

### Community 32 - "AlertKind"
Cohesion: 0.05
Nodes (34): AlertKind, .ALL, AnomalyContact, AnomalyHour, AnomalyVolume, AppChanged, Arp, Away (+26 more)

### Community 33 - "autostart.rs"
Cohesion: 0.07
Nodes (17): CHILD, claim_instance(), EVENTS, in_program_files(), LAUNCH, LAUNCH_HIDDEN, MOVED_TO, REFUSED (+9 more)

### Community 34 - ".show_dialog"
Cohesion: 0.09
Nodes (22): about_click_hits(), Outcome, Apply, Close, Confirmed, ExportRules, ImportRules, InstallService (+14 more)

### Community 35 - "sys/mod.rs"
Cohesion: 0.08
Nodes (21): file_icon_rgba(), has_valid_embedded_signature(), service_has_sid(), from_wide(), hidden_start(), home_region(), message(), NO_WINDOW (+13 more)

### Community 36 - "ping/worker.rs"
Cohesion: 0.08
Nodes (13): AT_ONCE, echo(), EVERY_SECS, KEEP_SECS, LAST_OK, ping_v4(), ping_v6(), PINGS (+5 more)

### Community 37 - "sys/firewall.rs"
Cohesion: 0.06
Nodes (5): PROFILE_DOMAIN, PROFILE_PRIVATE, PROFILE_PUBLIC, PROFILES, PROTO_ANY

### Community 38 - "Alert"
Cohesion: 0.07
Nodes (23): LogState, Alert, AlertDest, .ALL, Any, Local, Remote, AlertFilter (+15 more)

### Community 39 - "wfp.rs"
Cohesion: 0.08
Nodes (8): app_name(), decode(), dos_path(), is_icmp(), on_event(), RPC_C_AUTHN_DEFAULT, Subscription, swap_device()

### Community 40 - "QosLimit"
Cohesion: 0.08
Nodes (15): decode_all(), directions_round_trip_and_old_lines_still_read(), encode_all(), fmt_rate(), limit(), MAX_DELAY_MS, MAX_KBPS, MAX_LOSS_PCT (+7 more)

### Community 41 - "Geo"
Cohesion: 0.10
Nodes (12): asn_networks(), city_db_path(), country_networks_cover_addresses_the_database_places_there(), default_db_path(), download_dbip(), Geo, Place, Country (+4 more)

### Community 42 - ".notify"
Cohesion: 0.17
Nodes (6): Confirm, firewall_toggle_confirm(), profile_confirm(), virustotal_upload_confirm(), RustWarden, set_mode_and_enable()

### Community 43 - "driver.rs"
Cohesion: 0.10
Nodes (24): BLOCKED_HELP, DLL, DriverState, Blocked, Missing, Ready, folder_state_tells_missing_ready_and_blocked_apart(), hash_matches() (+16 more)

### Community 44 - "netinfo.rs"
Cohesion: 0.10
Nodes (11): Adapter, adapters(), adapters_and_neighbors_are_readable(), idle_seconds(), is_tunnel(), Neighbor, neighbors(), proxy_snapshot() (+3 more)

### Community 45 - "etw.rs"
Cohesion: 0.08
Nodes (10): DROPPED, parse_kernel_network(), SESSION_NAME, set_spawn_hook(), SPAWN_HOOK, SpawnHook, tcp_v4_send(), u16_be() (+2 more)

### Community 46 - "ui/traffic.rs"
Cohesion: 0.16
Nodes (7): tick_step(), command_card(), command_card_id(), kind_icon(), popup_fit(), RustWarden, fmt_bytes()

### Community 47 - "dest.rs"
Cohesion: 0.13
Nodes (15): MAX_RULES_PER_DEST, Dest, DNS_WINDOW, firewall_rules_belong_to_their_destination_rule(), id_of(), load(), name_changes_with_the_address_list_program_and_mode_only(), rule() (+7 more)

### Community 48 - "windivert.rs"
Cohesion: 0.09
Nodes (17): ChecksumFn, CloseFn, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED, FLAG_RECV_ONLY, FLAG_SNIFF, LAYER_FLOW, LAYER_NETWORK (+9 more)

### Community 49 - "conns.rs"
Cohesion: 0.07
Nodes (3): ENABLED, STATE_ESTABLISHED, STATE_SYN_SENT

### Community 50 - "rules_file.rs"
Cohesion: 0.12
Nodes (18): FirewallApp, Verdict, Allowed, Blocked, a_file_survives_writing_and_reading(), AppRule, current_of(), destination_rules_are_added_once_and_get_fresh_ids() (+10 more)

### Community 51 - "cli.rs"
Cohesion: 0.11
Nodes (21): demo_live(), adopt(), adopt_user_copy(), dir(), exe(), EXE_SHA256, install(), parse() (+13 more)

### Community 52 - "RustWarden features"
Cohesion: 0.07
Nodes (25): 🚨 Alerts and log analysis, 🧭 Behaviour baseline, Clean up, 📏 Data quotas, 🔎 DNS Log, ⚙️ Everything else, 🛡️ Firewall: your firewall, simplified, 📈 Hardware resources (+17 more)

### Community 53 - "lease.rs"
Cohesion: 0.13
Nodes (21): before_spawn(), check_again_at(), decode(), due(), encode(), end(), end_all(), GROUP (+13 more)

### Community 54 - "icons.rs"
Cohesion: 0.17
Nodes (15): a_ring_has_no_repeated_end_point(), app_icon(), app_icon_for(), arc_points(), flag(), flag_texture(), glyph(), IconCache (+7 more)

### Community 55 - "asn.rs"
Cohesion: 0.15
Nodes (14): curl_url(), cymru(), cymru_name(), cymru_names_are_reversed(), format_info(), from_json(), http(), lookup() (+6 more)

### Community 56 - "notify.rs"
Cohesion: 0.09
Nodes (6): balloon(), copy(), copy_truncates_and_terminates(), icon(), LINGER, worker()

### Community 57 - "steps"
Cohesion: 0.07
Nodes (26): run, GH_TOKEN, RUSTFLAGS, TAG_MATCH, UPDATE_SIGNING_KEY, jobs, release, name (+18 more)

### Community 58 - "live/qos.rs"
Cohesion: 0.14
Nodes (10): KEY, load(), NEEDS_ADMIN, Qos, run(), saved_limits_round_trip_through_the_store(), store(), without_administrator_rights_a_limit_is_refused() (+2 more)

### Community 59 - "report.rs"
Cohesion: 0.12
Nodes (20): KIND_WAN, a_report_is_due_once_per_slot(), build(), build_finds_new_hosts_only_with_older_history(), country_of(), due(), KV_LAST, last_slot() (+12 more)

### Community 60 - "p2p.rs"
Cohesion: 0.13
Nodes (20): fingerprint(), P2P_PREFIX, blocked_keys(), blocks_only_with_detection_on_and_no_vpn(), BROWSERS, CLIENTS, Detector, ip() (+12 more)

### Community 61 - "sys/apps.rs"
Cohesion: 0.09
Nodes (6): current_process_has_a_path(), notepad_like_system_binary_has_version_info(), pid_path(), running_paths(), version_info(), VersionInfo

### Community 62 - "steps"
Cohesion: 0.08
Nodes (25): run, GH_TOKEN, RUSTFLAGS, UPDATE_SIGNING_KEY, jobs, release, name, on (+17 more)

### Community 63 - "dnsguard.rs"
Cohesion: 0.16
Nodes (14): Action, Pass, Redirect, Restore, decide(), FILTER, Guard, KEEP (+6 more)

### Community 64 - "net.rs"
Cohesion: 0.14
Nodes (18): classify(), classify_v4(), classify_v6(), dns_results_are_scanned_for_addresses(), ip(), ips_in_dns_results(), is_cgnat(), Locality (+10 more)

### Community 65 - "FirewallMode"
Cohesion: 0.09
Nodes (20): FirewallMode, .ALL, AskToConnect, BlockAll, ClickToBlock, prompt_for_label(), mode_confirm(), prompt_step() (+12 more)

### Community 66 - "monitors.rs"
Cohesion: 0.12
Nodes (19): Debounce, diff_files(), diff_tasks(), plan_level(), PlanLevel, Over, Warning, arp_snapshot() (+11 more)

### Community 67 - "clock.rs"
Cohesion: 0.14
Nodes (13): civil_from_days(), day_label(), days_from_civil(), file_stamp(), fmt_date(), fmt_stamp(), fmt_time_lower(), local_offset_at() (+5 more)

### Community 68 - "app.rs"
Cohesion: 0.09
Nodes (16): BLOCK_AFTER_MINS, DomainDraft, fit_window(), HwSeries, ProtectState, QosDraft, REFRESH_EVERY, ScannerLoad (+8 more)

### Community 69 - "metrics.rs"
Cohesion: 0.15
Nodes (12): bind_retrying(), Endpoint, exchange(), handle(), label(), LOG, metrics_answers_loopback_requests(), render() (+4 more)

### Community 70 - "steps"
Cohesion: 0.09
Nodes (22): run, GALLIUM_DRIVER, MESA_SHA256, RUSTWARDEN_SHOTS, jobs, screenshots, name, on (+14 more)

### Community 71 - "Scale"
Cohesion: 0.15
Nodes (15): TrafficSample, align(), fill(), fill_pads_and_converts_to_rates(), range_buckets(), range_ends_in_the_current_bucket(), Scale, .ALL (+7 more)

### Community 72 - "netpkt.rs"
Cohesion: 0.15
Nodes (16): pkt(), limited_ports(), addresses_can_be_swapped_in_ipv4_only(), FlowKey, ipv4_tcp(), parse(), Parsed, reads_ipv4_tcp_and_both_directions_share_one_flow() (+8 more)

### Community 73 - "Shared"
Cohesion: 0.16
Nodes (5): a_mute_rule_records_the_alert_but_shows_nothing(), an_escalate_rule_makes_an_alert_important_with_a_popup(), lock(), Shared, shared()

### Community 74 - "tab"
Cohesion: 0.17
Nodes (9): calendar(), day_shift(), Feed, Line, refresh_status(), reload(), State, tab() (+1 more)

### Community 75 - "modal.rs"
Cohesion: 0.10
Nodes (3): find(), find_all(), MAIN

### Community 76 - "ask.rs"
Cohesion: 0.18
Nodes (13): icon_for(), count(), fw_closed_since(), IN_FLIGHT, is_noise(), lookups_on(), MAX_IN_FLIGHT, MAX_OPEN_ASKS (+5 more)

### Community 77 - "speedtest/ui.rs"
Cohesion: 0.11
Nodes (11): SpeedRoute, arc_mesh(), dial_frac(), DIAL_START, DIAL_SWEEP, MARKS, RANGES, RELOAD (+3 more)

### Community 78 - "sniff.rs"
Cohesion: 0.21
Nodes (12): FILTER, flow_loop(), Flows, MAX_FLOWS, packet_loop(), refresh(), report(), run() (+4 more)

### Community 79 - "Tab"
Cohesion: 0.10
Nodes (17): every_tab_has_its_own_key_that_reads_back(), Tab, AlertRules, .ALL, Bandwidth, Broadband, Connections, DestRules (+9 more)

### Community 80 - "ha/client.rs"
Cohesion: 0.14
Nodes (15): curl(), lookup(), parse(), parses_a_match_and_picks_the_type(), template(), template_embeds_only_a_clean_lowercase_mac(), test(), HaInfo (+7 more)

### Community 81 - "watch.rs"
Cohesion: 0.14
Nodes (9): device_use(), open(), root_certs(), RUN_KEYS, service_names(), snapshots_read_the_registry(), startup_entries(), subkeys() (+1 more)

### Community 82 - "map.rs"
Cohesion: 0.23
Nodes (13): ARC, blocked_color(), clamp_center(), home_dot(), land(), land_active(), land_edge(), land_hover() (+5 more)

### Community 83 - "opnsense/client.rs"
Cohesion: 0.17
Nodes (12): a_leftover_alias_is_reported(), a_read_check_keeps_the_earlier_write_result(), a_read_only_key_is_told_apart(), a_writable_key_creates_then_removes_the_test_alias(), base64(), Fake, json_str(), PROBE_ALIAS (+4 more)

### Community 84 - ".ui"
Cohesion: 0.13
Nodes (4): snap(), RustWarden, RustWarden, service()

### Community 85 - "latency.rs"
Cohesion: 0.19
Nodes (16): BLUE, camera(), column_count(), columns(), columns_keep_the_extremes_and_average_the_rest(), export(), FLASH_SECS, FOOTER_H (+8 more)

### Community 86 - "ConfirmAction"
Cohesion: 0.10
Nodes (20): ConfirmAction, ApplyRules, BlockWindowsExtras, CleanUp, ClearHistory, DeleteProfile, FirewallEnabled, FirewallMode (+12 more)

### Community 87 - "quota.rs"
Cohesion: 0.25
Nodes (17): action_none_only_warns(), block_is_asked_for_until_it_happens(), clock_moved_back_starts_a_fresh_period(), Decision, deleted_disabled_or_retargeted_quotas_orphan_their_track(), jumping_straight_over_alerts_once(), KV_KEY, level() (+9 more)

### Community 88 - "thinkbroadband/ui.rs"
Cohesion: 0.17
Nodes (12): alert_options(), DISMISSED, EDIT, editor(), Import, LOADING, LOGO, loss_levels() (+4 more)

### Community 89 - "services.rs"
Cohesion: 0.15
Nodes (8): by_pid(), label(), lists_running_services(), one_service_is_named_with_its_short_name(), SC_MANAGER_ENUMERATE_SERVICE, Service, shared_hosts_are_keyed_in_a_stable_order(), svc()

### Community 90 - "hashset"
Cohesion: 0.13
Nodes (8): decode_all(), DomainRule, DomainView, encode_all(), MAX_LIST, MAX_RULES, normalize(), parse_list()

### Community 91 - "domains.rs"
Cohesion: 0.16
Nodes (8): Matcher, FILTER, FILTER_BROAD, KEY, packet_loop(), Running, should_drop(), URL_KEY

### Community 93 - "shots.rs"
Cohesion: 0.15
Nodes (8): SCREENS, SETTLE, Setup, Shots, Window, Ask, Main, Threat

### Community 94 - "live/traffic.rs"
Cohesion: 0.27
Nodes (12): Aggregator, aggregator_sums_by_key(), ev(), Flow, flow_of(), ip(), is_vpn_outer(), lan_traffic_is_classified() (+4 more)

### Community 95 - "alertrules.rs"
Cohesion: 0.19
Nodes (13): AlertInfo, conditions_all_have_to_hold(), contains_nocase(), decide(), Effect, first_enabled_match_wins(), in_window(), info() (+5 more)

### Community 96 - "RangeSet"
Cohesion: 0.24
Nodes (10): block_mode_never_touches_the_local_network(), blocked_set(), complement_covers_everything_else(), ip(), local_ranges(), long_lists_are_split_into_rules_within_the_limits(), RangeSet, set() (+2 more)

### Community 97 - "vt.rs"
Cohesion: 0.14
Nodes (13): json_val(), API, curl(), HOLD, HOLD_AFTER, lookup(), MAX_POLLS, MAX_UPLOAD (+5 more)

### Community 98 - "Integration"
Cohesion: 0.23
Nodes (7): a_read_only_key_cannot_push(), changing_the_key_discards_the_probe(), Integration, options_stay_off_until_probed(), probed(), sanitize(), saving_needs_a_name_address_key_and_secret()

### Community 99 - "Priority"
Cohesion: 0.12
Nodes (10): LimitDir, .ALL, Both, Down, Up, Priority, .ALL, High (+2 more)

### Community 100 - "scandetect.rs"
Cohesion: 0.18
Nodes (12): a_burst_from_many_sources_is_a_flood(), Detector, Finding, PortScan, SynFlood, FLOOD_PER_SEC, ip(), many_ports_from_one_source_is_a_scan_reported_once() (+4 more)

### Community 101 - "Address"
Cohesion: 0.14
Nodes (6): Address, flow_address(), flow_events_are_read_from_the_address_union(), FlowInfo, Handle, ipv6_words_come_last_first()

### Community 102 - "Collector"
Cohesion: 0.21
Nodes (4): kernel_service(), Collector, publish_geo_note(), run()

### Community 103 - "alert_rules.rs"
Cohesion: 0.18
Nodes (9): AlertRule, ALL_DAYS, DAY_NAMES, parse_minute(), draft_becomes_a_rule_or_says_why_not(), kind_title(), labelled(), RuleDraft (+1 more)

### Community 104 - "Dialog"
Cohesion: 0.12
Nodes (16): Dialog, About, Confirm, Info, InstallService, NewProfile, Password, Rename (+8 more)

### Community 105 - "destrules.rs"
Cohesion: 0.15
Nodes (8): MAX_CHARS_PER_RULE, MAX_RANGES_PER_RULE, merge(), merge_seen(), seen_addresses_expire(), seen_from_text(), seen_to_text(), V4_MAX

### Community 106 - ".tick"
Cohesion: 0.21
Nodes (8): orphaned(), run(), Track, tracks_from_text(), tracks_round_trip_through_text(), tracks_to_text(), user_blocked(), Worker

### Community 107 - "Tbb"
Cohesion: 0.21
Nodes (4): backfill(), RustWarden, start_sign_in(), Tbb

### Community 108 - "capture.rs"
Cohesion: 0.18
Nodes (3): Capture, Session, CaptureStatus

### Community 109 - "tray.rs"
Cohesion: 0.17
Nodes (5): icon(), Tray, TrayCmd, Menu, Toggle

### Community 110 - "external_notifications/ui.rs"
Cohesion: 0.19
Nodes (6): png(), section(), table(), field(), mark(), section()

### Community 111 - "protect.rs"
Cohesion: 0.17
Nodes (10): PendingBlock, block(), countdown_is_the_earliest_block_of_that_app(), countdown_of(), DEFAULT_COLS, held_row_keeps_its_place_while_others_move(), hold_in_place(), ROW_H (+2 more)

### Community 112 - "DestRule"
Cohesion: 0.12
Nodes (8): demo_dest_status(), decode_all(), DestRule, DestRuleView, encode_all(), Mode, Block, OnlyAllow

### Community 113 - "TrafficFilter"
Cohesion: 0.12
Nodes (12): Scope, .ALL, Both, Lan, Wan, TrafficDir, .ALL, Both (+4 more)

### Community 114 - "windows_extras.rs"
Cohesion: 0.18
Nodes (11): only_the_windows_svchost_is_split_by_service(), system_root(), expand(), Group, GROUPS, is_protected(), matches(), PROTECTED (+3 more)

### Community 115 - "Domains"
Cohesion: 0.28
Nodes (5): Domains, list_path(), load_rules(), run(), store_rules()

### Community 116 - "speedtest/worker.rs"
Cohesion: 0.21
Nodes (11): CLI_READY, ERROR, install(), INSTALLING, KEEP_SECS, LAST_OK, LIVE, run() (+3 more)

### Community 117 - "TcpState"
Cohesion: 0.13
Nodes (14): state_raw(), TcpState, Closed, CloseWait, Closing, DeleteTcb, Established, FinWait1 (+6 more)

### Community 118 - "traffic_load.rs"
Cohesion: 0.26
Nodes (8): Loader, merge_adds_parts_and_takes_the_newer_values(), Query, query(), run(), run_reads_only_what_was_asked(), sel_fractions(), Slot

### Community 119 - ".log_tab"
Cohesion: 0.19
Nodes (5): counts(), multi_pick(), RustWarden, source_tab(), stat_bars()

### Community 120 - "netparse.rs"
Cohesion: 0.23
Nodes (10): client_hello(), dns(), DnsMessage, finds_the_server_name_and_refuses_junk(), host_ok(), name_at(), query(), reads_queries_and_answers_with_compressed_names() (+2 more)

### Community 121 - "sys/qos.rs"
Cohesion: 0.21
Nodes (9): add_exclusion(), remove_exclusion(), apply(), list(), parse_policy(), Policy, powershell(), remove() (+1 more)

### Community 122 - "install_service"
Cohesion: 0.22
Nodes (14): adopt_legacy_entries(), desktop_lnk(), downloads_exe(), install_service(), installed_exe(), lnk_in(), refresh_stale_service(), run_elevated() (+6 more)

### Community 123 - "quiet"
Cohesion: 0.23
Nodes (14): authorize_stop(), end_other_instances(), end_processes(), ensure_service_running(), ok(), prepare_debug(), quiet(), remove_legacy_service() (+6 more)

### Community 124 - "tamper.rs"
Cohesion: 0.18
Nodes (7): digest(), hash(), hex(), ROUNDS, salt(), verify(), checks_the_release_signature()

### Community 125 - "err"
Cohesion: 0.29
Nodes (11): add_rule(), adopt_rule(), bool_variant(), default_outbound_blocked(), enable_windows_firewall(), err(), policy(), remove_rule() (+3 more)

### Community 127 - "Vt"
Cohesion: 0.15
Nodes (12): Vt, Analysing, Failed, None, NotFound, OnHold, Pending, Result (+4 more)

### Community 128 - "migrate.rs"
Cohesion: 0.27
Nodes (13): dir(), DONE, merge_dir(), merge_keeps_what_the_new_folder_has(), move_program_files(), move_user_data(), OLD, rename_in_db() (+5 more)

### Community 129 - "UsageEntry"
Cohesion: 0.22
Nodes (7): Dim, App, Proto, Remote, inspect_db(), inspect_detail(), UsageEntry

### Community 130 - ".speedtest_tab"
Cohesion: 0.30
Nodes (10): card_frame(), chart(), gauge(), live_chart(), mbps(), nice_ceil(), results_card(), setup_card() (+2 more)

### Community 131 - "PCWSTR"
Cohesion: 0.19
Nodes (11): answer_stop(), DISPLAY, EV_ACK, EV_ASK, EV_NO, EV_OK, open_event(), SHOW_EVENT (+3 more)

### Community 133 - "super"
Cohesion: 0.19
Nodes (5): Db, samples_are_read_back_per_host_in_order(), SCHEMA, MIGRATIONS, SCHEMA

### Community 134 - "pathbuf"
Cohesion: 0.23
Nodes (9): disable(), disables_the_features_that_use_downloads(), remove(), removes_files_and_folders_and_ignores_missing(), run(), size(), targets(), warning() (+1 more)

### Community 135 - "QuotaStatus"
Cohesion: 0.17
Nodes (8): QuotaLevel, Ok, Over, Warn, QuotaStatus, demo_quotas(), used_by(), Quota

### Community 136 - "live/store.rs"
Cohesion: 0.26
Nodes (7): ConnectAsk, country_of(), FwSnapshot, HwNow, NetworkInfo, State, TrafficNow

### Community 137 - "Country"
Cohesion: 0.17
Nodes (11): Country, France, Germany, Ireland, Iso, Local, Netherlands, Other (+3 more)

### Community 138 - "Caps"
Cohesion: 0.26
Nodes (7): Curl, demo_probe(), probe(), Reply, request(), Transport, Caps

### Community 139 - "audit.rs"
Cohesion: 0.24
Nodes (9): auditpol(), blocked_since(), data(), failure_audit_on(), parse_events(), reads_outbound_drops_only(), set_failure_audit(), SUBCATEGORY (+1 more)

### Community 141 - "connections.rs"
Cohesion: 0.24
Nodes (10): compare(), conn(), groups_by_process_and_folds(), HEADERS, Line, Conn, Group, lines() (+2 more)

### Community 142 - "tcp_row"
Cohesion: 0.24
Nodes (10): ConnRow, filetime_to_unix(), fill_bytes(), kill(), killable(), read_bytes(), row_uses_network_byte_order(), set_collection() (+2 more)

### Community 143 - "PWSTR"
Cohesion: 0.23
Nodes (9): handler(), launch_gui(), logon_hidden(), make_events(), report(), report_step(), run_dispatcher(), service_main() (+1 more)

### Community 144 - "PlanPeriod"
Cohesion: 0.17
Nodes (11): PeriodKind, Day, Month, Week, period_kind(), period_word(), PlanPeriod, .ALL (+3 more)

### Community 145 - "AppCategory"
Cohesion: 0.17
Nodes (10): AppCategory, AiAssistants, .ALL, Browsers, CloudSync, DevTools, Other, RemoteAccess (+2 more)

### Community 146 - "AppIcon"
Cohesion: 0.17
Nodes (12): AppIcon, Bitwarden, Chrome, Claude, ClaudeCode, Drive, Gear, Generic (+4 more)

### Community 147 - "export.rs"
Cohesion: 0.24
Nodes (8): AlertRow, alerts_csv(), csv_keeps_awkward_values_in_one_cell(), json(), json_uses_field_names(), traffic_csv(), traffic_csv_has_one_line_per_row_after_the_header(), TrafficRow

### Community 148 - "src/geo.rs"
Cohesion: 0.29
Nodes (7): Country, load(), no_giant_triangles(), Poly, Reader, world(), WORLD_BIN

### Community 150 - "pcwstr"
Cohesion: 0.18
Nodes (4): W, Writer, EVENT_ID, write()

### Community 151 - "curl.rs"
Cohesion: 0.24
Nodes (6): a_value_cannot_break_out_of_the_config(), api_config(), PROTO, quote(), refuses_other_protocols(), run()

### Community 152 - "dpapi.rs"
Cohesion: 0.25
Nodes (4): protect(), round_trips_and_rejects_garbage(), take(), unprotect()

### Community 153 - "ifstats.rs"
Cohesion: 0.22
Nodes (5): Counters, delta(), IF_OPER_STATUS_UP, IF_TYPE_SOFTWARE_LOOPBACK, read()

### Community 154 - "pcap.rs"
Cohesion: 0.22
Nodes (5): LINKTYPE_RAW, MAX_BYTES, MAX_SECS, tcp_filter(), the_filter_names_both_directions_of_one_connection()

### Community 155 - "NetEvent"
Cohesion: 0.25
Nodes (7): inject(), NetEvent, Data, Dns, PATHS, sink(), SINK

### Community 156 - "Scanner"
Cohesion: 0.31
Nodes (4): a_hash_virustotal_has_not_seen_is_never_uploaded_by_itself(), a_hash_with_a_final_answer_is_not_looked_up_or_sent_again(), Scanner, upload_queues_only_when_asked_and_only_once()

### Community 157 - ".start"
Cohesion: 0.31
Nodes (3): EtwSession, Props, stop_by_name()

### Community 159 - "Rule"
Cohesion: 0.33
Nodes (9): rules_to_suspend(), enabled_outbound_allows(), enabled_outbound_blocks(), read_rule(), reading_rules_works_without_administrator(), Rule, rules_in_group(), rules_named() (+1 more)

### Community 160 - "StatusNote"
Cohesion: 0.20
Nodes (5): NoteLevel, Info, Vpn, Warn, StatusNote

### Community 161 - "DeviceKind"
Cohesion: 0.20
Nodes (9): DeviceKind, Generic, Laptop, Raspberry, SmartDevice, WiFi, guess_kind(), kind_from_i64() (+1 more)

### Community 162 - "Target"
Cohesion: 0.22
Nodes (5): only_allow_needs_a_program(), Target, Asn, Country, Domain

### Community 163 - "Line"
Cohesion: 0.24
Nodes (6): Line, Plan, At, Drop, Pass, the_line_serves_high_first_and_squeezes_the_rest()

### Community 164 - "thinkbroadband/store.rs"
Cohesion: 0.29
Nodes (3): Db, samples_are_replaced_and_read_back_in_order(), SCHEMA

### Community 165 - "QuotaAction"
Cohesion: 0.20
Nodes (7): QuotaAction, AlertOnly, .ALL, Block, None, Throttle, ThrottleBlock

### Community 166 - "listeners"
Cohesion: 0.22
Nodes (7): Conn, fetch(), fetch_class(), Listener, listeners(), port_of(), tcp()

### Community 167 - ".connections_tab"
Cohesion: 0.24
Nodes (6): Act, Block, Capture, Kill, fmt_age(), RustWarden

### Community 169 - "paths"
Cohesion: 0.25
Nodes (6): cached_path(), forget_dead(), parent_of(), paths(), remember(), spawn_own()

### Community 170 - "FirewallInfo"
Cohesion: 0.22
Nodes (7): ProtectLoad, EngineState, Ready, Unavailable, WindowsFirewallOff, FirewallInfo, banner_text()

### Community 171 - "countries.rs"
Cohesion: 0.31
Nodes (6): by_a2(), Entry, table!, parse_a2(), parse_name_or_a2(), search()

### Community 172 - "Direction"
Cohesion: 0.22
Nodes (7): Answer, Allow, Block, Direction, In, Local, Out

### Community 174 - "SpeedResult"
Cohesion: 0.25
Nodes (5): SpeedResult, Db, results_are_read_back_in_order_and_pruned(), down(), up()

### Community 175 - "AlertLevel"
Cohesion: 0.25
Nodes (5): AlertLevel, .ALL, Important, Logs, AlertOpts

### Community 176 - "accent.rs"
Cohesion: 0.36
Nodes (3): dword(), windows_accent(), windows_dark()

### Community 177 - "instant"
Cohesion: 0.29
Nodes (5): GB, HISTORY_STEP, MB, run(), HW_WINDOW

### Community 178 - "RuleAction"
Cohesion: 0.25
Nodes (6): RuleAction, .ALL, Escalate, KeepLocal, Limit, Mute

### Community 179 - "ConnGroup"
Cohesion: 0.25
Nodes (7): ConnsState, ConnGroup, .ALL, Country, None, Process, State

### Community 180 - "HistoryData"
Cohesion: 0.29
Nodes (6): HistoryData, Alerts, Traffic, HistoryFormat, Csv, Json

### Community 181 - "hashmap"
Cohesion: 0.33
Nodes (5): BG, graph_pixels(), H, main(), PALETTE

### Community 182 - "Security Policy"
Cohesion: 0.29
Nodes (6): Design notes, Reporting a vulnerability, Scope, Security Policy, Supported versions, What to expect

### Community 183 - "AppGroup"
Cohesion: 0.29
Nodes (6): AppGroup, Active, .ALL, Inactive, Uninstalled, Windows

### Community 184 - "SpeedStatus"
Cohesion: 0.29
Nodes (3): SpeedStatus, RustWarden, status()

### Community 185 - "Threat"
Cohesion: 0.29
Nodes (3): only_the_made_up_threat_is_a_test(), Threat, .TEST_IP

### Community 186 - "ExtrasAct"
Cohesion: 0.29
Nodes (4): ExtrasAct, Pause, Resume, Unblock

### Community 187 - "AccountChange"
Cohesion: 0.29
Nodes (7): account_and_task_changes(), AccountChange, Activated, Created, Deactivated, Deleted, diff_accounts()

### Community 188 - "RuleSpec"
Cohesion: 0.38
Nodes (3): icmp_specs(), ping_rules_are_ours_allow_icmp_and_stay_off_the_program_list(), RuleSpec

### Community 189 - "AGENTS.md"
Cohesion: 0.33
Nodes (5): File updates, graphify, Project rules, Version control, Versioning

### Community 190 - "decode"
Cohesion: 0.33
Nodes (4): decode(), DNS_CLIENT, KERNEL_NETWORK, on_event()

### Community 191 - "path"
Cohesion: 0.47
Nodes (4): a_full_log_moves_aside_and_restarts(), append(), line(), MAX

### Community 192 - "NetInfoSource"
Cohesion: 0.33
Nodes (5): NetInfoSource, .ALL, Http, Off, TeamCymru

### Community 193 - "PlanDirection"
Cohesion: 0.33
Nodes (5): PlanDirection, .ALL, In, Out, Total

### Community 194 - "parse_dns"
Cohesion: 0.47
Nodes (6): dns_answer_maps_name_to_addresses(), dns_payload(), failed_lookup_is_logged_without_addresses(), parse_dns(), server_response_only_maps_names(), u32_le()

### Community 195 - "Manual checks on a real machine"
Cohesion: 0.33
Nodes (5): Automated, Elevated (use "Restart as administrator"), Manual checks on a real machine, Testing RustWarden, Unelevated (a normal user)

### Community 196 - "install_elevated"
Cohesion: 0.50
Nodes (4): ensure_recovery(), install_elevated(), remove_service(), set_recovery()

### Community 198 - "DeviceEvent"
Cohesion: 0.40
Nodes (5): DeviceEvent, MacChanged, MultiIp, New, Returned

### Community 200 - "parse_add"
Cohesion: 0.60
Nodes (5): Added, Denied, Failed, Uuid, parse_add()

### Community 201 - "Phase"
Cohesion: 0.40
Nodes (5): Phase, Download, Idle, Ping, Upload

### Community 202 - "plan-release.sh"
Cohesion: 0.83
Nodes (3): section(), plan-release.sh script, skip()

## Knowledge Gaps
- **369 isolated node(s):** `rustwarden`, `Mute`, `Escalate`, `KeepLocal`, `Limit` (+364 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1595 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **20 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Settings` connect `Settings` to `LiveBackend`, `toast.rs`, `MockBackend`, `pathbuf`, `QuotaStatus`, `live/store.rs`, `arc`, `Theme`, `browser.rs`, `baseline.rs`, `settings.rs`, `update.rs`, `dialogs.rs`, `Backend`, `external_notifications/mod.rs`, `RustWarden`, `data.rs`, `demo.rs`, `discord.rs`, `alerts.rs`, `.show_dialog`, `AlertLevel`, `rules_file.rs`, `asn.rs`, `report.rs`, `NetInfoSource`, `app.rs`, `Shared`, `thinkbroadband/ui.rs`, `Integration`, `alert_rules.rs`, `Dialog`, `external_notifications/ui.rs`, `protect.rs`?**
  _High betweenness centrality (0.093) - this node is a cross-community bridge._
- **Are the 8 inferred relationships involving `Settings` (e.g. with `.apply_settings()` and `.quotas()`) actually correct?**
  _`Settings` has 8 INFERRED edges - model-reasoned connections that need verification._
- **What connects `rustwarden`, `Mute`, `Escalate` to the rest of the system?**
  _369 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `live/firewall.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.037292025243832475 - nodes in this community are weakly interconnected._
- **Why does `Db` connect `Db` to `UsageEntry`, `toast.rs`, `LiveBackend`, `threat.rs`, `super`, `QuotaStatus`, `live/store.rs`, `arc`, `baseline.rs`, `db.rs`, `export.rs`, `live/apps.rs`, `FwController`, `pcap.rs`, `Scanner`, `thinkbroadband/store.rs`, `dest.rs`, `lease.rs`, `live/qos.rs`, `report.rs`, `monitors.rs`, `Scale`, `Shared`, `tab`, `ha/client.rs`, `latency.rs`, `quota.rs`, `thinkbroadband/ui.rs`, `domains.rs`, `Monitors`, `live/traffic.rs`, `vt.rs`, `Collector`, `.tick`, `Tbb`, `Domains`, `ordering`, `Vt`?**
  _High betweenness centrality (0.084) - this node is a cross-community bridge._
- **Are the 11 inferred relationships involving `Db` (e.g. with `.target_ranges()` and `.views()`) actually correct?**
  _`Db` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Should `LiveBackend` be split into smaller, more focused modules?**
  _Cohesion score 0.0379746835443038 - nodes in this community are weakly interconnected._