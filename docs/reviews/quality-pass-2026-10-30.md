# Quality pass, 2026-10-30

A second AI-assisted review of the Python package and CLI, run the way the
review in [security-review.md](../security-review.md) was: five finders
(verify and import, gateway security, CLI usability, silent failures,
performance) reported 44 findings against commit f737b96; two refuters for each
P0/P1 finding and one for each P2 tried to disprove it, most by reproducing it;
none was refuted, though most were downgraded. Fixers then changed the code, one
module group each, with a test for every fix. It is not an independent
assessment. The security-relevant findings are summarised in
[security-review.md](../security-review.md#quality-pass-2026-10-30).

| | Before (f737b96) | After |
|---|---|---|
| Tests collected | 1,344 | 1,478 (+134) |
| `pytest -q` | 1,337 passed, 6 skipped, 1 failed | 1,471 passed, 6 skipped, 1 failed |

The one failure is the same test before and after
(`tests/test_preflight.py::test_leaky_app_fails_with_attribution_and_fix`); it
depends on the macOS kernel sandbox log, which recorded no denials on the day,
so it comes from the environment, not from the pass. Done after the pass on the
same day: `ferry pack` refuses a version rollback protection cannot order, and
`docs/design/v1-spec.md` and `v1-additions.md` describe the new behaviour.

## Findings

44 findings from 5 finders. Each P0/P1 finding went to 2 refuters and each
P2 to 1. None was refuted; most were downgraded. Severity is shown as
finder's rating -> refuters' ratings.

| Id | Severity | File:line | Title | Verdict (refuter's reason) |
|---|---|---|---|---|
| VI-1 | P0 -> P1, P2 | ferry/formats.py:854 | A GGUF that is also a protocol-0 pickle is accepted as GGUF | confirmed: rebuilt a 6 MB polyglot that `parse_gguf` accepts and that `pickletools` reads as importing `os.system`; narrow impact because nothing unpickles a .gguf |
| VI-2 | P0 -> P1, P2 | ferry/bundle/importer.py:200 | `version_key` compares non-numeric parts as text (v10 < v9, 1.0.0rc1 > 1.0.0) | confirmed: signed v10.0.0 then a replayed v9.0.0 was accepted end to end with policy.rollback=pass |
| VI-3 | P1 -> P2, P2 | ferry/bundle/importer.py:268 | Rollback/version-reuse check runs outside the registering write transaction | confirmed with real threads: two concurrent imports of one version both registered; bundles has only PK(bundle_id) |
| VI-4 | P1 -> P2, P3 | ferry/bundle/importer.py:140 | Re-import keeps a same-size corrupted store file without re-hashing | confirmed: one flipped byte, re-import reported already_imported with nothing repaired; a recovery gap, not a bypass |
| VI-5 | P1 -> P2, P1 | ferry/bundle/reader.py:187 | Tar listing keeps every PAX/GNU long header in memory before size limits | confirmed with tracemalloc: per-read cap only, no total bound across members |
| VI-6 | P1 -> P2, P2 | ferry/bundle/importer.py:296 | `artifacts` rows are first-writer-wins, so a later bundle's signed kind/name/licence is lost | confirmed: INSERT OR IGNORE; the evidence report and the console showed the first bundle's declaration |
| VI-7 | P2 -> P3 | ferry/formats.py:321 | GGUF validation looser than llama.cpp (64-byte names, gaps, out-of-order tensors) | confirmed against llama.cpp 0.7.0: it refuses all three; Ferry accepted them |
| VI-8 | P2 -> P3 | ferry/formats.py:623 | Nested-archive detection misses ar, cpio, v7 tar, .Z, lzip | confirmed: `_archive_magic` is a closed list; these came out as text/binary |
| VI-9 | P2 -> P3 | ferry/bundle/importer.py:262 | Failures after verification are not audited and leave placed files | confirmed: only `verify_bundle` sat inside the `_audit_failure` handler |
| VI-10 | P2 -> P3 | ferry/trust.py:233 | Trust store checks mode bits but not ownership | confirmed: `st_uid` was never read; exploiting it needs a misconfiguration or an existing foothold |
| VI-11 | P2 -> P3 | ferry/bundle/verify.py:325 | Size-limit rejections do not name the setting | confirmed with a sparse 120 GiB member: the messages named no setting |
| GWS-1 | P0 -> P2, P2 | ferry/gateway/admin_api.py:157 | Login throttle is check-then-act; concurrent guesses bypass 5-per-user | confirmed over real HTTP: 20 concurrent guesses all got a password check; not P0 because scrypt cost and the lock after the burst still apply |
| GWS-2 | P1 -> P3, P2 | ferry/cli.py:1015 | uvicorn trusts X-Forwarded-For/-Proto from loopback | confirmed with real `ferry serve`: a local client sets `client_ip` (throttle key, audit); needs local access |
| GWS-3 | P1 -> P2, P2 | ferry/policy.py:325 | Policy warning computation is quadratic and unbounded | confirmed: under 1 MiB of policy took minutes; only the output was capped, not the work |
| GWS-4 | P1 -> P2, P3 | ferry/gateway/openai_api.py:692 | Streamed completions delivered when their audit write fails | confirmed with a locked/readonly DB: the stream got 200 while non-stream got 500; needs a DB write fault |
| GWS-5 | P2 -> P3 | ferry/auth.py:598 | Expired console sessions never purged | confirmed: `purge_expired_sessions` is called only from a test; hygiene |
| cli-ux-1 | P1 -> P2, P2 | ferry/backup.py:271 | Restored ferry.toml keeps the old absolute data_dir | confirmed: `--config restored/ferry.toml` ran against the original installation |
| cli-ux-2 | P1 -> P2, P3 | ferry/backup.py:130 | backup.create recorded as success before the archive is written | confirmed: an unwritable --out left a committed success event |
| cli-ux-3 | P1 -> P2, P3 | ferry/cli.py:930 | audit checkpoint recorded before --out is written | confirmed: on a failed write the evidence report cited a checkpoint that does not exist; the operator still sees exit 2 |
| cli-ux-4 | P1 -> P3, P2 | ferry/cli_offline.py:142 | preflight/rehearse write --out/--md only after the run | confirmed: a bad path threw away a finished run; usability only |
| cli-ux-5 | P1 -> P3, P3 | ferry/cli_offline.py:134 | Invalid --request-json gives "internal error (JSONDecodeError)" | confirmed: a ValueError fell through to the catch-all |
| cli-ux-6 | P1 -> P3, P3 | ferry/cli_offline.py:203 | rehearse rejects --data-dir after the command name | confirmed: subparser built without `parents=[common]` |
| cli-ux-7 | P2 -> P3 | ferry/cli_offline.py:162 | rehearse --require-role accepts unknown roles | confirmed: no SIGNER_ROLES check, so the error showed up as a misleading verify failure |
| cli-ux-8 | P2 -> P3 | ferry/cli.py:1284 | Integrity refusals exit 2 instead of 1 | confirmed: a damaged backup and a fingerprint mismatch exited 2 |
| cli-ux-9 | P2 -> P3 | ferry/cli.py:448 | No progress output for multi-GB hashing | confirmed: no progress callback wired in the CLI; UX only |
| cli-ux-10 | P2 -> P2 | ferry/preflight.py:638 | Preflight Markdown joins the command with spaces | confirmed: copied command was wrong for quoted arguments |
| cli-ux-11 | P2 -> P3 | demo/run-demo.sh:26 | Demo expect_fail treats exit 2 as the expected rejection | confirmed the code properties; neither failure happens in the current tree |
| SF-1 | P0 -> P2, P1 | ferry/bundle/importer.py:269 | Rollback/version-reuse checks outside the registering transaction (same as VI-3) | confirmed: reproduced the concurrent double registration |
| SF-2 | P1 -> P2, P2 | ferry/backup.py:141 | Live backup hashes, then re-reads files for the tar | confirmed: a file changed in between gave a backup whose manifest does not match it |
| SF-3 | P1 -> P2, P2 | ferry/bundle/importer.py:140 | Re-import does not repair a same-size corrupted store file (same as VI-4) | confirmed via API and real CLI |
| SF-4 | P1 -> P2, P2 | ferry/gateway/openai_api.py:692 | Streamed completions delivered without an audit event (same as GWS-4) | confirmed: `_StreamRelay.close()` logged and swallowed the failure |
| SF-5 | P1 -> P2, P2 | ferry/gateway/security.py:344 | Internal errors logged with only the exception class | confirmed: disk-full and locked could not be told apart in the log; an operability gap |
| SF-6 | P2 -> P2 | ferry/bundle/store.py:132 | Staging files from a killed import never cleaned up | confirmed: stage-* files survived and `store verify` text hid them |
| SF-7 | P2 -> P2 | ferry/backends.py:1013 | Health pass has no total deadline; availability ignores status age | confirmed: a trickling backend stalled the health loop |
| SF-8 | P2 -> P2 | ferry/gateway/admin_api.py:755 | audit.export records a head that is not the last exported event | confirmed: `head()` read a newer snapshot after the export |
| SF-9 | P2 -> P2 | ferry/backup.py:130 | Backup/checkpoint audited as success before the artifact exists; tar renamed unsynced | confirmed: false success event and no fsync |
| SF-10 | P2 -> P3 | ferry/cli.py:387 | `ferry verify --trust-dir/--require-role` records the overridden verdict as the host's | confirmed: the inbox and evidence report showed the override's verdict |
| SF-11 | P2 -> P3 | ferry/rehearse.py:212 | Outer subprocess timeout kills the runner and leaves the runtime running | confirmed: `run()` SIGKILLs only the direct child; the trigger is narrow |
| integrity-1 | P1 -> P2, P3 | ferry/bundle/importer.py:140 | Re-import does not repair a same-size corrupted store file (same as VI-4) | confirmed: one flipped bit kept the corrupt file |
| perf-1 | P1 -> P2, P2 | ferry/evidence.py:135 | Every GET /api/evidence re-verifies the whole audit chain | confirmed: O(total events) per request in a sync handler, for any role |
| perf-2 | P1 -> P2, P2 | ferry/gateway/admin_api.py:841 | Overview traffic summary scans every chat event | confirmed: single-column indexes only, so the query planner scanned all chat rows |
| perf-3 | P2 -> P3 | ferry/audit.py:330 | Audit facets and resource/actor_type filters scan the table | confirmed: SELECT DISTINCT with no index |
| perf-4 | P2 -> P3 | ferry/backup.py:141 | Backup reads every model file twice | confirmed: hash pass plus tar pass |
| perf-5 | P2 -> P3 | ferry/bundle/verify.py:500 | Import keeps staging after rejection; no free-space check | confirmed: rejected bundles still filled staging |

## Fixes and covering tests

| Id | What changed | Covering tests |
|---|---|---|
| VI-1 | `detect_format` runs the header-less pickle scan on a valid GGUF and returns `pickle` with `polyglot: gguf` | `tests/test_formats.py::test_gguf_headerless_pickle_polyglot_is_pickle`, `::test_gguf_headerless_pickle_polyglot_in_a_bundle_is_rejected_on_pickle_policy` |
| VI-2 | `version_key` parses versions: optional `v`, integer core, a letter suffix on the last part becomes a pre-release, build ignored, natural ordering within pre-release identifiers. A non-numeric core raises `UnorderableVersion`, which fails `policy.rollback` even with `--allow-downgrade` | `tests/test_bundle_rollback.py::test_version_order`, `::test_v10_is_newer_than_v9_so_a_replayed_v9_is_a_rollback`, `::test_the_final_release_after_its_release_candidate_is_an_upgrade`, `::test_an_unorderable_version_is_refused_even_with_allow_downgrade` |
| VI-3 / SF-1 | History check repeated inside the `BEGIN IMMEDIATE` registration transaction (`_register`); a conflict is recorded as a rejection; newly placed files are removed unless registered elsewhere; `_restore_missing` puts back files that a concurrent failed import removed | `tests/test_bundle_rollback.py::test_concurrent_imports_of_one_version_register_only_one`, `::test_a_concurrent_newer_import_makes_the_older_one_a_rollback`, `tests/test_bundle_import.py::test_concurrent_same_version_import_is_rejected` |
| VI-4 / SF-3 / integrity-1 | `_place` keeps an existing file only if it is regular, mode 0444 and hashes to its digest; otherwise it is replaced from the verified staged copy and listed in `repaired` and in the audit event | `tests/test_bundle_import.py::test_same_size_damaged_store_file_is_repaired`, `::test_reimport_repairs_bit_rot_and_a_writable_store_file` |
| VI-5 | `HEADER_READ_CAP` 64 KiB per header, `HEADER_TOTAL_CAP` 16 MiB in total, PAX records dropped after use, `RecursionError` reported as `archive.readable` | `tests/test_bundle_verify.py::test_oversized_pax_headers_are_refused_while_listing`, `::test_many_pax_headers_under_the_per_header_cap_are_refused_in_total`, `::test_chained_extended_headers_are_refused_cleanly`, `::test_pax_records_are_not_kept_after_listing`, `::test_long_paths_still_read` |
| VI-6 | The newest import that declares the bytes as a model sets kind/model_name/metadata; a later document declaration does not demote a model; `evidence._bundles` reads each bundle's own signed manifest | `tests/test_bundle_import.py::test_same_bytes_declared_differently_in_two_bundles`, `::test_bytes_first_shipped_as_a_document_can_later_be_a_model` |
| VI-7 | Tensor-name limit 63 bytes; with known ggml types, tensor offsets must be contiguous and in order (problems, not warnings); unused trailing bytes are still a warning | `tests/test_formats.py::test_gguf_layouts_llama_cpp_refuses_are_problems`, `::test_gguf_contiguous_tensors_have_no_problems`, `::test_gguf_tensor_name_length_limit` |
| VI-8 | `_archive_magic` detects ar, cpio (newc/odc/binary), compress, lzip, cab and xar; `_tar_checksum_ok` detects v7 tar | `tests/test_formats.py::test_more_archive_containers`, `::test_v7_tar_sample_is_a_real_tar`, `::test_ar_archive_declared_as_document_is_rejected_on_archive_policy` |
| VI-9 | Everything after verification runs under a `BaseException` handler that removes newly placed objects and writes a `bundle.import` error event (step, error, code, removed_digests) | `tests/test_bundle_import.py::test_registration_failure_is_audited`, `::test_store_failure_is_audited_and_undone` |
| VI-10 | Trust directory and entries must be owned by the effective uid or by root (checked with fstat); anything else is ignored, and the problem message gives the `chown` fix | `tests/test_trust.py::test_entry_owned_by_another_user_is_ignored`, `::test_directory_owned_by_another_user_trusts_nothing`, `::test_root_owned_entries_and_directory_are_trusted` |
| VI-11 | Limit messages end with the setting, e.g. `([import].max_artifact_bytes)`; same in manifest schema bounds | `tests/test_bundle_verify.py::test_limit_messages_name_the_setting`, `::test_manifest_schema_bounds_name_the_setting` |
| GWS-1 | `LoginThrottle.begin/finish` count in-flight checks under the lock (5 per user, 20 per IP); scrypt runs under a `BoundedSemaphore(4)` | `tests/test_app_admin_api.py::test_login_throttle_holds_under_concurrency`, `::test_throttle_begin_and_finish_count_in_flight_attempts`, `::test_concurrent_password_checks_are_bounded` |
| GWS-2 | `[server] trusted_proxies` (default empty, validated as IPs or networks); uvicorn `proxy_headers` only when it is set; `docs/deployment.md` updated | `tests/test_cli.py::test_serve_ignores_forwarded_headers_unless_a_proxy_is_trusted` |
| GWS-3 | Set-based coverage (`_PatternSet`), `_find_shadow` budget of 5,000,000 comparisons with one note when it runs out, early stop once output is truncated, warnings past the cap counted rather than stored | `tests/test_policy.py::test_validate_large_policy_is_bounded`, `::test_validate_endpoint_is_bounded_for_the_auditor`, `::test_shadow_budget_exhaustion_is_reported_once`, `::test_budget_note_survives_truncation`, `::test_ordinary_large_policy_is_fully_analysed`, `::test_shadow_search_stops_once_output_is_truncated`, `::test_set_based_coverage_matches_pairwise_definition` |
| GWS-4 / SF-4 | A `gateway.chat.stream_opened` event is committed before the first byte; on failure the request gets 500 "response withheld" and the lease is released; audit failure logs carry the SQLite message | `tests/test_gateway_openai.py::test_completion_withheld_when_audit_unwritable[True]`, `::test_stream_records_an_opening_event_before_relaying`, `::test_non_stream_writes_no_opening_event`, `::test_stream_whose_closing_write_fails_still_leaves_a_trace` |
| GWS-5 | `create_session` purges expired sessions (expires_at, idle limit, absolute limit) in its own transaction | `tests/test_auth.py::test_login_purges_expired_sessions`, `::test_login_keeps_live_sessions_and_purges_past_absolute_limit` |
| cli-ux-1 | `restore_backup` rewrites the top-level `data_dir` of the restored ferry.toml to the restore target, or warns when it cannot | `tests/test_backup.py::test_restored_config_points_at_the_restored_directory`, `::test_restore_warns_when_it_cannot_retarget_the_config` |
| cli-ux-2 | Tmpdir created before anything is recorded; every later failure appends `backup.create` outcome=failure | `tests/test_backup.py::test_backup_to_an_unwritable_directory_records_no_success`, `::test_disk_full_during_the_tar_write_is_audited_as_failure`, `::test_unreadable_member_is_audited_as_failure` |
| cli-ux-3 | `cmd_audit_checkpoint` writes --out/stdout first, then appends `audit.checkpoint` in the same session (the backup fixer's "already done at HEAD" note was wrong: at f737b96 the event came first; the cli group fixed it) | `tests/test_cli.py::test_a_checkpoint_that_cannot_be_written_is_not_recorded` |
| cli-ux-4 | --out/--md validated before the run; the verdict is printed before the files are written; a late write error keeps the verdict and exits 2 | `tests/test_preflight.py::test_a_missing_out_directory_fails_before_the_run`, `::test_a_valid_out_is_written_after_the_verdict_is_printed`, `::test_a_late_write_error_still_shows_the_verdict` |
| cli-ux-5 | --request-json read with `cli._read_json_file`; bad JSON is a usage error (exit 2) | `tests/test_preflight.py::test_an_invalid_request_json_is_a_usage_error` |
| cli-ux-6 | `--data-dir` on the rehearse subparser (`default=SUPPRESS`), `--config-data-dir` kept as a hidden alias | `tests/test_rehearse.py::test_rehearse_accepts_data_dir_after_the_command_name`, `::test_rehearse_keeps_a_global_data_dir_given_before_the_command_name`, `::test_rehearse_data_dir_selects_the_import_policy` |
| cli-ux-7 | `--require-role` checked against SIGNER_ROLES before any work; duplicates removed | `tests/test_rehearse.py::test_rehearse_unknown_role_is_a_usage_error_before_any_import`, `::test_rehearse_repeated_role_is_required_once` |
| cli-ux-8 | `backup_rejected` and `fingerprint_mismatch` exit 1 with `ferry: rejected:` | `tests/test_cli.py::test_integrity_refusals_exit_1_and_io_errors_exit_2` |
| cli-ux-9 | `_ProgressMeter`, shown only on a TTY without --json, wired into pack, sign, verify, import, store verify and rehearse | `tests/test_cli.py::test_verify_shows_hashing_progress_only_on_a_terminal`, `::test_progress_meter_throttles_and_ends_its_line` |
| cli-ux-10 | Preflight Markdown shows `shlex.join(argv)` in a fenced block; table cells escaped | `tests/test_preflight.py::test_markdown_command_is_the_exact_argv`, `::test_markdown_table_cells_survive_pipes_and_newlines` |
| cli-ux-11 | `expect_fail` requires exit 1; the two-signer edit asserts and re-loads the config | `tests/test_cli.py::test_demo_expect_fail_accepts_only_a_rejection`, `::test_demo_two_signer_edit_matches_the_default_config` |
| SF-2 | Config, trust and secrets copied and hashed in one read; each member re-hashed while it is written to the tar; the archive is read back before `os.replace` | `tests/test_backup.py::test_trust_change_during_backup_still_gives_a_restorable_archive` |
| SF-5 | `errors.operator_detail`/`operator_traceback` in the 500 log, failed-job log and importer `_audit_failure` (no request data) | `tests/test_app_security.py::test_unhandled_errors_log_the_system_text_and_the_stack`, `::test_unhandled_error_logs_keep_other_exception_text_out`, `::test_operator_detail_names_os_errors_without_the_file_name`, `::test_a_failed_job_logs_its_source_and_the_system_text`, `::test_a_failed_import_audit_is_logged` |
| SF-6 | `store.import_lock()` (shared flock); leftover stage-* files swept on entry when no other import runs; `verify_store` warns about leftover staging and untracked files | `tests/test_bundle_import.py::test_leftover_staging_files_are_swept_and_reported`, `::test_verify_store_warns_about_untracked_files` |
| SF-7 | `check_backend` under a 2 x HEALTH_TIMEOUT_S deadline; statuses older than 3 x health_interval count as unchecked in gateway routing | `tests/test_backends.py::test_a_trickling_backend_cannot_stall_the_health_pass`, `::test_status_max_age_follows_the_health_interval`, `::test_stale_or_undated_statuses_count_as_unchecked`, `::test_route_views_report_stale_statuses_when_asked`, `::test_gateway_refuses_a_route_whose_status_went_stale` |
| SF-8 | `audit.export` returns the head of what it wrote; used by the API and the CLI | `tests/test_audit.py::test_export_reports_the_head_of_what_it_wrote`, `::test_export_of_an_empty_log_reports_the_genesis_head`, `::test_api_export_record_names_the_last_exported_event`, `::test_cli_export_record_names_the_last_exported_event` |
| SF-9 | `backup.create` accepted -> success after `os.replace` (or failure); tar and parent directory fsynced | `tests/test_backup.py::test_successful_backup_is_audited_after_the_archive_exists`, `::test_backup_tar_is_fsynced_before_it_is_renamed` |
| SF-10 | Verify with --trust-dir/--require-role on a host runs standalone, with no verification row and no history update; one audit event with `host_verdict=false` | `tests/test_cli.py::test_verify_overrides_on_a_host_are_not_recorded_as_the_host_verdict` |
| SF-11 (rehearse) | Runner started with Popen in its own session; outer budget derived from the inner limits; SIGTERM then SIGKILL to the group; the runner handles SIGTERM and stops llama-server | `tests/test_rehearse.py::test_runner_timeout_leaves_no_runtime_running`, `::test_runner_budget_covers_every_inner_limit` |
| perf-1 | `build_evidence` verifies only the events after the last recorded full verification (`verify_chain(start=...)`); details encoded once per row | `tests/test_evidence.py::test_evidence_checks_only_events_after_the_last_full_verification`, `::test_evidence_catches_changes_at_and_after_the_verified_head`, `::test_verify_chain_from_a_start_point`, `::test_compute_hash_with_preencoded_details_matches_the_plain_form`, `::test_a_failed_verification_without_a_broken_event_falls_back_to_a_full_pass` |
| perf-2 | Migration v2: `idx_audit_action_ts`; `idx_audit_action` kept on purpose (newest-first filtered pages need it) | `tests/test_audit.py::test_traffic_summary_searches_the_action_ts_index`, `::test_a_v1_database_is_upgraded_to_v2_with_the_same_traffic_summary` |
| perf-3 | Facets by index skip-scan; `idx_audit_resource_seq`, `idx_audit_actor_type_seq` | `tests/test_audit.py::test_facets_list_every_value_present_including_off_vocabulary_ones`, `::test_facets_of_an_empty_log`, `::test_facets_and_filtered_pages_do_not_scan_the_log` |
| perf-4 | Store members read once (digest from the name, hashed while streamed); a corrupt store file aborts the backup with `store_corrupt` | `tests/test_backup.py::test_store_files_are_read_once`, `::test_corrupt_store_file_aborts_the_backup` |
| perf-5 | After a failed check, later artifacts are hashed but not staged; free space checked before staging (`insufficient_space`) | `tests/test_bundle_import.py::test_rejected_bundle_stops_staging`, `::test_insufficient_space_fails_before_staging` |

Fixers checked that their new tests fail against the f737b96 copy of the
module and pass with the fix. Some new tests are guards that pass both before
and after, e.g. `test_pax_records_are_not_kept_after_listing` and
`test_long_paths_still_read`.

## Behaviour changes

- Bundle versions without a numeric core (`latest`, `1.x`, `1.0.post1`) are
  now refused by `ferry pack` and at verify/import (`policy.rollback`), even
  with `--allow-downgrade`. `v1.0.0`, `1.0.0`, `1.0` and `1.0.0.0` count as the
  same release. Rows from before this change that have such versions are
  skipped when ordering.
- GGUF files with 64-byte tensor names, or with gaps between tensors or
  tensors out of order, are now problems (previously accepted or warned).
- Re-import re-hashes every store file that is already present. That costs
  one extra read per artifact.
- A trust store owned by another user trusts nothing.
- A new migration (schema v2) adds three audit indexes.
- `ferry init` writes `trusted_proxies = []`. A reverse-proxy deployment must
  list the proxy to keep `X-Forwarded-*`.
- Streamed requests write one extra audit event (`gateway.chat.stream_opened`).
- Integrity refusals in restore and fingerprint checks exit 1, not 2.
- `ferry verify --trust-dir/--require-role` on a configured host no longer
  writes a verification row.

## Left undone, with the reason

| Item | Reason |
|---|---|
| SF-11, preflight half: `ferry preflight`'s outer runner timeout can be shorter than its inner limits and leaves the command running | `ferry/preflight.py` belonged to another group, which was editing it at the time; recorded in `docs/limitations.md` |
| VI-6, rest: `/api/bundles/{id}` and the runtime name lookup still read the shared artifacts row (an older bundle's page shows the newer name and licence; the old name stops resolving) | `gateway/admin_api.py` and `runtime.py` belonged to other groups; recorded in `docs/limitations.md` |
| GWS-4 residual: if the closing write fails after delivery, the request has only the opening event, and traffic metrics leave it out | Deliberate design (an opening event plus one closing event, so traffic is not double-counted); recorded in `docs/limitations.md` |
| GWS-3 residual: shadow analysis is skipped once it uses up its budget on very large policies | Deliberate bound; recorded in `docs/limitations.md` |
| GWS-5: no session purge at startup or on the health loop | `gateway/app.py` and `backends.py` belonged to other groups; purging on each login keeps the table bounded |
| SF-1 backstop: no UNIQUE index on normalized versions | Needs a normalized column and a migration; the re-check under `BEGIN IMMEDIATE` is enough because writers are serialized |
| SF-6: no sweep in the app lifespan, no doctor check, no CLI test | The files belonged to other groups; each import already sweeps on entry |
| perf-2: three traffic queries not folded into one | Each is already an indexed range search |
| VI-10: parent-directory writability not checked | Kept the fix minimal; a replacement directory made by another user is rejected by the ownership check |
| cli-ux-10, rehearsal Markdown cells not escaped | `ferry/rehearse.py` was being edited by another group |
| Ruff not green (203 errors left, all from before the pass) | Out of scope; would need a `[tool.ruff]` config choice (e.g. ignore B008 for FastAPI) |
| `test_leaky_app_fails_with_attribution_and_fix` fails in this session | Environmental (macOS sandbox log recorded no denials); fails the same way on clean f737b96; rerun on a quiet host |
