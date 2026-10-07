use std::fs;
use std::path::Path;

// WO-23: deterministic source-contract tests for the macOS ES gate core.
fn repo_file(path: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

#[test]
fn main_selects_macos_gate_module() {
    let source = repo_file("src/main.rs");
    assert!(source.contains(r#"#[cfg(target_os = "macos")]"#));
    assert!(source.contains(r#"#[path = "gate_macos.rs"]"#));
    assert!(source.contains(r#"not(any(target_os = "linux", target_os = "macos"))"#));
}

#[test]
fn rust_launcher_fails_closed_until_es_edge_is_ready() {
    let source = repo_file("src/gate_macos.rs");
    for needle in [
        "BULWARK_MACOS_ES_GATE",
        "libc::SIGSTOP",
        "wait_for_ready",
        "libc::SIGCONT",
        "ES edge exited while child was running",
        "seed_denylist_decisions",
        "allow_once",
        "allow_session",
    ] {
        assert!(source.contains(needle), "gate_macos.rs missing {needle}");
    }
}

#[test]
fn swift_edge_decides_by_inode_and_tracks_supervised_tree() {
    let source = repo_file("macos-es-proof/es_gate.swift");
    for needle in [
        "st_dev",
        "st_ino",
        "ES_EVENT_TYPE_AUTH_OPEN",
        "ES_EVENT_TYPE_NOTIFY_FORK",
        "ES_EVENT_TYPE_NOTIFY_EXEC",
        "ES_EVENT_TYPE_NOTIFY_EXIT",
        "supervisedPids",
        "allowOnce",
        "operator allowed once",
        "es_respond_flags_result(clientPtr, message, 0, false)",
        "es_respond_flags_result(clientPtr, message, UInt32.max, cacheKernelAllow)",
        "ES_RESPOND_RESULT_SUCCESS",
    ] {
        assert!(source.contains(needle), "es_gate.swift missing {needle}");
    }
    assert!(
        !source.contains("String(cString:"),
        "ES edge must not parse kernel path tokens as null-terminated strings"
    );
}

// WO-127: the edge must convert Darwin's Int32 dev_t without trapping and must
// land on the same key Rust derives, or devfs opens kill the client and the
// kernel allows every later read.
#[test]
fn swift_edge_sign_extends_dev_and_flushes_receipts_before_exit() {
    let source = repo_file("macos-es-proof/es_gate.swift");
    assert!(
        source.contains("UInt64(bitPattern: Int64(st.st_dev))"),
        "edge must sign-extend st_dev through Int64"
    );
    assert!(
        !source.contains("UInt64(st.st_dev)"),
        "the trapping UInt64(st.st_dev) conversion must be gone"
    );
    assert!(
        !source.contains("WO-127 AUTH_OPEN raw"),
        "the capture-only diagnostic hunk must not ship"
    );
    // In-flight-aware shutdown must guard BOTH exit paths: the tree-drain exit
    // and the SIGINT/SIGTERM source the Rust supervisor uses to stop the edge.
    // A flush that timed out must not exit clean: flushForExit() reports whether
    // the in-flight decisions drained, and both exits turn a false into the
    // dedicated non-zero code the supervisor treats as abnormal.
    assert!(source.contains("func flushForExit() -> Bool"));
    assert!(source.contains("func flushReceipts()"));
    assert!(source.contains("let exitReceiptsIncomplete: Int32 = 71"));
    let exit_expr = "exit(flushForExit() ? 0 : exitReceiptsIncomplete)";
    let drain_exit = between(&source, "func scheduleDrainExit()", "var allowOnce");
    assert!(
        drain_exit.contains(exit_expr),
        "drain exit must flush and fail on timeout"
    );
    let signal_exit = between(&source, "DispatchSource.makeSignalSource", "dispatchMain()");
    assert!(
        signal_exit.contains(exit_expr),
        "signal exit must flush and fail on timeout"
    );
    // The wait is bounded well inside the supervisor's SIGTERM-to-SIGKILL window.
    let wait_decl = between(&source, "let shutdownWait", "\n");
    assert!(
        wait_decl.contains(".milliseconds(400)"),
        "shutdownWait must be 400 ms; got {wait_decl}"
    );
    // Only tree-relevant decisions are counted in flight (the client sees every
    // open on the host); the guard is the same on enter and on leave.
    let auth_open = between(&source, "case ES_EVENT_TYPE_AUTH_OPEN:", "default:");
    assert!(auth_open.contains("let tracked = membership != .outside"));
    let enter = between(auth_open, "if tracked {", "}");
    assert!(
        enter.contains("authInFlight.enter()"),
        "enter must be guarded by tracked"
    );
    let leave = between(auth_open, "defer {", "let allow: Bool");
    assert!(
        leave.contains("if tracked"),
        "leave must be guarded by tracked"
    );
    assert!(leave.contains("authInFlight.leave()"));
    // Unknown ancestry on a protected open fails closed in deny-list mode: a
    // failed parent lookup is not proof the opener is outside the tree.
    let denylist = between(&source, "case .denylist:", "case .allowlist:");
    assert!(
        denylist.contains(".unknown"),
        "deny-list branch must test .unknown"
    );
    assert!(denylist.contains(r#"source = "edge-error""#));
    let unknown_branch = between(denylist, ".unknown", "} else if");
    assert!(
        unknown_branch.contains("allow = false"),
        "unknown ancestry must DENY"
    );
    // A failed kernel response is receipted and the edge exits non-zero, which
    // the supervisor treats as abnormal.
    let respond_failure = between(
        &source,
        "if rr != ES_RESPOND_RESULT_SUCCESS",
        "let path = pathForReceipt",
    );
    assert!(respond_failure.contains("kernel response failed"));
    assert!(respond_failure.contains(r#"source: "edge-error""#));
    assert!(respond_failure.contains("flushReceipts()"));
    assert!(respond_failure.contains("exit(70)"));
}

// WO-127: the source slice between two unique markers, so a contract test pins
// WHERE a call sits (drain exit vs signal handler), not just that it exists.
fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let s = source
        .find(start)
        .unwrap_or_else(|| panic!("marker {start:?} not found"));
    let rest = &source[s..];
    let e = rest
        .find(end)
        .unwrap_or_else(|| panic!("marker {end:?} not found after {start:?}"));
    &rest[..e]
}

// WO-127: pins the Rust convention the edge now matches: std sign-extends the
// 32-bit Darwin dev_t into the u64 key, so a negative devfs dev stays a stable key.
#[cfg(target_os = "macos")]
#[test]
fn rust_dev_key_is_the_sign_extended_darwin_dev_t() {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata("/dev/null").unwrap();
    let path = std::ffi::CString::new("/dev/null").unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::stat(path.as_ptr(), &mut st) }, 0);
    let raw: i32 = st.st_dev;
    assert_eq!(
        meta.dev(),
        (raw as i64) as u64,
        "MetadataExt::dev() must be the sign-extension of the raw dev_t {raw}"
    );
}

// WO-127: an edge that died by a signal after the child finished used to be
// reported as a normal run; the supervisor must name it and fail.
#[test]
fn rust_supervisor_reports_abnormal_edge_exit_after_child_exit() {
    let source = repo_file("src/gate_macos.rs");
    for needle in [
        "ES edge exited abnormally",
        "ES edge exited while child was running",
        r#"source: "integrity""#,
    ] {
        assert!(source.contains(needle), "gate_macos.rs missing {needle}");
    }
}

#[test]
fn behavior_matrix_documents_macos_linux_divergences() {
    let doc = repo_file("docs/macos-behavior-matrix.md");
    for needle in [
        "Symlink",
        "Hardlink",
        "Socket consent verdicts",
        "Default-deny allow list",
        "mmap",
        "Deadline",
        "Crash-safe floor",
        "No Landlock analog",
        "host",
    ] {
        assert!(doc.contains(needle), "behavior matrix missing {needle}");
    }
}

#[test]
fn macos_quickstart_documents_operator_surface() {
    let doc = repo_file("docs/macos.md");
    for needle in [
        "BULWARK_MACOS_ES_GATE",
        "bulwark doctor --format json",
        "bulwark run",
        "--protect",
        "--receipts",
        "allow-once",
        "allow-session",
        "deny-forever",
        "bulwark audit",
        "bulwark base-set",
    ] {
        assert!(doc.contains(needle), "macOS quickstart missing {needle}");
    }
}

#[test]
fn ci_compiles_macos_rust_and_documents_swift_link_check() {
    let workflow = repo_file(".github/workflows/ci.yml");
    for needle in [
        "x86_64-apple-darwin",
        "cargo check --target x86_64-apple-darwin",
        "macOS Swift ES edge compile",
        "BULWARK_MACOS_SWIFT_CI",
        "es_proof.swift -lEndpointSecurity -lbsm",
        "es_gate.swift -lEndpointSecurity -lbsm",
    ] {
        assert!(workflow.contains(needle), "CI workflow missing {needle}");
    }
}

#[test]
fn allowlist_gate_has_sealed_hardware_harness() {
    let source = repo_file("macos-es-proof/verify-allowlist-gate.sh");
    for needle in [
        "WO-41",
        "RUN ON THE INTEL MAC",
        "bulwark run",
        "--deny-all",
        r#"--allow "$ALLOW_DIR/**""#,
        "SYMLINK_ESCAPE_DENIED",
        "HARDLINK_OUTSIDE_DENIED",
        "NO_PROMPT_OK",
        "EDGE_ALLOWLIST_OK",
        "SUP_STATUS",
        "LOAD_STATUS",
        "allowlist-supervised.err",
        "gate edge does not contain allow-list support",
        "seq 1 1200",
        "test5_base_set_launch",
        "verdict:               SEALED",
    ] {
        assert!(
            source.contains(needle),
            "allow-list harness missing {needle}"
        );
    }
}

#[test]
fn macos_socket_consent_keeps_peer_pid_and_process_tree_checks() {
    let socket = repo_file("src/socket.rs");
    let proctree = repo_file("src/proctree.rs");
    for needle in ["LOCAL_PEERPID", "SOL_LOCAL"] {
        assert!(socket.contains(needle), "socket.rs missing {needle}");
    }
    for needle in ["proc_pidinfo", "PROC_PIDTBSDINFO", "proc_name"] {
        assert!(proctree.contains(needle), "proctree.rs missing {needle}");
    }
}

// WO-128@v2: allow-list mode must not treat an unknown ancestry as outside the
// tree. The first hop comes from the ES message (parent_audit_token when the
// message version is >= 4, else ppid; original_ppid for a reparented process)
// before any proc_pidinfo walk, a walk that stopped on a failed lookup is
// retried once, and what is still unknown is DENIED with source edge-error.
// Deny-list mode keeps the WO-127 walk, so its decisions do not move.
#[test]
fn swift_edge_allowlist_denies_unknown_ancestry_after_message_first_hop() {
    let source = repo_file("macos-es-proof/es_gate.swift");
    // (b) the allow-list unknown branch denies; the WO-128@v1 instrument is gone.
    let allowlist = between(&source, "case .allowlist:", "// WO-23: AUTH_OPEN requires");
    assert!(
        !allowlist.contains("treated as outside"),
        "the measurement instrument must be replaced by the deny"
    );
    let unknown = between(allowlist, "membership == .unknown", "} else if");
    assert!(
        unknown.contains("allow = false"),
        "allow-list unknown ancestry must DENY; got: {unknown}"
    );
    assert!(unknown.contains(r#"source = "edge-error""#));
    assert!(unknown.contains("ancestry could not be established (denied, allow-list mode)"));
    assert!(unknown.contains("cacheKernelAllow = false"));
    // The outside branch keeps its reasons.
    assert!(allowlist.contains(
        r#"reason = allowedByPolicy ? "allowed inode opened outside supervised tree" : "outside supervised tree""#
    ));
    // (a) the first hop comes from the message, version check included, before
    // any proc_pidinfo walk; the resolver itself never calls proc_pidinfo.
    let resolver = between(&source, "func allowlistAncestry(", "\n}\n");
    let walk = resolver
        .find("walkParents(")
        .expect("the resolver must use the WO-127 walk");
    for needle in [
        "parent_audit_token",
        "version >= 4",
        ".ppid",
        "original_ppid",
    ] {
        let at = resolver
            .find(needle)
            .unwrap_or_else(|| panic!("first hop must read {needle}"));
        assert!(at < walk, "{needle} must be read before the walk");
    }
    assert!(
        !resolver.contains("proc_pidinfo"),
        "the resolver must not look a pid up itself; only the walk does"
    );
    // AUTH_OPEN hands the message (process + version) to the resolver in
    // allow-list mode only; deny-list membership is the unchanged WO-127 walk.
    let auth_open = between(&source, "case ES_EVENT_TYPE_AUTH_OPEN:", "default:");
    assert!(
        auth_open
            .contains("allowlistAncestry(msg.process, version: msg.version, root: config.rootPid)"),
        "allow-list AUTH_OPEN must resolve from the message"
    );
    assert!(
        auth_open.contains(": ancestryOf(eventPid, root: config.rootPid)"),
        "deny-list membership must keep the WO-127 walk"
    );
    // (c) exactly one retry, and only for a failed lookup, never for depth.
    assert_eq!(
        resolver.matches("walkParents(start").count(),
        2,
        "the walk from the first hop must be retried exactly once"
    );
    assert!(
        resolver.contains("if case .lookupFailed = walk"),
        "the retry applies to a failed lookup, not to the depth limit"
    );
    // FORK/EXEC membership keeps its meaning: only inTree counts.
    assert!(source.contains("ancestryOf(pid, root: root, maxDepth: maxDepth) == .inTree"));
}
