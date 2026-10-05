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
    assert!(source.contains("func flushReceipts()"));
    // Both exit paths flush: the drain exit and the SIGINT/SIGTERM source.
    let flush_calls = source.matches("flushReceipts()\n").count();
    assert!(
        flush_calls >= 2,
        "expected flushReceipts() before both exits, found {flush_calls} call(s)"
    );
    assert!(source.contains("DispatchSource.makeSignalSource"));
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
