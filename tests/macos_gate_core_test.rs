use std::fs;
use std::path::Path;

// deterministic source-contract tests for the macOS ES gate core.
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
        "",
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
