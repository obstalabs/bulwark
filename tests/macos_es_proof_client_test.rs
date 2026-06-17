use std::fs;
use std::path::Path;

// source-invariant tests for the macOS ES proof scripts.
fn repo_file(path: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(root.join(path)).unwrap_or_else(|err| panic!("read {path}: {err}"))
}

#[test]
fn es_proof_client_has_no_callback_timer_shared_state() {
    let source = repo_file("macos-es-proof/es_proof.swift");

    assert!(
        !source.contains("var lastDenied"),
        "lastDenied shared state must not return"
    );
    assert!(
        !source.contains("respondErrorLogged"),
        "respondErrorLogged shared state must not return"
    );
    assert!(
        !source.contains("DispatchSource.makeTimerSource"),
        "timer-based callback state sharing must not return"
    );
    assert!(
        !source.contains("lastLogged"),
        "timer-side deny log state must not return"
    );
    assert!(
        !source.contains("String(decoding: UnsafeRawBufferPointer"),
        "callback must not allocate a Swift String for proof logging"
    );
    assert!(
        source.contains("es_respond_flags_result(clientPtr, message, 0, false)"),
        "marked AUTH_OPEN must deny with flags 0"
    );
    assert!(
        source.contains("es_respond_flags_result(clientPtr, message, UInt32.max, true)"),
        "unmarked AUTH_OPEN must allow all flags with cache"
    );
}

#[test]
fn prove_script_seals_only_validated_app_bundle() {
    let source = repo_file("macos-es-proof/prove.sh");

    assert!(
        source.contains(r#"APP_BIN="$APP_BUNDLE/Contents/MacOS/es_proof""#),
        "proof must target the app-bundle binary"
    );
    assert!(
        source.contains(r#"NOTARY_RECEIPT="notarization.receipt""#),
        "proof must require the notary sidecar"
    );
    assert!(
        !source.contains(r#"ES_BIN="./es_proof""#),
        "bare binary fallback must not be sealable"
    );
    assert!(
        source.contains(r#"xcrun stapler validate "$APP_BUNDLE""#),
        "receipt must validate stapling"
    );
    assert!(
        source.contains(r#"spctl -a -vv "$APP_BUNDLE""#),
        "receipt must validate Gatekeeper assessment"
    );
    assert!(
        source.contains(r#"[ "${BUNDLE_VALID:-0}" = 1 ]"#),
        "SEALED predicate must require app-bundle validation"
    );
    for field in [
        "client_path:",
        "bundle_id:",
        "stapler:",
        "spctl:",
        "notary:",
    ] {
        assert!(source.contains(field), "receipt missing {field}");
    }
}
