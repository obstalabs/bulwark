import Foundation

// WO-39@v1: deterministic source checks for the AUTH deadline-safety invariants.
let testPath = URL(fileURLWithPath: #filePath)
let dir = testPath.deletingLastPathComponent()
let proofSource = try String(contentsOf: dir.appendingPathComponent("es_proof.swift"), encoding: .utf8)
// WO-249@v1: source-shape checks on the production ES gate (clonefile/copyfile/exchangedata).
let gateSource = try String(contentsOf: dir.appendingPathComponent("es_gate.swift"), encoding: .utf8)

// WO-39@v1: stop the deadline-safety source check with a named failure.
func expect(_ condition: Bool, _ message: String) {
    if !condition {
        fputs("es_proof_test.swift: \(message)\n", stderr)
        exit(1)
    }
}

expect(!proofSource.contains("var lastDenied"), "lastDenied shared state must not return")
expect(!proofSource.contains("respondErrorLogged"), "respondErrorLogged shared state must not return")
expect(!proofSource.contains("DispatchSource.makeTimerSource"), "timer-based callback state sharing must not return")
expect(!proofSource.contains("lastLogged"), "timer-side deny log state must not return")
expect(!proofSource.contains("String(decoding: UnsafeRawBufferPointer"), "callback must not allocate a Swift String for proof logging")
expect(proofSource.contains("es_respond_flags_result(clientPtr, message, 0, false)"), "marked AUTH_OPEN must deny with flags 0")
expect(proofSource.contains("es_respond_flags_result(clientPtr, message, UInt32.max, true)"), "unmarked AUTH_OPEN must allow all flags with cache")

// WO-249@v1: the production edge must subscribe to the three vnode-copy events,
// answer them with the boolean auth responder (never the flags responder), and
// refuse a directory clone.
expect(gateSource.contains("ES_EVENT_TYPE_AUTH_CLONE"), "es_gate must subscribe to AUTH_CLONE")
expect(gateSource.contains("ES_EVENT_TYPE_AUTH_COPYFILE"), "es_gate must subscribe to AUTH_COPYFILE")
expect(gateSource.contains("ES_EVENT_TYPE_AUTH_EXCHANGEDATA"), "es_gate must subscribe to AUTH_EXCHANGEDATA")
expect(gateSource.contains("ES_AUTH_RESULT_ALLOW"), "vnode-copy arms must answer allow with the boolean auth responder")
expect(gateSource.contains("ES_AUTH_RESULT_DENY"), "vnode-copy arms must answer deny with the boolean auth responder")
expect(gateSource.contains("directory clone bypasses per-file gating"), "a directory clone must be refused")
if let cloneIdx = gateSource.range(of: "case ES_EVENT_TYPE_AUTH_CLONE:") {
    let fromClone = gateSource[cloneIdx.upperBound...]
    let armsRegion: Substring
    if let defaultIdx = fromClone.range(of: "    default:") {
        armsRegion = fromClone[..<defaultIdx.lowerBound]
    } else {
        armsRegion = fromClone
    }
    expect(String(armsRegion).contains("respondAuthResult"), "vnode-copy arms must respond via the auth responder helper")
    expect(!String(armsRegion).contains("es_respond_flags_result"), "vnode-copy arms must not use es_respond_flags_result")
}