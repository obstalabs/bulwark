import Foundation

// deterministic source checks for AUTH callback deadline-safety invariants.
let testPath = URL(fileURLWithPath: #filePath)
let sourcePath = testPath.deletingLastPathComponent().appendingPathComponent("es_proof.swift")
let source = try String(contentsOf: sourcePath, encoding: .utf8)

func expect(_ condition: Bool, _ message: String) {
    if !condition {
        fputs("es_proof_test.swift: \(message)\n", stderr)
        exit(1)
    }
}

expect(!source.contains("var lastDenied"), "lastDenied shared state must not return")
expect(!source.contains("respondErrorLogged"), "respondErrorLogged shared state must not return")
expect(!source.contains("DispatchSource.makeTimerSource"), "timer-based callback state sharing must not return")
expect(!source.contains("lastLogged"), "timer-side deny log state must not return")
expect(!source.contains("String(decoding: UnsafeRawBufferPointer"), "callback must not allocate a Swift String for proof logging")
expect(source.contains("es_respond_flags_result(clientPtr, message, 0, false)"), "marked AUTH_OPEN must deny with flags 0")
expect(source.contains("es_respond_flags_result(clientPtr, message, UInt32.max, true)"), "unmarked AUTH_OPEN must allow all flags with cache")
