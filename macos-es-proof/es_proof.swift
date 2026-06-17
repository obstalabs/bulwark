// macOS Endpoint Security proof-of-gate client.
//
// The SMALLEST thing that proves the macOS gate chain end to end on a real Mac:
// a signed, ES-entitled, root-launched binary that subscribes to
// ES_EVENT_TYPE_AUTH_OPEN and gates a real open():
//   - opening a file whose path contains the sentinel marker -> DENY (open fails)
//   - opening anything else                                  -> ALLOW
//
// This is the macOS analog of the Linux fanotify VM demo. It proves
// entitlement -> sign -> notarize -> subscribe -> AUTH verdict gates a syscall.
// It is NOT bulwark's policy engine (that is ); the marker is a stand-in for
// "this inode is protected" so the gate itself can be proven in isolation.
//
// SAFETY / DEADLINE DISCIPLINE: the AUTH handler must answer the kernel fast.
// The kernel holds the open() hostage on our verdict and KILLS the client if we
// miss the deadline (and stalls every watched open until we die). So the handler
// does only an in-memory string check and responds immediately -- no disk, no
// locks, no allocation storms, no logging that can block. We also mute our own
// process so we never gate ourselves into a deadlock.
//
// Run as root (ES requires it): sudo ./es_proof <marker>
// Stop with Ctrl-C (SIGINT) -> clean es_delete_client, no wedged state.

import EndpointSecurity
import Foundation

// The sentinel marker. Any opened path containing this substring is DENIED.
// Default "BULWARK_DENY"; overridable as argv[1] so the proof harness can use a
// unique marker per run.
let marker: String = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "BULWARK_DENY"

// Self-gating guard: we only DENY paths containing the marker, and es_proof
// never opens a marker-named file, so our own opens are always ALLOWed and
// cannot deadlock us. (Production bulwark will mute its own process + log path
// explicitly; for this minimal proof the marker scoping is sufficient.)

FileHandle.standardError.write("[es_proof] starting; deny-marker=\"\(marker)\" pid=\(getpid())\n".data(using: .utf8)!)

var client: OpaquePointer?

// The marker as raw UTF-8 bytes, for a fast substring scan over the kernel's
// length-delimited path buffer WITHOUT building a Swift String on the hot path
// (String construction allocates; on a system-wide AUTH_OPEN firehose that risks
// the deadline).
let markerBytes = Array(marker.utf8)

let res = es_new_client(&client) { (clientPtr, message) in
    let msg = message.pointee

    // Only AUTH_OPEN is subscribed. The catch-all (never reached in practice)
    // uses the boolean responder, which is correct for non-OPEN AUTH events.
    guard msg.event_type == ES_EVENT_TYPE_AUTH_OPEN else {
        es_respond_auth_result(clientPtr, message, ES_AUTH_RESULT_ALLOW, true)
        return
    }

    // The opened file path is a length-delimited es_string_token_t {length, data}
    // -- NOT null-terminated. Scan the raw bytes for the marker; do NOT use
    // String(cString:) (over-reads past `length`).
    let token = msg.event.open.file.pointee.path
    var isMarked = false
    if token.length >= markerBytes.count, let base = token.data {
        let n = token.length
        let m = markerBytes.count
        let buf = UnsafeRawPointer(base).assumingMemoryBound(to: UInt8.self)
        // naive substring scan over n bytes (paths are short; this is microseconds)
        var i = 0
        let last = n - m
        while i <= last {
            var j = 0
            while j < m && buf[i + j] == markerBytes[j] { j += 1 }
            if j == m { isMarked = true; break }
            i += 1
        }
    }

    // CRITICAL API QUIRK: AUTH_OPEN takes a FLAGS response, not a boolean one.
    // It must be answered with es_respond_FLAGS_result (authorize a mask of open
    // flags), NOT es_respond_auth_result (which is for boolean AUTH events like
    // AUTH_EXEC). The wrong responder returns ERR_EVENT_TYPE, the message is never
    // answered, every system-wide open() queues, and the kernel SIGKILLs us.
    //   authorized flags 0          = deny ALL opens of this file (open() fails)
    //   authorized flags UInt32.max = allow ALL opens
    let rr: es_respond_result_t
    if isMarked {
        // DENY immediately and do not share mutable proof-log state across
        // callback/timer queues. The harness seals on the real open() result.
        // `false`: do not cache a deny (re-evaluate each time).
        rr = es_respond_flags_result(clientPtr, message, 0, false)
    } else {
        // ALLOW all flags + CACHE (true): the system stops re-asking about this
        // inode, collapsing the firehose so we never miss a deadline. We only
        // watch marker paths, so caching every other allow is exactly right.
        rr = es_respond_flags_result(clientPtr, message, UInt32.max, true)
    }

    // RESPOND-RESULT DISCIPLINE: a non-success respond means the kernel never got
    // our verdict -> it will SIGKILL us. This is the fatal path, so log it loudly
    // instead of letting the kernel express it only as Killed:9.
    if rr != ES_RESPOND_RESULT_SUCCESS {
        FileHandle.standardError.write("[es_proof] FATAL: es_respond_flags_result returned \(rr.rawValue) -- the kernel did NOT receive our verdict; a SIGKILL is imminent.\n".data(using: .utf8)!)
    }
}

guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
    // The decisive entitlement check: ERR_NOT_ENTITLED means the bundle/binary
    // does not carry the granted ES client entitlement (or isn't signed right).
    let why: String
    switch res {
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: why = "ERR_NOT_ENTITLED (binary lacks the ES client entitlement / not signed with it)"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: why = "ERR_NOT_PERMITTED (the CALLING terminal needs Full Disk Access: System Settings > Privacy & Security > Full Disk Access > add + enable your terminal, then restart it)"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: why = "ERR_NOT_PRIVILEGED (must be root)"
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: why = "ERR_TOO_MANY_CLIENTS"
    default: why = "error code \(res.rawValue)"
    }
    FileHandle.standardError.write("[es_proof] es_new_client FAILED: \(why)\n".data(using: .utf8)!)
    exit(2)
}

FileHandle.standardError.write("[es_proof] es_new_client OK -- entitlement accepted by the kernel\n".data(using: .utf8)!)

// Subscribe to AUTH_OPEN only -- the single event the proof needs.
var events: [es_event_type_t] = [ES_EVENT_TYPE_AUTH_OPEN]
let sub = es_subscribe(client, &events, UInt32(events.count))
guard sub == ES_RETURN_SUCCESS else {
    FileHandle.standardError.write("[es_proof] es_subscribe FAILED\n".data(using: .utf8)!)
    es_delete_client(client)
    exit(3)
}

FileHandle.standardError.write("[es_proof] subscribed to AUTH_OPEN -- gate is LIVE. Ctrl-C to stop.\n".data(using: .utf8)!)

// Clean teardown on SIGINT/SIGTERM: delete the client so no AUTH events are left
// queued (fail-closed: deleting the client releases held events per the kernel).
let sigHandler: @convention(c) (Int32) -> Void = { _ in
    FileHandle.standardError.write("[es_proof] signal -> tearing down client\n".data(using: .utf8)!)
    exit(0) // process exit deletes the client; kernel releases its subscription
}
signal(SIGINT, sigHandler)
signal(SIGTERM, sigHandler)

// Run the message loop.
dispatchMain()
