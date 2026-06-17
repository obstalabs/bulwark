// production-shaped macOS Endpoint Security AUTH_OPEN edge.
//
// The Rust core launches the supervised process stopped, writes an edge config
// containing root pid + protected dev:ino set, starts this signed ES client, and
// resumes the process only after this client has subscribed. The callback
// answers the kernel from in-memory state only: protected inode + supervised
// tree + pushed session allow set. Receipts are enqueued after the response.

import Darwin
import Dispatch
import EndpointSecurity
import Foundation

struct InodeKey: Hashable {
    let dev: UInt64
    let ino: UInt64
}

struct GrantRoot {
    let key: InodeKey // inode identity of the operator-granted root
    let recursive: Bool // directory grants cover descendants
    let path: String // canonical path used for symlink-safe boundary checks
}

enum GateMode: String {
    case denylist
    case allowlist
}

struct GateConfig {
    let mode: GateMode // deny-list vs default-deny allow-list behavior
    let rootPid: pid_t
    let readyPath: String
    let receiptPath: String?
    let protected: Set<InodeKey>
    let allowOnce: Set<InodeKey> // one-open startup consent grants
    let allowed: Set<InodeKey>
    let allowGlobs: [String] // macOS runtime base-set globs
    let allowRoots: [GrantRoot] // operator grants pinned to root identity
}

func parseInode(_ value: Substring) -> InodeKey? {
    let parts = value.split(separator: ":", maxSplits: 1)
    guard parts.count == 2, let dev = UInt64(parts[0]), let ino = UInt64(parts[1]) else {
        return nil
    }
    return InodeKey(dev: dev, ino: ino)
}

func parseGrantRoot(_ value: Substring) -> GrantRoot? {
    let parts = value.split(separator: ":", maxSplits: 3, omittingEmptySubsequences: false)
    guard
        parts.count == 4,
        let dev = UInt64(parts[0]),
        let ino = UInt64(parts[1])
    else {
        return nil
    }
    let recursive: Bool
    switch parts[2] {
    case "recursive":
        recursive = true
    case "exact":
        recursive = false
    default:
        return nil
    }
    return GrantRoot(
        key: InodeKey(dev: dev, ino: ino),
        recursive: recursive,
        path: String(parts[3])
    )
}

func loadConfig(_ path: String) throws -> GateConfig {
    let body = try String(contentsOfFile: path, encoding: .utf8)
    var mode = GateMode.denylist
    var rootPid: pid_t?
    var readyPath: String?
    var receiptPath: String?
    var protected = Set<InodeKey>()
    var allowOnce = Set<InodeKey>()
    var allowed = Set<InodeKey>()
    var allowGlobs: [String] = []
    var allowRoots: [GrantRoot] = []

    for rawLine in body.split(whereSeparator: \.isNewline) {
        let line = rawLine.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") {
            continue
        }
        let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        if parts.count != 2 {
            continue
        }
        switch parts[0] {
        case "mode":
            guard let parsed = GateMode(rawValue: String(parts[1])) else {
                throw NSError(domain: "BulwarkGateConfig", code: 3, userInfo: [
                    NSLocalizedDescriptionKey: "unknown gate mode \(parts[1])"
                ])
            }
            mode = parsed
        case "root_pid":
            rootPid = pid_t(parts[1])
        case "ready":
            readyPath = String(parts[1])
        case "receipts":
            receiptPath = String(parts[1])
        case "protected":
            if let key = parseInode(parts[1]) {
                protected.insert(key)
            }
        case "allow_once":
            if let key = parseInode(parts[1]) {
                allowOnce.insert(key)
            }
        case "allow_session":
            if let key = parseInode(parts[1]) {
                allowed.insert(key)
            }
        case "allow", "allow_inode":
            if let key = parseInode(parts[1]) {
                allowed.insert(key)
            }
        case "allow_glob":
            allowGlobs.append(String(parts[1]))
        case "allow_root":
            if let root = parseGrantRoot(parts[1]) {
                allowRoots.append(root)
            }
        default:
            continue
        }
    }

    guard let rootPid, let readyPath else {
        throw NSError(domain: "BulwarkGateConfig", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "config requires root_pid and ready"
        ])
    }
    if mode == .denylist && protected.isEmpty {
        throw NSError(domain: "BulwarkGateConfig", code: 2, userInfo: [
            NSLocalizedDescriptionKey: "config has no protected inode set"
        ])
    }
    if mode == .allowlist && allowed.isEmpty && allowGlobs.isEmpty && allowRoots.isEmpty {
        throw NSError(domain: "BulwarkGateConfig", code: 4, userInfo: [
            NSLocalizedDescriptionKey: "allowlist mode requires allow_inode, allow_glob, or allow_root entries"
        ])
    }
    return GateConfig(
        mode: mode,
        rootPid: rootPid,
        readyPath: readyPath,
        receiptPath: receiptPath,
        protected: protected,
        allowOnce: allowOnce,
        allowed: allowed,
        allowGlobs: allowGlobs,
        allowRoots: allowRoots
    )
}

func pidFromAuditToken(_ token: audit_token_t) -> pid_t {
    audit_token_to_pid(token)
}

func inodeKey(_ file: UnsafePointer<es_file_t>) -> InodeKey {
    let st = file.pointee.stat
    return InodeKey(dev: UInt64(st.st_dev), ino: UInt64(st.st_ino))
}

func tokenPath(_ token: es_string_token_t) -> String {
    guard token.length > 0, let data = token.data else {
        return ""
    }
    let start = UnsafeRawPointer(data).assumingMemoryBound(to: UInt8.self)
    let bytes = UnsafeBufferPointer(start: start, count: token.length)
    return String(decoding: bytes, as: UTF8.self)
}

func parentPid(_ pid: pid_t) -> pid_t? {
    var info = proc_bsdinfo()
    let size = proc_pidinfo(
        pid,
        PROC_PIDTBSDINFO,
        0,
        &info,
        Int32(MemoryLayout<proc_bsdinfo>.stride)
    )
    if size <= 0 {
        return nil
    }
    return pid_t(info.pbi_ppid)
}

func processName(_ pid: pid_t) -> String {
    var name = [CChar](repeating: 0, count: 128)
    let rc = proc_name(pid, &name, UInt32(name.count))
    if rc <= 0 {
        return "pid"
    }
    let end = name.firstIndex(of: 0) ?? name.count
    let bytes = name[..<end].map { UInt8(bitPattern: $0) }
    return String(decoding: bytes, as: UTF8.self)
}

func ancestry(_ pid: pid_t, maxDepth: Int = 16) -> String {
    var parts: [String] = []
    var current = pid
    var depth = 0
    while current > 1 && depth < maxDepth {
        parts.append("\(processName(current))(\(current))")
        guard let parent = parentPid(current), parent > 1, parent != current else {
            break
        }
        current = parent
        depth += 1
    }
    return parts.joined(separator: " <- ")
}

func hasAncestor(_ pid: pid_t, root: pid_t, maxDepth: Int = 16) -> Bool {
    if pid == root {
        return true
    }
    var current = pid
    var depth = 0
    while current > 1 && depth < maxDepth {
        guard let parent = parentPid(current) else {
            return false
        }
        if parent == root {
            return true
        }
        current = parent
        depth += 1
    }
    return false
}

func jsonEscape(_ value: String) -> String {
    var out = ""
    out.reserveCapacity(value.count)
    for scalar in value.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                out += String(format: "\\u%04x", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    return out
}

func nowMillis() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1000)
}

func pathMatchesGlob(_ path: String, _ glob: String) -> Bool {
    if let prefix = glob.dropSuffix("/**") {
        return path == prefix || path.hasPrefix(prefix + "/")
    }
    if !glob.contains("*") && !glob.contains("?") {
        return path == glob
    }
    return wildcardMatch(Array(path.utf8), Array(glob.utf8), 0, 0)
}

func canonicalPath(_ path: String) -> String? {
    var resolved = [CChar](repeating: 0, count: Int(PATH_MAX))
    return path.withCString { ptr in
        guard let out = realpath(ptr, &resolved) else {
            return nil
        }
        let length = strlen(out)
        let bytes = UnsafeBufferPointer(
            start: UnsafeRawPointer(out).assumingMemoryBound(to: UInt8.self),
            count: length
        )
        return String(decoding: bytes, as: UTF8.self)
    }
}

func inodeKey(at path: String) -> InodeKey? {
    do {
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        guard
            let dev = attrs[.systemNumber] as? NSNumber,
            let ino = attrs[.systemFileNumber] as? NSNumber
        else {
            return nil
        }
        return InodeKey(dev: dev.uint64Value, ino: ino.uint64Value)
    } catch {
        return nil
    }
}

func pathIsUnder(_ path: String, root: String) -> Bool {
    path == root || path.hasPrefix(root + "/")
}

func grantRootAllows(_ root: GrantRoot, key: InodeKey, canonicalPath: String) -> Bool {
    // prevent symlink/hardlink escapes by requiring the grant root's
    // inode to remain unchanged and the opened object's canonical path to stay
    // under that root.
    guard inodeKey(at: root.path) == root.key else {
        return false
    }
    if !root.recursive {
        return key == root.key && canonicalPath == root.path
    }
    return pathIsUnder(canonicalPath, root: root.path)
}

func wildcardMatch(_ path: [UInt8], _ glob: [UInt8], _ pi: Int, _ gi: Int) -> Bool {
    if gi == glob.count {
        return pi == path.count
    }
    if gi + 1 < glob.count && glob[gi] == UInt8(ascii: "*") && glob[gi + 1] == UInt8(ascii: "*") {
        var next = pi
        while next <= path.count {
            if wildcardMatch(path, glob, next, gi + 2) {
                return true
            }
            next += 1
        }
        return false
    }
    if glob[gi] == UInt8(ascii: "*") {
        var next = pi
        while next <= path.count {
            if wildcardMatch(path, glob, next, gi + 1) {
                return true
            }
            if next == path.count || path[next] == UInt8(ascii: "/") {
                break
            }
            next += 1
        }
        return false
    }
    if pi == path.count {
        return false
    }
    if glob[gi] == UInt8(ascii: "?") {
        return path[pi] != UInt8(ascii: "/") && wildcardMatch(path, glob, pi + 1, gi + 1)
    }
    return path[pi] == glob[gi] && wildcardMatch(path, glob, pi + 1, gi + 1)
}

extension String {
    func dropSuffix(_ suffix: String) -> String? {
        guard hasSuffix(suffix) else {
            return nil
        }
        return String(dropLast(suffix.count))
    }
}

func allowlistAllows(_ key: InodeKey, path: String, config: GateConfig) -> Bool {
    if config.allowed.contains(key) {
        return true
    }
    if config.allowGlobs.contains(where: { pathMatchesGlob(path, $0) }) {
        return true
    }
    guard let resolved = canonicalPath(path) else {
        return false
    }
    return config.allowRoots.contains {
        grantRootAllows($0, key: key, canonicalPath: resolved)
    }
}

let configPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
guard !configPath.isEmpty else {
    FileHandle.standardError.write("[bulwark-es] missing config path\n".data(using: .utf8)!)
    exit(64)
}

let config: GateConfig
do {
    config = try loadConfig(configPath)
} catch {
    FileHandle.standardError.write("[bulwark-es] config error: \(error)\n".data(using: .utf8)!)
    exit(65)
}

let hostLabel = ProcessInfo.processInfo.hostName
let receiptFd: Int32 = {
    guard let path = config.receiptPath else {
        return -1
    }
    return open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0o600)
}()
let receiptQueue = DispatchQueue(label: "dev.obstalabs.bulwark.es.receipts")

func appendReceipt(_ line: String) {
    guard receiptFd >= 0 else {
        return
    }
    let payload = line + "\n"
    receiptQueue.async {
        payload.withCString { ptr in
            _ = Darwin.write(receiptFd, ptr, strlen(ptr))
        }
    }
}

func receiptLine(
    pid: pid_t,
    key: InodeKey,
    decision: String,
    source: String,
    path: String,
    ancestry: String,
    reason: String
) -> String {
    return """
    {"ts_ms":\(nowMillis()),"host":"\(jsonEscape(hostLabel))","pid":\(pid),"dev":\(key.dev),"ino":\(key.ino),"decision":"\(decision)","source":"\(jsonEscape(source))","path":"\(jsonEscape(path))","ancestry":"\(jsonEscape(ancestry))","reason":"\(jsonEscape(reason))"}
    """
}

var supervisedPids = Set<pid_t>([config.rootPid])
var allowOnce = config.allowOnce
var client: OpaquePointer?

let res = es_new_client(&client) { clientPtr, message in
    let msg = message.pointee
    let eventPid = pidFromAuditToken(msg.process.pointee.audit_token)

    switch msg.event_type {
    case ES_EVENT_TYPE_NOTIFY_FORK:
        let child = msg.event.fork.child.pointee
        let childPid = pidFromAuditToken(child.audit_token)
        if supervisedPids.contains(eventPid) || hasAncestor(eventPid, root: config.rootPid) {
            supervisedPids.insert(eventPid)
            supervisedPids.insert(childPid)
        }
        return

    case ES_EVENT_TYPE_NOTIFY_EXEC:
        if supervisedPids.contains(eventPid) || hasAncestor(eventPid, root: config.rootPid) {
            supervisedPids.insert(eventPid)
        }
        return

    case ES_EVENT_TYPE_NOTIFY_EXIT:
        supervisedPids.remove(eventPid)
        return

    case ES_EVENT_TYPE_AUTH_OPEN:
        let file = msg.event.open.file
        let key = inodeKey(file)
        let treeHit = supervisedPids.contains(eventPid) || hasAncestor(eventPid, root: config.rootPid)
        if treeHit {
            supervisedPids.insert(eventPid)
        }

        let allow: Bool
        let source: String
        let reason: String
        let cacheKernelAllow: Bool
        var pathForReceipt = ""
        switch config.mode {
        case .denylist:
            let protectedHit = config.protected.contains(key)
            if !treeHit {
                allow = true
                source = "outside-tree"
                reason = protectedHit ? "protected inode opened outside supervised tree" : "outside supervised tree"
            } else if !protectedHit {
                allow = true
                source = ""
                reason = "not protected"
            } else if allowOnce.contains(key) {
                allowOnce.remove(key)
                allow = true
                source = "operator"
                reason = "operator allowed once"
            } else if config.allowed.contains(key) {
                allow = true
                source = "cache"
                reason = "operator allowed for session"
            } else {
                allow = false
                source = "static"
                reason = "protected inode opened by supervised tree"
            }
            cacheKernelAllow = allow && !protectedHit

        case .allowlist:
            // default-deny mode has no prompt path; the pushed policy
            // must decide immediately for every AUTH_OPEN event in-tree.
            let path = tokenPath(file.pointee.path)
            pathForReceipt = path
            let allowedByPolicy = allowlistAllows(key, path: path, config: config)
            // FIX: a DIRECTORY carries no file content to protect, and path
            // resolution requires opening every directory component (/, /usr,
            // /usr/lib, ...) on the way to an allowed file. Allowing only files
            // under a glob denies the containing directories -> the kernel can't
            // traverse to the file at all, and binaries fail to launch (dyld
            // aborts -> SIGABRT, observed as `/` ino 2 denied). Default-deny gates
            // FILE reads; directory opens are allowed so traversal works. The
            // protected files themselves are still gated by their own inode.
            let isDirectory = (file.pointee.stat.st_mode & S_IFMT) == S_IFDIR
            if !treeHit {
                allow = true
                source = "outside-tree"
                reason = allowedByPolicy ? "allowed inode opened outside supervised tree" : "outside supervised tree"
                cacheKernelAllow = false
            } else if allowedByPolicy {
                allow = true
                source = "allowlist"
                reason = "allowlist match"
                cacheKernelAllow = true
            } else if isDirectory {
                allow = true
                source = "allowlist"
                reason = "directory traversal (no file content)"
                cacheKernelAllow = true
            } else {
                allow = false
                source = "allowlist"
                reason = "not in allowlist (default deny)"
                cacheKernelAllow = false
            }
        }

        // AUTH_OPEN requires a FLAGS response. Do not use
        // es_respond_auth_result for this event type.
        let rr: es_respond_result_t
        if allow {
            rr = es_respond_flags_result(clientPtr, message, UInt32.max, cacheKernelAllow)
        } else {
            rr = es_respond_flags_result(clientPtr, message, 0, false)
        }
        if rr != ES_RESPOND_RESULT_SUCCESS {
            FileHandle.standardError.write("[bulwark-es] FATAL respond_flags_result=\(rr.rawValue)\n".data(using: .utf8)!)
            return
        }

        let path = pathForReceipt.isEmpty ? tokenPath(file.pointee.path) : pathForReceipt
        let chain = ancestry(eventPid)
        appendReceipt(receiptLine(
            pid: eventPid,
            key: key,
            decision: allow ? "allow" : "deny",
            source: source,
            path: path,
            ancestry: chain,
            reason: reason
        ))
        return

    default:
        return
    }
}

guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
    FileHandle.standardError.write("[bulwark-es] es_new_client failed: \(res.rawValue)\n".data(using: .utf8)!)
    exit(66)
}

// FIX: mute our OWN process before going live. In default-deny allow-list
// mode EVERY open() system-wide is adjudicated, including the edge's own opens
// (ready marker, receipt log, dyld, etc.). Without self-muting the edge gates
// itself: its ready-marker write is denied (path not in the allow-set) -> the
// marker is never written -> the launcher times out; and the self-open storm
// misses AUTH deadlines -> the kernel SIGKILLs the edge. (Deny-mode did not hit
// this because it only gates the protected inode set, not the edge's own files.)
// es_mute_process excludes our pid from ALL events, by audit token. Obtain our
// own audit token via task_info(TASK_AUDIT_TOKEN) on mach_task_self.
var selfToken = audit_token_t()
var tokenCount = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
let kr = withUnsafeMutablePointer(to: &selfToken) { tokenPtr in
    tokenPtr.withMemoryRebound(to: integer_t.self, capacity: Int(tokenCount)) { intPtr in
        task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), intPtr, &tokenCount)
    }
}
if kr == KERN_SUCCESS {
    _ = es_mute_process(client, &selfToken)
} else {
    FileHandle.standardError.write("[bulwark-es] WARN could not obtain self audit token (kr=\(kr)); not self-muted\n".data(using: .utf8)!)
}

// Write the ready marker BEFORE subscribing, so the write completes while the
// gate is not yet live (belt-and-suspenders with the self-mute above). Plain
// write, not atomically: (which does a temp-file + rename = extra opens).
do {
    try "ready\n".write(toFile: config.readyPath, atomically: false, encoding: .utf8)
} catch {
    FileHandle.standardError.write("[bulwark-es] cannot write ready marker: \(error)\n".data(using: .utf8)!)
    es_delete_client(client)
    exit(68)
}

var events: [es_event_type_t] = [
    ES_EVENT_TYPE_AUTH_OPEN,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_EXIT,
]
let sub = es_subscribe(client, &events, UInt32(events.count))
guard sub == ES_RETURN_SUCCESS else {
    FileHandle.standardError.write("[bulwark-es] es_subscribe failed\n".data(using: .utf8)!)
    es_delete_client(client)
    exit(67)
}

FileHandle.standardError.write("[bulwark-es] AUTH_OPEN gate live mode=\(config.mode.rawValue) root_pid=\(config.rootPid) protected=\(config.protected.count) allow_once=\(config.allowOnce.count) allow_inodes=\(config.allowed.count) allow_globs=\(config.allowGlobs.count) allow_roots=\(config.allowRoots.count)\n".data(using: .utf8)!)

let sigHandler: @convention(c) (Int32) -> Void = { _ in
    exit(0)
}
signal(SIGINT, sigHandler)
signal(SIGTERM, sigHandler)

dispatchMain()
