import CryptoKit
import Foundation

let siteURL = ProcessInfo.processInfo.environment["CLAUDUO_URL"] ?? "https://clauduo.com"

// 서버의 safeRel과 같은 규칙. 공유 파일이 Claude 설정(훅)이 되면 이 Mac에서 코드가 실행된다.
func safeRel(_ p: String) -> String? {
    if p.isEmpty || p.count > 500 || p.hasPrefix("/") || p.contains("\\") || p.contains("\0") { return nil }
    let blocked: Set<String> = [".", "..", ".claude", ".git", ".mcp.json"]
    return p.components(separatedBy: "/").allSatisfy { !$0.isEmpty && !blocked.contains($0) } ? p : nil
}

func sha(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

/// 일반 파일만 읽는다. 심볼릭 링크는 따라가지 않는다.
func walk(_ root: URL, skip: Set<String> = [], maxSize: Int? = nil, maxFiles: Int = .max) -> [String: Data] {
    let base = root.resolvingSymlinksInPath().path
    var out: [String: Data] = [:]
    guard let en = FileManager.default.enumerator(at: URL(fileURLWithPath: base), includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .fileSizeKey]) else { return out }
    for case let url as URL in en {
        let rel = String(url.resolvingSymlinksInPath().path.dropFirst(base.count + 1))
        let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey])
        if values?.isSymbolicLink == true { continue }
        if safeRel(rel) == nil || skip.contains(url.lastPathComponent) {
            if values?.isDirectory == true { en.skipDescendants() }
            continue
        }
        guard values?.isRegularFile == true, out.count < maxFiles else { continue }
        if let maxSize, (values?.fileSize ?? 0) > maxSize { continue }
        if let d = try? Data(contentsOf: url) { out[rel] = d }
    }
    return out
}

func findClaude() -> String? {
    if let p = ProcessInfo.processInfo.environment["CLAUDE_BIN"] { return p }
    let home = NSHomeDirectory()
    for p in ["\(home)/.local/bin/claude", "/opt/homebrew/bin/claude", "/usr/local/bin/claude", "\(home)/.claude/local/claude"] where FileManager.default.isExecutableFile(atPath: p) { return p }
    return nil // GUI 앱에는 셸의 PATH가 없어서 알려진 위치만 찾는다
}

private func execute(_ tool: String, _ args: [String], cwd: URL?, input: Data?) async -> (code: Int32, out: Data, err: Data) {
    await withCheckedContinuation { cont in
        DispatchQueue.global().async {
            let p = Process(), o = Pipe(), e = Pipe(), i = Pipe()
            p.executableURL = URL(fileURLWithPath: tool)
            p.arguments = args
            if let cwd { p.currentDirectoryURL = cwd }
            p.standardOutput = o; p.standardError = e; p.standardInput = i
            do { try p.run() } catch { cont.resume(returning: (-1, Data(), Data(error.localizedDescription.utf8))); return }
            let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
            DispatchQueue.global().asyncAfter(deadline: .now() + 570, execute: killer)
            if let input { try? i.fileHandleForWriting.write(contentsOf: input) }
            try? i.fileHandleForWriting.close()
            var errData = Data()
            let g = DispatchGroup(); g.enter()
            DispatchQueue.global().async { errData = e.fileHandleForReading.readDataToEndOfFile(); g.leave() }
            let outData = o.fileHandleForReading.readDataToEndOfFile()
            g.wait(); p.waitUntilExit(); killer.cancel()
            cont.resume(returning: (p.terminationStatus, outData, errData))
        }
    }
}

func runClaude(cwd: URL, prompt: String) async -> (ok: Bool, text: String) {
    guard let claude = findClaude() else { return (false, "Claude Code를 찾지 못했어요. 먼저 설치하고 로그인해 주세요.") }
    // 셸·웹 없이 파일 도구만 허용하고, 폴더 안의 설정은 읽지 않는다
    let args = ["-p", "--tools", "Read,Edit,Write,Glob,Grep", "--permission-mode", "acceptEdits", "--strict-mcp-config", "--setting-sources", "", "--no-session-persistence"]
    let r = await execute(claude, args, cwd: cwd, input: Data(prompt.utf8))
    let out = String(decoding: r.out, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    if r.code == 0 { return (true, out) }
    let err = String(decoding: r.err, as: UTF8.self)
    return (false, "실행 실패: \(String((err.isEmpty ? out : err).prefix(500)))")
}

func unifiedDiff(_ path: String, _ before: Data?, _ after: Data?) async -> String {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("clauduo-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: dir) }
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let a = dir.appendingPathComponent("a"), b = dir.appendingPathComponent("b")
    if (before ?? Data()).contains(0) || (after ?? Data()).contains(0) { return "" }
    try? (before ?? Data()).write(to: a); try? (after ?? Data()).write(to: b)
    let r = await execute("/usr/bin/diff", ["-u", "--label", "a/\(path)", "--label", "b/\(path)", a.path, b.path], cwd: nil, input: nil)
    return String(String(decoding: r.out, as: UTF8.self).prefix(50000))
}

struct Client {
    let url: String, token: String
    func call(_ method: String, _ path: String, _ body: [String: Any]? = nil) async throws -> (Int, [String: Any]) {
        var req = URLRequest(url: URL(string: url + path)!)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "authorization")
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        if let body { req.httpBody = try JSONSerialization.data(withJSONObject: body) }
        let (d, r) = try await URLSession.shared.data(for: req)
        return ((r as? HTTPURLResponse)?.statusCode ?? 0, (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] ?? [:])
    }
}

/// 방에서 멘션된 작업: 임시 폴더의 사본에서만 실행하므로 다른 멤버의 메시지가 실제 폴더를 건드릴 수 없다.
func workerLoop(_ c: Client, folders: @escaping @Sendable () -> [String], onStatus: @escaping @Sendable (String) -> Void) async {
    onStatus("연결됨")
    var reported: [String]? = nil
    while !Task.isCancelled {
        try? await Task.sleep(nanoseconds: 3_000_000_000)
        let allowed = folders()
        if reported != allowed, (try? await c.call("POST", "/api/worker/folders", ["folders": allowed]))?.0 == 200 { reported = allowed }
        guard let (status, job) = try? await c.call("GET", "/api/worker/job?caps=local") else { onStatus("서버 연결 재시도 중"); continue }
        if status == 401 { onStatus("연결 해제됨: 이 Claude가 제거됐어요"); return }
        if let id = job["id"], let folder = job["folder"] as? String, let prompt = job["prompt"] as? String {
            // 서버가 보낸 경로라도 이 Mac에서 허용한 폴더가 아니면 실행하지 않는다
            guard allowed.contains(folder) else { _ = try? await c.call("POST", "/api/worker/job", ["id": id, "reply": "이 Mac에서 허용하지 않은 폴더예요.", "error": true]); continue }
            onStatus("로컬 작업 중")
            let r = await localRun(folder: URL(fileURLWithPath: folder), prompt: prompt)
            var body: [String: Any] = ["id": id, "reply": r.text, "files": r.files]
            if !r.ok { body["error"] = true }
            _ = try? await c.call("POST", "/api/worker/job", body)
            onStatus("연결됨")
            continue
        }
        guard let id = job["id"], let files = job["files"] as? [String: String], let prompt = job["prompt"] as? String else { continue }
        onStatus("방 작업 처리 중")
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("clauduo-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var before: [String: String] = [:]
        for (rel, b64) in files {
            guard safeRel(rel) != nil, let d = Data(base64Encoded: b64) else { continue }
            let f = dir.appendingPathComponent(rel)
            try? FileManager.default.createDirectory(at: f.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? d.write(to: f); before[rel] = sha(d)
        }
        let r = await runClaude(cwd: dir, prompt: prompt)
        let after = walk(dir)
        var changes: [[String: Any]] = after.filter { before[$0.key] != sha($0.value) }.map { ["path": $0.key, "data": $0.value.base64EncodedString()] }
        changes += before.keys.filter { after[$0] == nil }.map { ["path": $0, "data": NSNull()] }
        try? FileManager.default.removeItem(at: dir)
        var body: [String: Any] = ["id": id, "reply": r.text, "changes": changes]
        if !r.ok { body["error"] = true }
        _ = try? await c.call("POST", "/api/worker/job", body)
        onStatus("연결됨")
    }
}

struct LocalResult { let ok: Bool; let text: String; let files: [[String: String]] }

/// 사용자가 이 앱에서 직접 시작한 작업: 고른 폴더에서 바로 실행한다.
func localRun(folder: URL, prompt: String) async -> LocalResult {
    let skip: Set<String> = ["node_modules", ".build", "dist", ".DS_Store"]
    let before = walk(folder, skip: skip, maxSize: 256_000, maxFiles: 3000) // ponytail: 큰 파일과 3000개 이후는 변경 추적 제외
    let r = await runClaude(cwd: folder, prompt: prompt)
    let after = walk(folder, skip: skip, maxSize: 256_000, maxFiles: 3000)
    var files: [[String: String]] = []
    for path in Set(before.keys).union(after.keys).sorted() where before[path] != after[path] {
        files.append(["path": path, "status": before[path] == nil ? "added" : after[path] == nil ? "deleted" : "changed", "diff": await unifiedDiff(path, before[path], after[path])])
        if files.count >= 200 { break }
    }
    return LocalResult(ok: r.ok, text: r.text, files: files)
}
