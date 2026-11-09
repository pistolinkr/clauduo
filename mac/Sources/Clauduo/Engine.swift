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
func walk(_ root: URL, skip: Set<String> = [], maxSize: Int? = nil, maxFiles: Int = .max, maxTotal: Int = .max) -> [String: Data] {
    let base = root.resolvingSymlinksInPath().path
    var out: [String: Data] = [:], total = 0
    guard let en = FileManager.default.enumerator(at: URL(fileURLWithPath: base), includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .fileSizeKey]) else { return out }
    for case let url as URL in en {
        let rel = String(url.resolvingSymlinksInPath().path.dropFirst(base.count + 1))
        let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey])
        if values?.isSymbolicLink == true { continue }
        if safeRel(rel) == nil || skip.contains(url.lastPathComponent) {
            if values?.isDirectory == true { en.skipDescendants() }
            continue
        }
        guard values?.isRegularFile == true, out.count < maxFiles, total < maxTotal else { continue }
        if let maxSize, (values?.fileSize ?? 0) > maxSize { continue }
        if let d = try? Data(contentsOf: url) { out[rel] = d; total += d.count }
    }
    return out
}

func findClaude() -> String? {
    if let p = ProcessInfo.processInfo.environment["CLAUDE_BIN"] { return p }
    let home = NSHomeDirectory()
    for p in ["\(home)/.local/bin/claude", "/opt/homebrew/bin/claude", "/usr/local/bin/claude", "\(home)/.claude/local/claude"] where FileManager.default.isExecutableFile(atPath: p) { return p }
    return nil // GUI 앱에는 셸의 PATH가 없어서 알려진 위치만 찾는다
}

/// GUI 앱에는 셸의 PATH가 없어서, Claude의 터미널 도구와 훅이 쓸 PATH를 로그인 셸에서 가져온다.
private let shellPath: String = {
    let p = Process(), o = Pipe()
    p.executableURL = URL(fileURLWithPath: "/bin/zsh"); p.arguments = ["-lc", "printf %s \"$PATH\""]; p.standardOutput = o; p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else { return "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin" }
    let d = o.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    return String(decoding: d, as: UTF8.self)
}()

/// config는 계정별 로그인 폴더. nil이면 지금 로그인된 기본 계정을 그대로 쓴다.
private func claudeEnv(_ config: String?) -> [String: String] {
    var env = ProcessInfo.processInfo.environment
    env["PATH"] = shellPath
    guard let config else { return env }
    env["CLAUDE_CONFIG_DIR"] = config
    // 부모 환경의 자격증명이 남아 있으면 모든 계정이 같은 계정으로 실행된다
    for k in ["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"] { env[k] = nil }
    return env
}

func claudeAuth(_ action: String, config: String) async -> Bool {
    guard let claude = findClaude() else { return false }
    return await execute(claude, ["auth", action], cwd: nil, input: Data(), env: claudeEnv(config)).code == 0
}

func execute(_ tool: String, _ args: [String], cwd: URL?, input: Data?, env: [String: String]? = nil) async -> (code: Int32, out: Data, err: Data) {
    await withCheckedContinuation { cont in
        DispatchQueue.global().async {
            let p = Process(), o = Pipe(), e = Pipe(), i = Pipe()
            p.executableURL = URL(fileURLWithPath: tool)
            p.arguments = args
            if let cwd { p.currentDirectoryURL = cwd }
            if let env { p.environment = env }
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

func runClaude(cwd: URL, prompt: String, config: String?) async -> (ok: Bool, text: String) {
    guard let claude = findClaude() else { return (false, "Claude Code를 찾지 못했어요. 먼저 설치하고 로그인해 주세요.") }
    // 셸·웹 없이 파일 도구만 허용하고, 폴더 안의 설정은 읽지 않는다
    let args = ["-p", "--tools", "Read,Edit,Write,Glob,Grep", "--permission-mode", "acceptEdits", "--strict-mcp-config", "--setting-sources", "", "--no-session-persistence"]
    let r = await execute(claude, args, cwd: cwd, input: Data(prompt.utf8), env: claudeEnv(config))
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
func workerLoop(_ c: Client, config: String?, fullAccessAllowed: @escaping @Sendable () -> Bool, folders: @escaping @Sendable () -> [String], onStatus: @escaping @Sendable (String) -> Void) async {
    onStatus("연결됨")
    var reported: [String]? = nil, lastScan = Date.distantPast, sent: [String: String] = [:]
    while !Task.isCancelled {
        try? await Task.sleep(nanoseconds: 3_000_000_000)
        let allowed = folders()
        if reported != allowed, (try? await c.call("POST", "/api/worker/folders", ["folders": allowed]))?.0 == 200 { reported = allowed }
        if reported == allowed, Date().timeIntervalSince(lastScan) > 300 || sent.isEmpty && lastScan == .distantPast {
            lastScan = Date() // 예전에 만든 결과물도 가져온다. 바뀐 것만 보낸다.
            let found = allowed.flatMap { scanArtifacts(URL(fileURLWithPath: $0)) }.filter { sent[$0.key] != $0.hash }
            for batch in stride(from: 0, to: found.count, by: 10).map({ Array(found[$0..<min($0 + 10, found.count)]) }) {
                if (try? await c.call("POST", "/api/worker/artifacts", ["artifacts": batch.map { ["title": $0.key, "html": $0.html] }]))?.0 == 200 { for f in batch { sent[f.key] = f.hash } }
            }
        }
        guard let (status, job) = try? await c.call("GET", "/api/worker/job?caps=local") else { onStatus("서버 연결 재시도 중"); continue }
        if status == 401 { onStatus("연결 해제됨: 이 Claude가 제거됐어요"); return }
        if let id = job["id"] as? Int, job["local"] as? Bool == true, let prompt = job["prompt"] as? String {
            let folder = job["folder"] as? String, chat = job["chat"] as? Bool == true
            // 서버가 보낸 값이라도 이 Mac의 설정을 벗어나면 실행하지 않는다
            let mode = job["mode"] as? String ?? "auto"
            func refuse(_ m: String) async { _ = try? await c.call("POST", "/api/worker/job", ["id": id, "reply": m, "error": true]) }
            guard chat || folder.map(allowed.contains) == true else { await refuse("이 Mac에서 허용하지 않은 폴더예요."); continue }
            // 대화 모드는 폴더 없이 계정별 전용 공간에서 실행한다
            let cwd = folder.map { URL(fileURLWithPath: $0) } ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Clauduo/chat/\(sha(Data((config ?? "default").utf8)).prefix(16))")
            try? FileManager.default.createDirectory(at: cwd, withIntermediateDirectories: true)
            guard ["auto", "acceptEdits", "plan", "bypassPermissions"].contains(mode) else { await refuse("지원하지 않는 권한 모드예요."); continue }
            if mode == "bypassPermissions", !fullAccessAllowed() { await refuse("이 Mac에서 전체 권한이 꺼져 있어요. Mac 앱 사이드바에서 켜 주세요."); continue }
            onStatus("작업 중")
            let opts = RunOptions(session: (job["session"] as? String).flatMap(cleanArg), model: (job["model"] as? String).flatMap(cleanArg), mode: mode, instructions: job["instructions"] as? String ?? "", artifactPrefix: folder.map { URL(fileURLWithPath: $0).lastPathComponent + "/" } ?? "")
            let r = await localRun(folder: cwd, prompt: prompt, config: config, opts: opts) { text, tools in
                let (_, o) = (try? await c.call("POST", "/api/worker/progress", ["id": id, "text": text, "tools": tools])) ?? (0, [:])
                return o["cancel"] as? Bool ?? false
            }
            var body: [String: Any] = ["id": id, "reply": r.text, "files": chat ? [] : r.files, "tools": r.tools, "artifacts": r.artifacts]
            if let session = r.session { body["session"] = session }
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
        let r = await runClaude(cwd: dir, prompt: prompt, config: config)
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

struct RunOptions: Sendable { var session, model: String?; var mode: String; var instructions = ""; var artifactPrefix = "" }

private func artifactTitle(_ prefix: String, _ rel: String) -> String { prefix + (rel as NSString).deletingPathExtension }

/// 허용 폴더의 artifacts/ 안에 있는 HTML을 찾는다.
func scanArtifacts(_ folder: URL) -> [(key: String, html: String, hash: String)] {
    let dir = folder.appendingPathComponent("artifacts"), prefix = folder.lastPathComponent + "/artifacts/"
    return walk(dir, maxSize: 1_500_000, maxFiles: 100).filter { $0.key.hasSuffix(".html") || $0.key.hasSuffix(".htm") }.map { (artifactTitle(prefix, $0.key), String(decoding: $0.value, as: UTF8.self), sha($0.value)) }
}
struct LocalResult { let ok: Bool; let text: String; let files: [[String: String]]; let tools: [String]; let session: String?; let artifacts: [[String: String]] }
struct StreamResult { var ok = false; var text = ""; var tools: [String] = []; var session: String? }

/// 명령행 인자로 해석되지 않도록 값 형식을 제한한다.
func cleanArg(_ v: String) -> String? { v.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", options: .regularExpression) != nil ? v : nil }

func toolLine(_ name: String, _ input: [String: Any]) -> String {
    let detail = ["command", "file_path", "path", "pattern", "url", "query", "description"].compactMap { input[$0] as? String }.first ?? ""
    return String((detail.isEmpty ? name : "\(name): \(detail)").prefix(300))
}

private final class Live: @unchecked Sendable {
    private let lock = NSLock(); private var r = StreamResult(); private var partial = ""; private(set) var done = false
    func update(_ f: (inout StreamResult, inout String) -> Void) { lock.lock(); f(&r, &partial); lock.unlock() }
    func snapshot() -> (String, [String]) { lock.lock(); defer { lock.unlock() }; return (partial, r.tools) }
    func finish() -> StreamResult { lock.lock(); defer { lock.unlock() }; done = true; if r.text.isEmpty { r.text = partial }; return r }
}

/// 사용자의 Claude Code를 설정·플러그인·MCP·전체 도구 그대로 실행한다.
func runClaudeStream(cwd: URL, prompt: String, config: String?, opts: RunOptions, onTick: @escaping @Sendable (String, [String]) async -> Bool) async -> StreamResult {
    guard let claude = findClaude() else { return StreamResult(ok: false, text: "Claude Code를 찾지 못했어요. 먼저 설치하고 로그인해 주세요.") }
    var args = ["-p", "--output-format", "stream-json", "--verbose", "--include-partial-messages", "--permission-mode", opts.mode]
    if let m = opts.model { args += ["--model", m] }
    if let s = opts.session { args += ["--resume", s] }
    args += ["--append-system-prompt", "사용자가 볼 HTML 페이지나 문서를 만들 때는 현재 폴더의 artifacts/이름.html 로 저장해.\(opts.instructions.isEmpty ? "" : "\n\n워크스페이스 지침:\n\(opts.instructions)")"]
    let p = Process(), o = Pipe(), e = Pipe(), i = Pipe()
    p.executableURL = URL(fileURLWithPath: claude); p.arguments = args; p.currentDirectoryURL = cwd; p.environment = claudeEnv(config)
    p.standardOutput = o; p.standardError = e; p.standardInput = i
    do { try p.run() } catch { return StreamResult(ok: false, text: "실행 실패: \(error.localizedDescription)") }
    try? i.fileHandleForWriting.write(contentsOf: Data(prompt.utf8)); try? i.fileHandleForWriting.close()
    let live = Live(), cancelled = Live()
    let ticker = Task.detached {
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            let (t, u) = live.snapshot()
            if await onTick(t, u) { _ = cancelled.finish(); p.terminate(); return }
        }
    }
    let errTask = Task.detached { e.fileHandleForReading.readDataToEndOfFile() }
    do {
        for try await line in o.fileHandleForReading.bytes.lines {
            guard let ev = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any], let type = ev["type"] as? String else { continue }
            live.update { r, partial in
                if let s = ev["session_id"] as? String { r.session = s }
                if type == "assistant", ev["parent_tool_use_id"] == nil || ev["parent_tool_use_id"] is NSNull, let blocks = (ev["message"] as? [String: Any])?["content"] as? [[String: Any]] {
                    for b in blocks {
                        if b["type"] as? String == "tool_use", let n = b["name"] as? String { r.tools.append(toolLine(n, b["input"] as? [String: Any] ?? [:])) }
                    }
                }
                if type == "stream_event", ev["parent_tool_use_id"] == nil || ev["parent_tool_use_id"] is NSNull, let event = ev["event"] as? [String: Any] {
                    if event["type"] as? String == "content_block_start", (event["content_block"] as? [String: Any])?["type"] as? String == "text", !partial.isEmpty { partial += "\n\n" }
                    if event["type"] as? String == "content_block_delta", let d = event["delta"] as? [String: Any], d["type"] as? String == "text_delta", let t = d["text"] as? String { partial += t }
                }
                if type == "result" { r.ok = ev["is_error"] as? Bool != true; r.text = ev["result"] as? String ?? "" }
            }
        }
    } catch {}
    p.waitUntilExit(); ticker.cancel()
    var r = live.finish()
    if cancelled.done { r.ok = false; r.text = "중지했어요." }
    else if r.text.isEmpty { r.ok = false; r.text = "실행 실패: \(String(String(decoding: await errTask.value, as: UTF8.self).prefix(500)))" }
    return r
}

/// 고른 폴더에서 바로 실행하고 파일 변경 내용을 모은다.
func localRun(folder: URL, prompt: String, config: String?, opts: RunOptions, onTick: @escaping @Sendable (String, [String]) async -> Bool) async -> LocalResult {
    let skip: Set<String> = ["node_modules", ".build", "dist", ".DS_Store"]
    let limit = 64_000_000 // ponytail: 큰 폴더는 앞쪽 64MB만 변경 추적, 메모리를 지키기 위한 상한
    let before = walk(folder, skip: skip, maxSize: 256_000, maxFiles: 3000, maxTotal: limit)
    let r = await runClaudeStream(cwd: folder, prompt: prompt, config: config, opts: opts, onTick: onTick)
    let after = walk(folder, skip: skip, maxSize: 256_000, maxFiles: 3000, maxTotal: limit)
    var files: [[String: String]] = []
    for path in Set(before.keys).union(after.keys).sorted() where before[path] != after[path] {
        files.append(["path": path, "status": before[path] == nil ? "added" : after[path] == nil ? "deleted" : "changed", "diff": await unifiedDiff(path, before[path], after[path])])
        if files.count >= 200 { break }
    }
    let artifacts = after.filter { ($0.key.hasSuffix(".html") || $0.key.hasSuffix(".htm")) && before[$0.key] != $0.value }.prefix(20).map { ["title": artifactTitle(opts.artifactPrefix, $0.key), "html": String(decoding: $0.value, as: UTF8.self)] }
    return LocalResult(ok: r.ok, text: r.text, files: files, tools: r.tools, session: r.session, artifacts: artifacts)
}

// ---- Claude Code/앱이 이 Mac에 저장한 세션 불러오기 ----
struct LocalSession: Identifiable, Hashable, Sendable {
    let id, title, cwd: String; let updated: Date; let path: String
    /// Claude의 작업트리에서 한 세션은 원래 프로젝트로 묶는다.
    var projectPath: String { ["/.claude/worktrees/", "/.claude-worktrees/"].compactMap { cwd.range(of: $0).map { String(cwd[..<$0.lowerBound]) } }.first ?? cwd }
    var project: String { projectPath.isEmpty ? "기타" : (projectPath as NSString).lastPathComponent }
}

func sessionsRoot(_ config: String?) -> URL { URL(fileURLWithPath: config ?? NSHomeDirectory() + "/.claude").appendingPathComponent("projects") }

private func visibleText(_ content: Any?) -> String {
    let parts: [String]
    if let s = content as? String { parts = [s] }
    else if let b = content as? [[String: Any]] { parts = b.filter { $0["type"] as? String == "text" }.compactMap { $0["text"] as? String } }
    else { parts = [] }
    // 앱이 자동으로 넣은 시스템 메시지는 대화로 보여주지 않는다
    return parts.filter { p in !["<system-reminder>", "<command-", "<local-command", "Caveat:"].contains { p.hasPrefix($0) } }.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
}

private func lines(_ data: Data) -> [[String: Any]] {
    data.split(separator: 10).compactMap { (try? JSONSerialization.jsonObject(with: Data($0))) as? [String: Any] }
}

/// 최근 세션 목록. 앞부분만 읽어 큰 기록에서도 빠르게 동작한다.
func listSessions(config: String?) -> [LocalSession] {
    let fm = FileManager.default, root = sessionsRoot(config)
    var found: [(URL, Date)] = []
    for dir in (try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? [] {
        for f in (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey])) ?? [] where f.pathExtension == "jsonl" && cleanArg(f.deletingPathExtension().lastPathComponent) != nil {
            found.append((f, (try? f.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast))
        }
    }
    return found.sorted { $0.1 > $1.1 }.compactMap { url, date in
        guard let h = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? h.close() }
        let events = lines(((try? h.read(upToCount: 256_000)) ?? nil) ?? Data())
        guard let first = events.first(where: { $0["type"] as? String == "user" && $0["isSidechain"] as? Bool != true && !visibleText(($0["message"] as? [String: Any])?["content"]).isEmpty }) else { return nil }
        let custom = events.last(where: { $0["type"] as? String == "custom-title" })?["customTitle"] as? String
        let title = custom ?? visibleText((first["message"] as? [String: Any])?["content"])
        return LocalSession(id: url.deletingPathExtension().lastPathComponent, title: String(title.prefix(60)), cwd: first["cwd"] as? String ?? "", updated: date, path: url.path)
    }
}

func uploadSession(_ s: LocalSession, client: Client) async -> Bool {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: s.path), options: .mappedIfSafe) else { return false }
    var turns: [[String: Any]] = [], written: [String: String] = [:], published: [String: String] = [:]
    for e in lines(data) where e["isSidechain"] as? Bool != true && e["isMeta"] as? Bool != true {
        let content = (e["message"] as? [String: Any])?["content"]
        if e["type"] as? String == "user" {
            let t = visibleText(content)
            if !t.isEmpty { turns.append(["role": "user", "text": t, "tools": [String]()]) }
        } else if e["type"] as? String == "assistant" {
            for b in content as? [[String: Any]] ?? [] where b["type"] as? String == "tool_use" {
                guard let input = b["input"] as? [String: Any], let path = input["file_path"] as? String, path.hasSuffix(".html") else { continue }
                if b["name"] as? String == "Write" { written[path] = input["content"] as? String }
                if b["name"] as? String == "Artifact", (input["action"] as? String ?? "publish") == "publish" { published[path] = (input["title"] as? String) ?? ((path as NSString).lastPathComponent as NSString).deletingPathExtension }
            }
            let text = visibleText(content), used = (content as? [[String: Any]] ?? []).filter { $0["type"] as? String == "tool_use" }.map { toolLine($0["name"] as? String ?? "", $0["input"] as? [String: Any] ?? [:]) }
            if text.isEmpty && used.isEmpty { continue }
            if turns.last?["role"] as? String == "assistant" { // 한 번의 응답이 여러 줄로 저장돼 있어 합친다
                var last = turns.removeLast()
                last["text"] = [last["text"] as? String ?? "", text].filter { !$0.isEmpty }.joined(separator: "\n\n")
                last["tools"] = (last["tools"] as? [String] ?? []) + used
                turns.append(last)
            } else { turns.append(["role": "assistant", "text": text, "tools": used]) }
        }
    }
    // 게시했던 아티팩트를 복원한다. 파일이 지워졌으면 세션 기록의 작성 내용을 쓴다.
    let artifacts: [[String: String]] = published.prefix(20).compactMap { path, title in
        let file = (try? Data(contentsOf: URL(fileURLWithPath: path))).map { String(decoding: $0, as: UTF8.self) }
        return (file ?? written[path]).map { ["title": title, "html": $0] }
    }
    let body: [String: Any] = ["sessions": [["id": s.id, "title": s.title, "folder": s.cwd, "project": s.project, "updated": s.updated.timeIntervalSince1970 * 1000, "turns": Array(turns.suffix(300)), "artifacts": artifacts]]]
    return (try? await client.call("POST", "/api/worker/sessions", body))?.0 == 200
}

// ---- 앱 업데이트: clauduo.com의 latest.json을 확인하고 DMG로 교체한다 ----
struct UpdateInfo: Decodable, Sendable { let version, url, sha256: String }

enum Updater {
    static var current: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }

    static func check() async -> UpdateInfo? {
        guard let (d, r) = try? await URLSession.shared.data(for: URLRequest(url: URL(string: siteURL + "/mac/latest.json")!, cachePolicy: .reloadIgnoringLocalCacheData)), (r as? HTTPURLResponse)?.statusCode == 200,
              let info = try? JSONDecoder().decode(UpdateInfo.self, from: d),
              info.version.compare(current, options: .numeric) == .orderedDescending else { return nil }
        return info
    }

    struct Failure: LocalizedError { let errorDescription: String? }
    private static func run(_ tool: String, _ args: [String]) async throws {
        let r = await execute(tool, args, cwd: nil, input: nil)
        if r.code != 0 { throw Failure(errorDescription: String(decoding: r.err, as: UTF8.self)) }
    }

    /// 내려받아 검증한 뒤, 앱이 종료되면 교체하는 스크립트를 띄운다. 호출한 쪽에서 앱을 종료해야 한다.
    static func install(_ info: UpdateInfo, relaunch: Bool) async throws {
        let target = Bundle.main.bundleURL, site = URL(string: siteURL)!, fm = FileManager.default
        guard fm.isWritableFile(atPath: target.deletingLastPathComponent().path), !target.path.hasPrefix("/Volumes/") else {
            throw Failure(errorDescription: "앱을 응용 프로그램 폴더로 옮긴 뒤 다시 시도해 주세요.")
        }
        // 업데이트는 Clauduo 서버에서만 받는다
        guard let url = URL(string: info.url, relativeTo: site)?.absoluteURL, url.host == site.host, url.scheme == site.scheme else { throw Failure(errorDescription: "잘못된 업데이트 주소예요.") }
        let (file, _) = try await URLSession.shared.download(from: url)
        defer { try? fm.removeItem(at: file) }
        guard let data = try? Data(contentsOf: file, options: .mappedIfSafe), sha(data) == info.sha256 else { throw Failure(errorDescription: "내려받은 파일 검증에 실패했어요.") }
        let work = fm.temporaryDirectory.appendingPathComponent("clauduo-update-\(UUID().uuidString)"), mount = work.appendingPathComponent("m"), staged = work.appendingPathComponent("Clauduo.app")
        try fm.createDirectory(at: mount, withIntermediateDirectories: true)
        let dmg = work.appendingPathComponent("u.dmg"); try fm.copyItem(at: file, to: dmg)
        try await run("/usr/bin/hdiutil", ["attach", dmg.path, "-nobrowse", "-readonly", "-mountpoint", mount.path])
        do { try await run("/usr/bin/ditto", [mount.appendingPathComponent("Clauduo.app").path, staged.path]) }
        catch { try? await run("/usr/bin/hdiutil", ["detach", mount.path, "-force"]); throw error }
        try await run("/usr/bin/hdiutil", ["detach", mount.path, "-force"])
        try await run("/usr/bin/codesign", ["--verify", "--deep", staged.path])
        let script = #"while kill -0 "$1" 2>/dev/null; do sleep 0.2; done; rm -rf "$2"; /usr/bin/ditto "$3" "$2"; rm -rf "$4"; [ "$5" = 1 ] && /usr/bin/open "$2""#
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", script, "sh", String(getpid()), target.path, staged.path, work.path, relaunch ? "1" : "0"]
        try p.run()
    }
}
