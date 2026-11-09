import AppKit
import Security
import SwiftUI
import WebKit

/// 연결 토큰 저장소. 임시 서명 앱은 업데이트마다 서명이 바뀌어 키체인이 매번 비밀번호를 묻는다.
/// ponytail: 권한 0600 파일에 저장(Clauduo 연결 토큰만, Claude 로그인 정보 아님). Apple 서명을 쓰게 되면 키체인으로 되돌린다.
enum Keychain {
    private static var dir: URL { FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Clauduo/tokens") }
    private static func file(_ key: String) -> URL { dir.appendingPathComponent(sha(Data(key.utf8))) }
    private static func query(_ key: String) -> [String: Any] { [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.clauduo.mac", kSecAttrAccount as String: key] }
    static func load(_ key: String) -> String? { try? String(contentsOf: file(key), encoding: .utf8) }
    /// 이전 버전이 키체인에 넣어 둔 토큰을 옮긴다. macOS 권한 창이 뜨므로 사용자가 눌렀을 때만 호출한다.
    static func recover(_ key: String) {
        var q = query(key); q[kSecReturnData as String] = true
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data, let v = String(data: d, encoding: .utf8) else { return }
        save(key, v); SecItemDelete(query(key) as CFDictionary)
    }
    static func save(_ key: String, _ v: String) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        FileManager.default.createFile(atPath: file(key).path, contents: Data(v.utf8), attributes: [.posixPermissions: 0o600])
    }
    static func clear(_ key: String) { try? FileManager.default.removeItem(at: file(key)) }
}

/// config가 nil이면 이 Mac에 이미 로그인된 기본 계정이다.
struct Account: Codable, Identifiable, Hashable {
    var key: String, name: String, agentId: String, ws: String
    var config: String?
    var id: String { key }
}

enum Accounts {
    static var list: [Account] {
        get {
            if let d = UserDefaults.standard.data(forKey: "accounts"), let a = try? JSONDecoder().decode([Account].self, from: d) { return a }
            return []
        }
        set { UserDefaults.standard.set(try? JSONEncoder().encode(newValue), forKey: "accounts") }
    }
}

enum Folders {
    static var list: [String] { get { UserDefaults.standard.stringArray(forKey: "allowedFolders") ?? [] } set { UserDefaults.standard.set(newValue, forKey: "allowedFolders") } }
}

/// 앱 전체가 사이트 하나를 보여주고, 사이트는 이 브리지로 Mac 기능을 부른다.
final class Web: NSObject, WKUIDelegate, WKNavigationDelegate, WKScriptMessageHandler {
    static let shared = Web()
    let view: WKWebView
    var model: Model?
    override init() {
        let cfg = WKWebViewConfiguration()
        view = WKWebView(frame: .zero, configuration: cfg)
        super.init()
        cfg.userContentController.add(self, name: "clauduo")
        view.uiDelegate = self; view.navigationDelegate = self
        view.underPageBackgroundColor = .clear
        view.load(URLRequest(url: URL(string: siteURL + "/app")!))
    }
    func userContentController(_ c: WKUserContentController, didReceive m: WKScriptMessage) {
        // 브리지는 Clauduo 페이지에서만 받는다
        guard m.frameInfo.isMainFrame, m.frameInfo.request.url?.host == URL(string: siteURL)!.host, let action = m.body as? String else { return }
        if action.hasPrefix("{"), let d = action.data(using: .utf8), let state = try? JSONDecoder().decode(SiteState.self, from: d) {
            Task { @MainActor in self.model?.apply(state) }
            return
        }
        Task { @MainActor in
            if action == "customize" { self.model?.showCustomize = true } else if action == "connect" { self.model?.showAdd = true } else if action == "addFolder" { self.model?.addFolder() }
        }
    }
    func webView(_ w: WKWebView, runJavaScriptAlertPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler h: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = m; a.runModal(); h()
    }
    func webView(_ w: WKWebView, runJavaScriptConfirmPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler h: @escaping (Bool) -> Void) {
        let a = NSAlert(); a.messageText = m; a.addButton(withTitle: "확인"); a.addButton(withTitle: "취소")
        h(a.runModal() == .alertFirstButtonReturn)
    }
    func webView(_ w: WKWebView, runJavaScriptTextInputPanelWithPrompt m: String, defaultText d: String?, initiatedByFrame f: WKFrameInfo, completionHandler h: @escaping (String?) -> Void) {
        let a = NSAlert(); a.messageText = m; a.addButton(withTitle: "확인"); a.addButton(withTitle: "취소")
        let t = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24)); t.stringValue = d ?? ""; a.accessoryView = t
        h(a.runModal() == .alertFirstButtonReturn ? t.stringValue : nil)
    }
    func webView(_ w: WKWebView, runOpenPanelWith p: WKOpenPanelParameters, initiatedByFrame f: WKFrameInfo, completionHandler h: @escaping ([URL]?) -> Void) {
        let o = NSOpenPanel(); o.canChooseFiles = !p.allowsDirectories; o.canChooseDirectories = p.allowsDirectories; o.allowsMultipleSelection = p.allowsMultipleSelection
        o.begin { h($0 == .OK ? o.urls : nil) }
    }
    func webView(_ w: WKWebView, decidePolicyFor a: WKNavigationAction, decisionHandler h: @escaping (WKNavigationActionPolicy) -> Void) {
        // 이 앱에서는 Clauduo만 연다. 다른 주소는 기본 브라우저로 보낸다.
        if let u = a.request.url, let host = u.host, host != URL(string: siteURL)!.host { NSWorkspace.shared.open(u); return h(.cancel) }
        h(.allow)
    }
}

struct WebTab: NSViewRepresentable {
    func makeNSView(context: Context) -> WKWebView { Web.shared.view }
    func updateNSView(_ v: WKWebView, context: Context) {}
}

struct SiteThread: Decodable, Identifiable { let id, title, env, kind: String; let busy: Bool; let project: String? }
struct SiteAgent: Decodable, Identifiable { let id, name, mode: String; let online: Bool; let mine: Bool? }
struct SiteWorkspace: Decodable, Identifiable { let id, name, role: String }
struct SiteState: Decodable { let signedIn: Bool; let view: String; let cur, ws, email, kind, agent: String?; let agents: [SiteAgent]; let workspaces: [SiteWorkspace]; let threads: [SiteThread] }
enum Destination: Hashable { case view(String), thread(String), agent(String) }

@MainActor final class Model: ObservableObject {
    @Published var site: SiteState?
    @Published var selection: Destination?

    func apply(_ s: SiteState) { site = s; let d = destination(s); if selection != d { selection = d } }

    private func destination(_ s: SiteState) -> Destination { s.view == "thread" ? .thread(s.cur ?? "") : s.view == "agent" ? .agent(s.agent ?? "") : .view(s.view) }

    /// 사이트의 Claude가 이 Mac의 어떤 계정인지 찾는다. 예전 버전으로 연결된 계정은 agentId가 비어 있다.
    func account(for a: SiteAgent) -> Account? {
        if let m = accounts.first(where: { $0.agentId == a.id }) { return m }
        let claimed = Set(accounts.map(\.agentId))
        let firstFree = site?.agents.first { $0.mode == "worker" && $0.mine == true && !claimed.contains($0.id) }
        return firstFree?.id == a.id ? accounts.first { $0.agentId.isEmpty } : nil
    }

    func go(_ d: Destination?) {
        guard let d, d != currentSite else { return }
        switch d {
        case .view(let v): call("clauduoNav(v)", ["v": v])
        case .thread(let id): call("clauduoNav('thread', id)", ["id": id])
        case .agent(let name): call("clauduoNav('agent', name)", ["name": name])
        }
    }
    private var currentSite: Destination? { site.map(destination) }
    func setKind(_ k: String) { call("clauduoKind(k)", ["k": k]) }
    func selectWorkspace(_ id: String) { call("clauduoWs(id)", ["id": id]) }
    func logout() { call("clauduoLogout()", [:]) }
    private func call(_ js: String, _ args: [String: Any]) { Web.shared.view.callAsyncJavaScript(js, arguments: args, in: nil, in: .page) { _ in } }

    @Published var accounts = Accounts.list
    @Published var status: [String: String] = [:]
    @Published var showAdd = false
    @Published var showCustomize = false
    @Published var showImport = false
    @Published var adding = false
    private var loops: [String: Task<Void, Never>] = [:]

    @Published var update: UpdateInfo?
    @Published var updating = false
    private var begun = false
    var missingTokens: [Account] { accounts.filter { Keychain.load($0.key) == nil } }
    func recoverTokens() { for a in missingTokens { Keychain.recover(a.key); start(a) }; objectWillChange.send() }

    /// 동의 전에는 계정, 네트워크, 키체인을 건드리지 않는다.
    func begin() {
        guard !begun else { return }; begun = true
        accounts.forEach(start)
        Task { for _ in 0... { await refreshUpdate(); try? await Task.sleep(nanoseconds: 6 * 3600 * 1_000_000_000) } }
    }
    func refreshUpdate(announce: Bool = false) async {
        update = await Updater.check()
        if announce, update == nil { notify("최신 버전이에요. (\(Updater.current))") }
    }
    func installUpdate() async {
        guard let info = update, !updating else { return }
        updating = true; defer { updating = false }
        do { try await Updater.install(info, relaunch: true); NSApp.terminate(nil) }
        catch { notify("업데이트하지 못했어요: \(error.localizedDescription)") }
    }

    func start(_ a: Account) {
        loops[a.key]?.cancel()
        guard let token = Keychain.load(a.key) else { return }
        let c = Client(url: siteURL, token: token), key = a.key, config = a.config
        loops[a.key] = Task.detached { await workerLoop(c, config: config, fullAccessAllowed: { UserDefaults.standard.bool(forKey: "fullAccess") }, folders: { Folders.list }) { s in Task { @MainActor in self.status[key] = s } } }
    }

    private func site(_ js: String, _ args: [String: Any]) async -> [String: Any]? {
        guard Web.shared.view.url?.host == URL(string: siteURL)!.host,
              let raw = try? await Web.shared.view.callAsyncJavaScript(js, arguments: args, contentWorld: .page) as? String,
              let o = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] else { return nil }
        return o
    }

    /// 계정마다 Claude 로그인 폴더를 따로 둔다. 로그인은 Claude의 공식 브라우저 절차로만 한다.
    func add(name: String, useCurrent: Bool) async {
        adding = true; defer { adding = false }
        var config: String?
        let key = "agent-\(UUID().uuidString)"
        if !useCurrent {
            let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Clauduo/accounts/\(key)")
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            guard await claudeAuth("login", config: dir.path) else { try? FileManager.default.removeItem(at: dir); notify("Claude 로그인을 마치지 못했어요."); return }
            config = dir.path
        }
        if await createAgent(name: name, config: config, key: key) == false, let config { _ = await claudeAuth("logout", config: config); try? FileManager.default.removeItem(atPath: config) }
    }

    /// 다시 로그인하지 않고 같은 Claude 계정을 지금 워크스페이스에도 연결한다.
    func link(_ a: Account) async {
        adding = true; defer { adding = false }
        _ = await createAgent(name: a.name == "기본 계정" ? "기본" : a.name, config: a.config, key: "agent-\(UUID().uuidString)")
    }

    private func createAgent(name: String, config: String?, key: String) async -> Bool {
        let js = """
        const ws = localStorage['clauduo.ws'];
        if (!ws) return JSON.stringify({ status: 0 });
        const r = await fetch(`/api/w/${ws}/agents`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name, mode: 'worker' }) });
        return JSON.stringify({ status: r.status, ws, body: await r.json() });
        """
        let o = await site(js, ["name": name]), body = o?["body"] as? [String: Any]
        guard o?["status"] as? Int == 200, let cmd = body?["command"] as? String, let token = cmd.components(separatedBy: " ").last, let id = body?["id"] as? String else {
            notify((body?["error"] as? String) ?? "먼저 로그인하고 워크스페이스를 만들어 주세요."); return false
        }
        let a = Account(key: key, name: name, agentId: id, ws: o?["ws"] as? String ?? "", config: config)
        Keychain.save(key, token); accounts.append(a); Accounts.list = accounts; start(a); showAdd = false
        return true
    }

    func remove(_ a: Account) async {
        let alert = NSAlert(); alert.messageText = "\(a.name) 계정을 제거할까요?"; alert.informativeText = a.config == nil ? "이 앱과의 연결만 끊어요." : "이 앱에 저장된 해당 계정의 로그인도 지워져요."
        alert.addButton(withTitle: "제거"); alert.addButton(withTitle: "취소")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        loops[a.key]?.cancel(); loops[a.key] = nil
        if !a.agentId.isEmpty { _ = await site("const r = await fetch(`/api/w/${ws}/agents/${id}`, { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: '{}' }); return JSON.stringify({ status: r.status });", ["ws": a.ws, "id": a.agentId]) }
        // 같은 로그인을 다른 워크스페이스에서도 쓰고 있으면 로그아웃하지 않는다
        if let config = a.config, accounts.filter({ $0.config == config }).count == 1 { _ = await claudeAuth("logout", config: config); try? FileManager.default.removeItem(atPath: config) }
        Keychain.clear(a.key); accounts.removeAll { $0 == a }; Accounts.list = accounts; status[a.key] = nil
    }

    private func notify(_ m: String) { let a = NSAlert(); a.messageText = m; a.runModal() }

    func addFolder() {
        let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = false; p.prompt = "허용"
        p.message = "Claude가 이 폴더의 파일을 읽고 고칠 수 있게 허용합니다."
        if p.runModal() == .OK, let path = p.url?.path, !Folders.list.contains(path) { Folders.list.append(path) }
    }
}

struct Sidebar: View {
    @ObservedObject var model: Model
    @AppStorage("fullAccess") private var fullAccess = false
    @State private var open: [String: Bool] = [:]
    private var kind: String { model.site?.kind ?? "code" }
    private var threads: [SiteThread] { (model.site?.threads ?? []).filter { $0.kind == kind } }
    private var groups: [(name: String, items: [SiteThread])] { // 최근 작업 순서를 유지한다
        var out: [(name: String, items: [SiteThread])] = []
        for t in threads {
            let n = t.project ?? (t.env == "cloud" ? "공유 작업공간" : "기타")
            if let i = out.firstIndex(where: { $0.name == n }) { out[i].items.append(t) } else { out.append((n, [t])) }
        }
        return out
    }
    private func row(_ t: SiteThread) -> some View {
        HStack {
            Label(t.title, systemImage: t.env == "local" ? "laptopcomputer" : "cloud").lineLimit(1)
            Spacer()
            if t.busy { ProgressView().controlSize(.mini) }
        }.tag(Destination.thread(t.id))
    }
    var body: some View {
        List(selection: Binding(get: { model.selection }, set: { model.selection = $0; model.go($0) })) {
            Section {
                Label("새 작업", systemImage: "square.and.pencil").tag(Destination.view("home"))
                Label("검색", systemImage: "magnifyingglass").tag(Destination.view("search"))
                Label("아티팩트", systemImage: "square.on.square").tag(Destination.view("artifacts"))
                Label("예약", systemImage: "clock").tag(Destination.view("schedule"))
                Label("맞춤 설정", systemImage: "slider.horizontal.3").tag(Destination.view("custom"))
                Label("워크스페이스", systemImage: "square.stack").tag(Destination.view("workspaces"))
                Label("팀 대화", systemImage: "bubble.left.and.bubble.right").tag(Destination.view("room"))
                Label("공유 파일", systemImage: "folder").tag(Destination.view("files"))
                Label("Claude와 팀원", systemImage: "person.2").tag(Destination.view("team"))
            }
            Section {
                ForEach(model.site?.agents ?? []) { a in
                    let local = model.account(for: a)
                    HStack {
                        Label(a.name, systemImage: a.mode == "api" ? "cloud" : "person.crop.circle")
                        Spacer()
                        Circle().fill(a.online ? Color.green : Color.secondary).frame(width: 7, height: 7).accessibilityLabel(a.online ? "접속 중" : "연결 대기")
                    }
                    .tag(Destination.agent(a.name))
                    .contextMenu { if let local { Button("이 Mac에서 제거", role: .destructive) { Task { await model.remove(local) } } } }
                }
                if model.site?.agents.isEmpty ?? true { Text("연결된 계정이 없어요.").foregroundStyle(.secondary) }
                if !model.missingTokens.isEmpty { Button("이전 연결 복구 (\(model.missingTokens.count))") { model.recoverTokens() }.help("이전 버전이 키체인에 저장한 연결을 가져와요. macOS가 권한을 물어볼 수 있어요.") }
                Toggle("전체 권한 허용", isOn: $fullAccess).help("켜면 입력창에서 '전체 권한'을 고른 작업이 확인 없이 명령을 실행해요.")
            } header: {
                HStack { Text("Claude 계정"); Spacer(); Button { model.showAdd = true } label: { Image(systemName: "plus") }.buttonStyle(.plain).accessibilityLabel("계정 추가") }
            }
            if kind == "chat" {
                Section("대화") {
                    if threads.isEmpty { Text("아직 대화가 없어요.").foregroundStyle(.secondary) }
                    ForEach(threads) { row($0) }
                }
            } else {
                Section("프로젝트") {
                    if threads.isEmpty { Text("아직 작업이 없어요.").foregroundStyle(.secondary) }
                    ForEach(Array(groups.enumerated()), id: \.element.name) { i, g in
                        DisclosureGroup(isExpanded: Binding(get: { open[g.name] ?? (i < 3 || g.items.contains { model.selection == .thread($0.id) }) }, set: { open[g.name] = $0 })) {
                            ForEach(g.items) { row($0) }
                        } label: {
                            HStack { Label(g.name, systemImage: "folder").lineLimit(1); Spacer(); Text("\(g.items.count)").font(.caption).foregroundStyle(.secondary) }
                        }
                    }
                }
            }
        }
        .safeAreaInset(edge: .top) {
            Picker("모드", selection: Binding(get: { model.site?.kind ?? "code" }, set: { model.setKind($0) })) { Text("Chat").tag("chat"); Text("Code").tag("code") }
                .pickerStyle(.segmented).labelsHidden().padding(.horizontal, 12).padding(.bottom, 4)
        }
        .safeAreaInset(edge: .bottom) {
            HStack {
                Text(model.site?.email ?? "").font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                Spacer()
                Button("로그아웃") { model.logout() }.buttonStyle(.link).font(.caption)
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
        }
        .navigationSplitViewColumnWidth(min: 220, ideal: 260, max: 340)
    }
}

struct AddAccount: View {
    @ObservedObject var model: Model
    @State private var name = ""
    @State private var current = false
    private var valid: Bool { name.range(of: "^[\\w가-힣-]{1,30}$", options: .regularExpression) != nil && !["all", "모두", "system"].contains(name) }
    private var here: [Account] { model.accounts.filter { $0.ws == model.site?.ws || $0.agentId.isEmpty } }
    private var currentTaken: Bool { here.contains { $0.config == nil } }
    private var reusable: [Account] { // 로그인 폴더 기준으로 한 번씩만 보여준다
        var seen = Set<String>()
        return model.accounts.filter { a in !here.contains { $0.config == a.config } && seen.insert(a.config ?? "default").inserted }
    }
    var body: some View {
        Form {
            TextField("이름 (공백 없이)", text: $name)
            if !reusable.isEmpty {
                Section("다른 워크스페이스의 계정을 여기에 연결") {
                    ForEach(reusable) { a in HStack { Text(a.name); Spacer(); Button("연결") { Task { await model.link(a) } }.disabled(model.adding) } }
                }
            }
            Toggle("이 Mac에 이미 로그인된 Claude 계정 사용", isOn: $current).disabled(currentTaken)
            if !current { Text("브라우저에서 추가할 Claude 계정으로 로그인해 주세요. 이미 다른 계정이 로그인돼 있으면 먼저 바꿔 주세요.").font(.caption).foregroundStyle(.secondary) }
        }
        .formStyle(.grouped).frame(width: 400)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("취소") { model.showAdd = false }.disabled(model.adding) }
            ToolbarItem(placement: .confirmationAction) {
                if model.adding { ProgressView().controlSize(.small) } else { Button("추가") { Task { await model.add(name: name, useCurrent: current) } }.disabled(!valid) }
            }
        }
    }
}

/// Claude 앱과 Claude Code가 이 Mac에 저장한 세션 중 고른 것만 올린다. 불러온 세션은 본인에게만 보인다.
struct ImportSessions: View {
    @ObservedObject var model: Model
    @State private var key = ""
    @State private var sessions: [LocalSession] = []
    @State private var picked = Set<String>()
    @State private var busy = false
    @State private var note = ""
    @State private var done = 0
    @State private var total = 0
    @State private var loading = false
    @State private var opened = Set<String>()
    private var groups: [(name: String, path: String, items: [LocalSession])] {
        var out: [(name: String, path: String, items: [LocalSession])] = []
        for s in sessions { if let i = out.firstIndex(where: { $0.path == s.projectPath }) { out[i].items.append(s) } else { out.append((s.project, s.projectPath, [s])) } }
        return out
    }
    private var account: Account? { model.accounts.first { $0.key == key } }
    private func load() {
        picked = []; sessions = []; note = ""; loading = true
        let config = account?.config
        Task.detached { let list = listSessions(config: config); await MainActor.run { sessions = list; loading = false } }
    }
    private func importAll() async {
        let a = NSAlert(); a.messageText = "세션 \(sessions.count)개를 모두 불러올까요?"; a.informativeText = "대화 내용이 Clauduo 서버에 저장돼요. 불러온 세션은 나에게만 보여요."
        a.addButton(withTitle: "모두 불러오기"); a.addButton(withTitle: "취소")
        if a.runModal() == .alertFirstButtonReturn { await start(sessions) }
    }
    private func start(_ list: [LocalSession]) async {
        guard let a = account, let token = Keychain.load(a.key) else { return }
        busy = true; defer { busy = false }
        let c = Client(url: siteURL, token: token)
        var failed = 0
        done = 0; total = list.count; note = ""
        for s in list { if await uploadSession(s, client: c) == false { failed += 1 }; done += 1 }
        if failed == 0 { model.showImport = false } else { note = "\(failed)개를 불러오지 못했어요." }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("계정", selection: $key) { ForEach(model.accounts) { Text($0.name).tag($0.key) } }
            Text("불러온 세션은 나에게만 보여요. 이어서 작업하려면 해당 폴더를 허용해 주세요.").font(.caption).foregroundStyle(.secondary)
            List {
                ForEach(groups, id: \.path) { g in
                    DisclosureGroup(isExpanded: Binding(get: { opened.contains(g.path) }, set: { if $0 { opened.insert(g.path) } else { opened.remove(g.path) } })) {
                        ForEach(g.items) { s in
                            Toggle(isOn: Binding(get: { picked.contains(s.id) }, set: { if $0 { picked.insert(s.id) } else { picked.remove(s.id) } })) {
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(s.title).lineLimit(1)
                                    Text(s.updated.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    } label: {
                        Toggle(isOn: Binding(get: { g.items.allSatisfy { picked.contains($0.id) } }, set: { on in for s in g.items { if on { picked.insert(s.id) } else { picked.remove(s.id) } } })) {
                            HStack { Text(g.name).bold().lineLimit(1).help(g.path); Spacer(); Text("\(g.items.count)개").font(.caption).foregroundStyle(.secondary) }
                        }
                    }
                }
            }.frame(height: 340)
            HStack {
                Text(note).font(.caption).foregroundStyle(.red)
                Spacer()
                if loading { ProgressView().controlSize(.small); Text("세션 찾는 중").font(.caption).foregroundStyle(.secondary) }
                if busy { ProgressView().controlSize(.small); Text("\(done)/\(total)").font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
                Button("닫기") { model.showImport = false }.disabled(busy)
                Button("전체 불러오기 (\(sessions.count))") { Task { await importAll() } }.disabled(sessions.isEmpty || busy)
                Button("선택 불러오기 (\(picked.count))") { let list = sessions.filter { picked.contains($0.id) }; Task { await start(list) } }.buttonStyle(.borderedProminent).disabled(picked.isEmpty || busy)
            }
        }
        .padding().frame(width: 560)
        .onAppear { key = model.accounts.first?.key ?? ""; load() }
        .onChange(of: key) { _, _ in load() }
    }
}

/// 계정별 Claude 설정. 로그인 정보는 복사하지 않는다.
struct CustomizeAccount: View {
    @ObservedObject var model: Model
    @State private var key = ""
    @State private var text = ""
    @State private var note = ""
    private var account: Account? { model.accounts.first { $0.key == key } }
    private func dir(_ a: Account?) -> URL { a?.config.map { URL(fileURLWithPath: $0) } ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".claude") }
    private func load() { text = (try? String(contentsOf: dir(account).appendingPathComponent("CLAUDE.md"), encoding: .utf8)) ?? ""; note = "" }
    private func copyDefaults() {
        let fm = FileManager.default, src = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".claude"), dst = dir(account)
        guard account?.config != nil else { return }
        for item in ["CLAUDE.md", "settings.json", "skills", "agents", "commands", "plugins"] where fm.fileExists(atPath: src.appendingPathComponent(item).path) {
            try? fm.removeItem(at: dst.appendingPathComponent(item)); try? fm.copyItem(at: src.appendingPathComponent(item), to: dst.appendingPathComponent(item))
        }
        // .claude.json에는 계정 정보가 있어서 MCP 서버 설정만 옮긴다
        let srcJSON = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".claude.json"), dstJSON = dst.appendingPathComponent(".claude.json")
        if let d = try? Data(contentsOf: srcJSON), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let mcp = o["mcpServers"] {
            var t = (try? Data(contentsOf: dstJSON)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            t["mcpServers"] = mcp
            try? JSONSerialization.data(withJSONObject: t, options: .prettyPrinted).write(to: dstJSON)
        }
        load(); note = "복사했어요."
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("계정", selection: $key) { ForEach(model.accounts) { Text($0.name).tag($0.key) } }
            Text("이 계정의 전역 지침 (CLAUDE.md)").font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $text).font(.system(.body, design: .monospaced)).frame(height: 220)
            HStack {
                Button("기본 계정 설정 복사") { copyDefaults() }.disabled(account?.config == nil).help("지침, 설정, 스킬, 에이전트, 명령, 플러그인, MCP 서버를 복사해요. 기존 항목은 덮어써요.")
                Text(note).font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("닫기") { model.showCustomize = false }
                Button("저장") { try? text.write(to: dir(account).appendingPathComponent("CLAUDE.md"), atomically: true, encoding: .utf8); note = "저장했어요." }.buttonStyle(.borderedProminent).disabled(account == nil)
            }
        }
        .padding().frame(width: 520)
        .onAppear { key = model.accounts.first?.key ?? ""; load() }
        .onChange(of: key) { _, _ in load() }
    }
}

struct Root: View {
    @ObservedObject var model: Model
    @State private var columns = NavigationSplitViewVisibility.detailOnly
    var body: some View {
        NavigationSplitView(columnVisibility: $columns) {
            Sidebar(model: model)
        } detail: {
            WebTab().ignoresSafeArea(edges: .bottom)
        }
        .toolbar {
            if model.site?.signedIn == true {
                ToolbarItem(placement: .navigation) {
                    Menu {
                        Section("내 워크스페이스") { ForEach((model.site?.workspaces ?? []).filter { $0.role == "owner" }) { w in Button(w.name + (w.id == model.site?.ws ? " ✓" : "")) { model.selectWorkspace(w.id) } } }
                        Section("초대받은 워크스페이스") { ForEach((model.site?.workspaces ?? []).filter { $0.role != "owner" }) { w in Button(w.name + (w.id == model.site?.ws ? " ✓" : "")) { model.selectWorkspace(w.id) } } }
                    } label: { Label(model.site?.workspaces.first { $0.id == model.site?.ws }?.name ?? "워크스페이스", systemImage: "square.stack").labelStyle(.titleAndIcon) }
                }
                ToolbarItem(placement: .status) {
                    Label(model.accounts.isEmpty ? "이 Mac 연결 안 됨" : "로컬 계정 \(model.accounts.count)개", systemImage: model.accounts.isEmpty ? "laptopcomputer.slash" : "laptopcomputer").labelStyle(.titleAndIcon).font(.caption).foregroundStyle(.secondary)
                }
                ToolbarSpacer(.flexible)
                if let u = model.update {
                    ToolbarItem {
                        Button { Task { await model.installUpdate() } } label: { Label(model.updating ? "업데이트 중" : "\(u.version) 업데이트", systemImage: "arrow.down.circle").labelStyle(.titleAndIcon) }.disabled(model.updating)
                    }
                }
                ToolbarItemGroup {
                    Button { model.showImport = true } label: { Label("세션 불러오기", systemImage: "clock.arrow.circlepath") }.disabled(model.accounts.isEmpty)
                    Button { model.showAdd = true } label: { Label("계정 추가", systemImage: "person.crop.circle.badge.plus") }
                    Button { model.addFolder() } label: { Label("폴더 허용", systemImage: "folder.badge.plus") }
                }
                ToolbarSpacer(.fixed)
                ToolbarItem {
                    Button { model.go(.view("home")) } label: { Label("새 작업", systemImage: "square.and.pencil") }.buttonStyle(.glassProminent)
                }
            }
        }
        .font(.custom("Pretendard Variable", size: 13))
        .frame(minWidth: 1000, minHeight: 680)
        .sheet(isPresented: $model.showAdd) { AddAccount(model: model) }
        .sheet(isPresented: $model.showImport) { ImportSessions(model: model) }
        .sheet(isPresented: $model.showCustomize) { CustomizeAccount(model: model) }
        .onAppear { Web.shared.model = model }
        .onChange(of: model.site?.signedIn) { _, on in withAnimation { columns = on == true ? .all : .detailOnly } }
    }
}

/// 첫 실행 안내와 동의. 내용을 바꾸면 consentVersion을 올려 다시 동의받는다.
struct Onboarding: View {
    let agree: () -> Void
    @State private var checked = false
    private let items: [(String, String, String)] = [
        ("laptopcomputer", "내 Mac에서 실행", "허용한 폴더에서 이 Mac의 Claude Code가 파일을 읽고 고치며, 선택한 권한에 따라 명령을 실행해요."),
        ("icloud", "서버에 저장되는 내용", "대화, 작업 기록, 파일 변경 내용, 아티팩트, 불러온 세션은 Clauduo 서버(Cloudflare)에 저장돼요. 팀 작업은 워크스페이스 멤버에게 보이고, 불러온 세션은 나에게만 보여요."),
        ("key", "로그인과 연결 정보", "Claude 로그인은 Claude의 공식 절차로 진행되고 Clauduo 서버로 보내지 않아요. Clauduo 연결 토큰은 이 Mac의 사용자 전용 파일에 저장돼요."),
        ("exclamationmark.triangle", "베타 서비스", "기능과 데이터가 바뀌거나 사라질 수 있어요. 중요한 파일은 따로 백업해 주세요. Claude 사용량과 요금, 각 계정의 약관 준수는 사용자 책임이에요."),
        ("building.2", "독립 서비스", "Clauduo는 Anthropic과 제휴 관계가 없는 독립 서비스예요."),
    ]
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Clauduo 시작하기").font(.custom("Pretendard Variable", size: 26).weight(.semibold))
            Text("사용 전에 아래 내용을 확인해 주세요.").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 14) {
                ForEach(items, id: \.1) { icon, title, text in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: icon).frame(width: 22).foregroundStyle(.secondary).accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) { Text(title).fontWeight(.semibold); Text(text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
                    }
                }
            }
            Toggle("위 내용을 확인했고 동의합니다", isOn: $checked)
            HStack {
                Button("종료") { NSApp.terminate(nil) }
                Spacer()
                Button("동의하고 시작하기") { agree() }.buttonStyle(.glassProminent).disabled(!checked)
            }
        }
        .font(.custom("Pretendard Variable", size: 14))
        .padding(30).frame(width: 540)
        .glassEffect(in: .rect(cornerRadius: 24))
        .frame(minWidth: 1000, maxWidth: .infinity, minHeight: 680, maxHeight: .infinity)
    }
}

let consentVersion = 1

struct ClauduoApp: App {
    @StateObject private var model = Model()
    @AppStorage("consentVersion") private var agreed = 0
    var body: some Scene {
        WindowGroup("Clauduo") {
            if agreed >= consentVersion { Root(model: model).onAppear { model.begin() } }
            else { Onboarding { agreed = consentVersion } }
        }.windowToolbarStyle(.unified)
            .commands { CommandGroup(after: .appInfo) { Button("업데이트 확인…") { Task { await model.refreshUpdate(announce: true); if model.update != nil { await model.installUpdate() } } } } }
    }
}

@main struct Entry {
    static func main() {
        let a = CommandLine.arguments
        // 테스트와 자동화용 실행 모드
        if a.count == 4, a[1] == "--worker" {
            Task { let f = ProcessInfo.processInfo.environment["CLAUDUO_FOLDERS"]?.components(separatedBy: ":") ?? []; await workerLoop(Client(url: a[2], token: a[3]), config: ProcessInfo.processInfo.environment["CLAUDUO_CONFIG_DIR"], fullAccessAllowed: { ProcessInfo.processInfo.environment["CLAUDUO_FULL"] != nil }, folders: { f }) { print($0) }; exit(0) }
            dispatchMain()
        }
        if a.count == 2, a[1] == "--version" { print(Updater.current); exit(0) }
        if a.count == 2, a[1] == "--self-update" { // 업데이트 절차 시험용
            Task { guard let u = await Updater.check() else { exit(3) }; do { try await Updater.install(u, relaunch: false); exit(0) } catch { print(error.localizedDescription); exit(1) } }
            dispatchMain()
        }
        if a.count == 5, a[1] == "--import" {
            Task {
                let config = a[4].isEmpty ? nil : a[4], c = Client(url: a[2], token: a[3])
                for s in listSessions(config: config) where await uploadSession(s, client: c) == false { exit(1) }
                exit(0)
            }
            dispatchMain()
        }
        NSApplication.shared.setActivationPolicy(.regular)
        ClauduoApp.main()
    }
}
