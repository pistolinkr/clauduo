import AppKit
import Security
import SwiftUI
import WebKit

enum Keychain {
    private static let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "com.clauduo.mac", kSecAttrAccount as String: "agent-token"]
    static func load() -> String? {
        var q = query; q[kSecReturnData as String] = true
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    static func save(_ v: String) {
        SecItemDelete(query as CFDictionary)
        var q = query; q[kSecValueData as String] = Data(v.utf8)
        SecItemAdd(q as CFDictionary, nil)
    }
    static func clear() { SecItemDelete(query as CFDictionary) }
}

/// 사이트는 alert/confirm/prompt를 쓰므로 WKWebView에서 직접 처리해야 한다.
final class Web: NSObject, WKUIDelegate, WKNavigationDelegate {
    static let shared = Web()
    let view = WKWebView()
    override init() {
        super.init()
        view.uiDelegate = self; view.navigationDelegate = self
        view.load(URLRequest(url: URL(string: siteURL + "/app")!))
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

struct RunEntry: Identifiable { let id = UUID(); let folder: String; let prompt: String; let result: LocalResult; let shared: Bool }

@MainActor final class Model: ObservableObject {
    @Published var status = "연결 안 됨"
    @Published var connected = Keychain.load() != nil
    @Published var folder: URL?
    @Published var running = false
    @Published var runs: [RunEntry] = []
    @Published var error = ""
    private var loop: Task<Void, Never>?

    var client: Client? { Keychain.load().map { Client(url: siteURL, token: $0) } }
    init() { start() }

    func start() {
        loop?.cancel()
        guard let c = client else { return }
        loop = Task.detached { await workerLoop(c) { s in Task { @MainActor in self.status = s } } }
    }

    func pair(name: String) async {
        error = ""
        let js = """
        const ws = localStorage['clauduo.ws'];
        if (!ws) return JSON.stringify({ status: 0 });
        const r = await fetch(`/api/w/${ws}/agents`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name, mode: 'worker' }) });
        return JSON.stringify({ status: r.status, body: await r.json() });
        """
        do {
            guard Web.shared.view.url?.host == URL(string: siteURL)!.host else { error = "먼저 워크스페이스 탭에서 로그인해 주세요."; return }
            let raw = try await Web.shared.view.callAsyncJavaScript(js, arguments: ["name": name], contentWorld: .page) as? String ?? ""
            let o = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] ?? [:]
            let body = o["body"] as? [String: Any]
            guard o["status"] as? Int == 200, let cmd = body?["command"] as? String, let token = cmd.components(separatedBy: " ").last else {
                error = (body?["error"] as? String) ?? "워크스페이스 탭에서 로그인하고 워크스페이스를 만들어 주세요."; return
            }
            Keychain.save(token); connected = true; start()
        } catch { self.error = "연결하지 못했어요: \(error.localizedDescription)" }
    }

    func disconnect() { loop?.cancel(); Keychain.clear(); connected = false; status = "연결 안 됨" }

    func pickFolder() {
        let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = false
        if p.runModal() == .OK { folder = p.url }
    }

    func run(prompt: String, share: Bool) async {
        guard let folder, !running else { return }
        running = true; defer { running = false }
        let r = await localRun(folder: folder, prompt: prompt)
        var shared = false
        if share, let c = client { shared = await uploadRun(c, folder: folder, prompt: prompt, result: r) }
        runs.insert(RunEntry(folder: folder.lastPathComponent, prompt: prompt, result: r, shared: shared), at: 0)
    }
}

struct LocalTab: View {
    @ObservedObject var model: Model
    @State private var name = Host.current().localizedName?.components(separatedBy: CharacterSet.alphanumerics.inverted).filter { !$0.isEmpty }.joined(separator: "-") ?? "mac"
    @State private var prompt = ""
    @AppStorage("shareRuns") private var share = true

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GroupBox("이 Mac 연결") {
                HStack {
                    if model.connected {
                        Label(model.status, systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                        Spacer()
                        Button("연결 해제") { model.disconnect() }
                    } else {
                        TextField("이 Mac의 Claude 이름", text: $name)
                        Button("연결") { Task { await model.pair(name: name) } }
                    }
                }.padding(4)
                if !model.error.isEmpty { Text(model.error).foregroundStyle(.red).font(.caption).frame(maxWidth: .infinity, alignment: .leading) }
            }
            GroupBox("로컬 작업") {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Button("폴더 선택") { model.pickFolder() }
                        Text(model.folder?.path ?? "Claude가 작업할 폴더를 골라 주세요").foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                    TextEditor(text: $prompt).font(.body).frame(minHeight: 90).overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
                    HStack {
                        Toggle("프롬프트·결과·파일 변경을 워크스페이스에 공유", isOn: $share).disabled(!model.connected)
                        Spacer()
                        if model.running { ProgressView().controlSize(.small) }
                        Button("실행") { let p = prompt; prompt = ""; Task { await model.run(prompt: p, share: share) } }
                            .keyboardShortcut(.return, modifiers: .command).buttonStyle(.borderedProminent)
                            .disabled(model.folder == nil || model.running || prompt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }.padding(4)
            }
            List(model.runs) { r in
                VStack(alignment: .leading, spacing: 4) {
                    HStack { Text(r.folder).font(.caption).foregroundStyle(.secondary); if r.shared { Text("공유됨").font(.caption).foregroundStyle(.green) }; if !r.result.ok { Text("오류").font(.caption).foregroundStyle(.red) } }
                    Text(r.prompt).bold().lineLimit(2)
                    Text(r.result.text).textSelection(.enabled)
                    ForEach(r.result.files, id: \.self) { f in Text("\(f["status"] ?? "") \(f["path"] ?? "")").font(.system(.caption, design: .monospaced)) }
                }.padding(.vertical, 4)
            }
        }.padding()
    }
}

struct ClauduoApp: App {
    @StateObject private var model = Model()
    var body: some Scene {
        WindowGroup("Clauduo") {
            TabView {
                WebTab().tabItem { Text("워크스페이스") }
                LocalTab(model: model).tabItem { Text("로컬") }
            }.frame(minWidth: 1000, minHeight: 680)
        }
    }
}

@main struct Entry {
    static func main() {
        let a = CommandLine.arguments
        // 테스트와 자동화용 실행 모드
        if a.count == 4, a[1] == "--worker" {
            Task { await workerLoop(Client(url: a[2], token: a[3])) { print($0) }; exit(0) }
            dispatchMain()
        }
        if a.count == 6, a[1] == "--local-run" {
            Task {
                let folder = URL(fileURLWithPath: a[4]), r = await localRun(folder: folder, prompt: a[5])
                exit(await uploadRun(Client(url: a[2], token: a[3]), folder: folder, prompt: a[5], result: r) ? 0 : 1)
            }
            dispatchMain()
        }
        NSApplication.shared.setActivationPolicy(.regular)
        ClauduoApp.main()
    }
}
