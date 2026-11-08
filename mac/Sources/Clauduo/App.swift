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
        view.load(URLRequest(url: URL(string: siteURL + "/app")!))
    }
    func userContentController(_ c: WKUserContentController, didReceive m: WKScriptMessage) {
        // 브리지는 Clauduo 페이지에서만 받는다
        guard m.frameInfo.isMainFrame, m.frameInfo.request.url?.host == URL(string: siteURL)!.host, let action = m.body as? String else { return }
        Task { @MainActor in
            if action == "connect" { await self.model?.pair() } else if action == "addFolder" { self.model?.addFolder() }
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

@MainActor final class Model: ObservableObject {
    @Published var status = "연결 안 됨"
    @Published var connected = Keychain.load() != nil
    private var loop: Task<Void, Never>?

    var client: Client? { Keychain.load().map { Client(url: siteURL, token: $0) } }
    init() { start() }

    func start() {
        loop?.cancel()
        guard let c = client else { return }
        loop = Task.detached { await workerLoop(c, folders: { Folders.list }) { s in Task { @MainActor in self.status = s } } }
    }

    func pair() async {
        let name = (Host.current().localizedName ?? "mac").components(separatedBy: CharacterSet.alphanumerics.inverted).filter { !$0.isEmpty }.joined(separator: "-")
        let js = """
        const ws = localStorage['clauduo.ws'];
        if (!ws) return JSON.stringify({ status: 0 });
        const r = await fetch(`/api/w/${ws}/agents`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name, mode: 'worker' }) });
        return JSON.stringify({ status: r.status, body: await r.json() });
        """
        do {
            guard Web.shared.view.url?.host == URL(string: siteURL)!.host else { return }
            let raw = try await Web.shared.view.callAsyncJavaScript(js, arguments: ["name": name], contentWorld: .page) as? String ?? ""
            let o = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any] ?? [:]
            let body = o["body"] as? [String: Any]
            guard o["status"] as? Int == 200, let cmd = body?["command"] as? String, let token = cmd.components(separatedBy: " ").last else {
                notify((body?["error"] as? String) ?? "먼저 로그인하고 워크스페이스를 만들어 주세요."); return
            }
            Keychain.save(token); connected = true; start()
        } catch { notify("연결하지 못했어요: \(error.localizedDescription)") }
    }

    private func notify(_ m: String) { let a = NSAlert(); a.messageText = m; a.runModal() }

    func addFolder() {
        let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = false; p.prompt = "허용"
        p.message = "Claude가 이 폴더의 파일을 읽고 고칠 수 있게 허용합니다."
        if p.runModal() == .OK, let path = p.url?.path, !Folders.list.contains(path) { Folders.list.append(path) }
    }
}

struct ClauduoApp: App {
    @StateObject private var model = Model()
    var body: some Scene {
        WindowGroup("Clauduo") {
            WebTab().frame(minWidth: 1000, minHeight: 680).onAppear { Web.shared.model = model }
        }
    }
}

@main struct Entry {
    static func main() {
        let a = CommandLine.arguments
        // 테스트와 자동화용 실행 모드
        if a.count == 4, a[1] == "--worker" {
            Task { let f = ProcessInfo.processInfo.environment["CLAUDUO_FOLDERS"]?.components(separatedBy: ":") ?? []; await workerLoop(Client(url: a[2], token: a[3]), folders: { f }) { print($0) }; exit(0) }
            dispatchMain()
        }
        NSApplication.shared.setActivationPolicy(.regular)
        ClauduoApp.main()
    }
}
