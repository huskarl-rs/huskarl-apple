import AppKit

@MainActor
final class App: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var status: NSTextField!
    var ephemeral: NSButton!
    var timer: Timer?
    var active = false
    var cancellationCheck = false
    var checkStep = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 270),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.title = "Huskarl browser login smoke test"
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(NSTextField(labelWithString: "Disposable local Keycloak account"))
        stack.addArrangedSubview(NSTextField(labelWithString: "Username: huskarl    Password: huskarl-test-only"))
        ephemeral = NSButton(checkboxWithTitle: "Request ephemeral browser session", target: nil, action: nil)
        stack.addArrangedSubview(ephemeral)
        let buttons = NSStackView()
        for (title, action) in [("Sign in", #selector(start)), ("Cancel session", #selector(cancel)),
                                ("Drop session", #selector(dropSession)), ("Quit", #selector(quit))] {
            buttons.addArrangedSubview(NSButton(title: title, target: self, action: action))
        }
        stack.addArrangedSubview(buttons)
        status = NSTextField(wrappingLabelWithString: "Ready. Click Sign in, allow the browser prompt, then log in.")
        stack.addArrangedSubview(status)
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 24)
        ])
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        timer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.poll() }
        }
        print("BROWSER_SMOKE app_ready")
        cancellationCheck = ProcessInfo.processInfo.environment["HUSKARL_BROWSER_CANCEL_CHECK"] == "1"
        if cancellationCheck {
            ephemeral.state = .on
            startCancellationCheck()
        }
    }
    func startCancellationCheck() {
        start()
        Timer.scheduledTimer(withTimeInterval: 2, repeats: false) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                if self.checkStep == 1 {
                    self.dropSession()
                    self.checkStep = 2
                    self.startCancellationCheck()
                } else {
                    self.cancel()
                }
            }
        }
    }
    @objc func start() {
        guard !active else { return }
        active = true
        status.stringValue = "Waiting for browser authentication…"
        huskarl_browser_start(Unmanaged.passUnretained(window).toOpaque(), ephemeral.state == .on ? 1 : 0)
    }
    func poll() {
        guard active else { return }
        let result = huskarl_browser_poll()
        if result == 2 { status.stringValue = "Success: callback received, state validated, PKCE code exchanged."; active = false }
        if result == 3 {
            status.stringValue = "Session cancelled or failed. See the smoke-test log for details."
            active = false
            if cancellationCheck {
                if checkStep == 0 { checkStep = 1; startCancellationCheck() }
                else { print("BROWSER_SMOKE cancellation_sequence_finished"); quit() }
            }
        }
    }
    @objc func cancel() { huskarl_browser_cancel() }
    @objc func dropSession() {
        huskarl_browser_drop(); active = false
        status.stringValue = "Session dropped. Its browser should be dismissed."
    }
    @objc func quit() { NSApp.terminate(nil) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { huskarl_browser_drop() }
}
@main
struct Launcher {
    @MainActor static func main() {
        let app = NSApplication.shared
        let delegate = App()
        app.setActivationPolicy(.regular)
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
}
