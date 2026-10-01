import AppKit

@MainActor
final class App: NSObject, NSApplicationDelegate, NSWindowDelegate {
    var window: NSWindow!
    var status: NSTextField!
    var ephemeral: NSButton!
    var controls: [NSButton] = []
    var timer: Timer?
    var active = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 700, height: 300),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.title = "Huskarl native session"
        window.delegate = self
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 18
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.addArrangedSubview(NSTextField(labelWithString: "Secure browser sign-in and persistent API access"))
        stack.addArrangedSubview(NSTextField(wrappingLabelWithString:
            "Sign in, make a request, then quit and relaunch to restore the session. Log out removes the saved refresh token."))
        ephemeral = NSButton(checkboxWithTitle: "Request a private browser session", target: nil, action: nil)
        stack.addArrangedSubview(ephemeral)
        let buttons = NSStackView()
        for (tag, title) in [(0, "Retry restore"), (1, "Sign in"), (2, "Make request"), (3, "Log out")] {
            let button = NSButton(title: title, target: self, action: #selector(startAction(_:)))
            button.tag = tag
            buttons.addArrangedSubview(button)
            controls.append(button)
        }
        buttons.addArrangedSubview(NSButton(title: "Cancel sign-in", target: self, action: #selector(cancel)))
        stack.addArrangedSubview(buttons)
        status = NSTextField(wrappingLabelWithString: "Restoring session…")
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
        start(0)
    }

    func setActive(_ value: Bool) {
        active = value
        controls.forEach { $0.isEnabled = !value }
        ephemeral.isEnabled = !value
    }
    func start(_ action: Int32) {
        guard !active else { return }
        setActive(true)
        huskarl_native_start(Unmanaged.passUnretained(window).toOpaque(), action, ephemeral.state == .on ? 1 : 0)
        status.stringValue = String(cString: huskarl_native_status())
    }
    @objc func startAction(_ sender: NSButton) { start(Int32(sender.tag)) }
    @objc func cancel() { huskarl_native_cancel() }
    func poll() {
        guard active else { return }
        let result = huskarl_native_poll()
        if result != 1 {
            status.stringValue = String(cString: huskarl_native_status())
            setActive(false)
        }
    }
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if active { NSSound.beep(); return false }
        return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if active { NSSound.beep(); return .terminateCancel }
        return .terminateNow
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
        huskarl_native_shutdown()
    }
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
