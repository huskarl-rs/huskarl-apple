import AppKit
import SwiftUI

enum SessionAction: Int32 {
    case restore = 0, signIn, request, logOut

    var title: String {
        switch self {
        case .restore: "Restore session"
        case .signIn: "Sign in"
        case .request: "Make request"
        case .logOut: "Log out"
        }
    }
    var progress: String {
        switch self {
        case .restore: "Restoring session…"
        case .signIn: "Waiting for browser sign-in…"
        case .request: "Making authenticated request…"
        case .logOut: "Removing saved session…"
        }
    }
    var symbol: String {
        switch self {
        case .restore: "arrow.clockwise"
        case .signIn: "person.badge.key"
        case .request: "arrow.up.right"
        case .logOut: "rectangle.portrait.and.arrow.right"
        }
    }
}

struct Activity: Identifiable {
    let id = UUID()
    let date = Date()
    let title: String
    let detail: String
    let succeeded: Bool
}

@MainActor
final class App: NSObject, NSApplicationDelegate, NSWindowDelegate, ObservableObject {
    var window: NSWindow!
    @Published var status = "Checking for saved credentials."
    @Published var ephemeral = false
    @Published var operation: SessionAction?
    @Published var shuttingDown = false
    @Published var phase: Int32 = 0
    @Published var persistence: Int32 = 0
    @Published var failed = false
    @Published var restored = false
    @Published var latestRequest: String?
    @Published var activity: [Activity] = []
    @Published var successes = 0

    var active: Bool { operation != nil || shuttingDown }
    var ready: Bool { phase == 2 }
    var primaryAction: SessionAction {
        switch phase {
        case 1: .signIn
        case 2: .request
        case 3: .logOut
        default: .restore
        }
    }
    var sessionTitle: String {
        switch phase {
        case 1: "Signed out"
        case 2: "Session ready"
        case 3: "Cleanup required"
        case 4: "Restore required"
        case 5: "Session changing"
        default: "Session not loaded"
        }
    }
    var storageTitle: String {
        switch persistence {
        case 1: "No saved credentials"
        case 2: "Saved in Keychain"
        case 3: "Changes not saved"
        default: "Not checked"
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 660, height: 650),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.title = "Huskarl"
        window.titlebarAppearsTransparent = true
        window.minSize = NSSize(width: 580, height: 540)
        window.delegate = self
        window.contentView = NSHostingView(rootView: SessionView(app: self))
        installMenu()
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        start(.restore)
    }

    private func installMenu() {
        let main = NSMenu()
        let application = NSMenu()
        application.addItem(withTitle: "About Huskarl", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        application.addItem(.separator())
        application.addItem(withTitle: "Hide Huskarl", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        application.addItem(withTitle: "Quit Huskarl", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        let item = NSMenuItem()
        item.submenu = application
        main.addItem(item)
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        let editItem = NSMenuItem()
        editItem.submenu = edit
        main.addItem(editItem)
        NSApp.mainMenu = main
    }

    func start(_ action: SessionAction) {
        guard !active else { return }
        operation = action
        failed = false
        status = action.progress
        huskarl_native_start(Unmanaged.passUnretained(window).toOpaque(), action.rawValue, ephemeral ? 1 : 0) { result in
            MainActor.assumeIsolated { (NSApp.delegate as? App)?.completed(result) }
        }
    }

    func cancel() {
        guard operation == .signIn else { return }
        huskarl_native_cancel()
    }

    func completed(_ result: Int32) {
        let action = operation
        status = String(cString: huskarl_native_status())
        let state = huskarl_native_state()
        phase = state.phase
        persistence = state.persistence
        failed = result != 2
        if action == .restore { restored = !failed && ready }
        if !ready { restored = false }
        if action == .request { latestRequest = status }
        if !failed {
            successes += 1
            if action == .signIn || action == .logOut {
                restored = false
                latestRequest = nil
            }
        }
        activity.insert(Activity(title: action?.title ?? "Close session", detail: status, succeeded: !failed), at: 0)
        activity = Array(activity.prefix(30))
        operation = nil
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if active { NSSound.beep(); return false }
        return true
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if shuttingDown { return .terminateLater }
        if active { NSSound.beep(); return .terminateCancel }
        shuttingDown = true
        // Defer shutdown so even an immediate error follows terminateLater.
        DispatchQueue.main.async {
            huskarl_native_shutdown { result in
                MainActor.assumeIsolated {
                    if let app = NSApp.delegate as? App, result != 2 {
                        app.shuttingDown = false
                        app.completed(result)
                    }
                    NSApp.reply(toApplicationShouldTerminate: result == 2)
                }
            }
        }
        return .terminateLater
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

// Keep native fallbacks for older SDKs, older macOS, and reduced transparency.
private struct SessionButtonStyle: ViewModifier {
    var prominent = false
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder func body(content: Content) -> some View {
#if compiler(>=6.2)
        if #available(macOS 26.0, *), !reduceTransparency {
            if prominent {
                content.buttonStyle(.glassProminent)
            } else {
                content.buttonStyle(.glass)
            }
        } else {
            fallback(content)
        }
#else
        fallback(content)
#endif
    }

    @ViewBuilder private func fallback(_ content: Content) -> some View {
        if prominent {
            content.buttonStyle(.borderedProminent)
        } else {
            content.buttonStyle(.bordered)
        }
    }
}

private struct SessionBadgeBackground: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    @ViewBuilder func body(content: Content) -> some View {
#if compiler(>=6.2)
        if #available(macOS 26.0, *), !reduceTransparency {
            content.glassEffect(.regular, in: Capsule())
        } else {
            content.background(.quaternary, in: Capsule())
        }
#else
        content.background(.quaternary, in: Capsule())
#endif
    }
}

struct SessionView: View {
    @ObservedObject var app: App
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showActivity = false

    private var accent: Color { .teal }

    @ViewBuilder private var actions: some View {
#if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            GlassEffectContainer(spacing: 8) { actionButtons }
        } else {
            actionButtons
        }
#else
        actionButtons
#endif
    }

    private var actionButtons: some View {
        HStack(spacing: 12) {
            Button { app.start(app.primaryAction) } label: {
                Label(app.primaryAction.title, systemImage: app.primaryAction.symbol)
                    .padding(.horizontal, 6)
            }
            .modifier(SessionButtonStyle(prominent: true))
            .keyboardShortcut(.defaultAction)
            .disabled(app.active)
            if app.operation == .signIn {
                Button("Cancel sign-in") { app.cancel() }
                    .keyboardShortcut(.cancelAction)
                    .modifier(SessionButtonStyle())
            } else if app.ready {
                Button("Log out") { app.start(.logOut) }
                    .modifier(SessionButtonStyle())
                    .disabled(app.active)
            }
            Spacer()
            if app.active {
                ProgressView().controlSize(.small)
                    .accessibilityLabel(app.shuttingDown ? "Closing session" : app.operation?.progress ?? "Working")
            }
        }
        .controlSize(.large)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                HStack(spacing: 16) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 32, weight: .medium))
                        .foregroundStyle(accent)
                        .frame(width: 64, height: 64)
                        .background(accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 18))
                        .symbolEffect(.bounce, options: .nonRepeating, value: reduceMotion ? 0 : app.successes)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Huskarl").font(.largeTitle.bold())
                        Text("Secure access, made native.").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Label(app.active ? "Working" : app.ready ? "Ready" : "OAuth demo",
                          systemImage: app.active ? "clock" : app.ready ? "checkmark.circle.fill" : "macwindow")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(app.ready ? accent : .secondary)
                        .padding(.horizontal, 12).padding(.vertical, 7)
                        .modifier(SessionBadgeBackground())
                }

                VStack(alignment: .leading, spacing: 20) {
                    HStack {
                        Text("Your session").font(.headline)
                        Spacer()
                        if app.restored {
                            Label("Restored session", systemImage: "arrow.clockwise")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    HStack(alignment: .top, spacing: 14) {
                        Image(systemName: app.failed ? "exclamationmark.circle.fill" : app.ready ? "checkmark.shield.fill" : "lock.shield")
                            .font(.title).foregroundStyle(app.failed ? Color.orange : accent)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 7) {
                            Text(app.sessionTitle).font(.title2.weight(.semibold))
                            Text(app.status)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                                .accessibilityIdentifier("session-status")
                        }
                    }
                    Divider()
                    HStack {
                        Label("Credentials", systemImage: "key.horizontal")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(app.storageTitle)
                            .foregroundStyle(app.persistence == 3 ? Color.orange : .primary)
                    }
                    if let request = app.latestRequest, app.operation != .request {
                        VStack(alignment: .leading, spacing: 5) {
                            Text("Latest request").font(.caption).foregroundStyle(.secondary)
                            Text(request).font(.callout).textSelection(.enabled)
                        }
                    }
                    actions
                }
                .padding(24)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 20))
                .overlay(RoundedRectangle(cornerRadius: 20).strokeBorder(.primary.opacity(0.07)))

                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 5) {
                        Toggle("Private browser session", isOn: $app.ephemeral)
                            .toggleStyle(.checkbox)
                            .disabled(app.active)
                        Text("Request a fresh browser session for your next sign-in.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Menu {
                        Button("Retry restore") { app.start(.restore) }
                        Button("Log out / clear saved credentials") { app.start(.logOut) }
                    } label: {
                        Label("Session options", systemImage: "ellipsis.circle")
                    }
                    .fixedSize().disabled(app.active)
                }

                DisclosureGroup(isExpanded: $showActivity) {
                    VStack(alignment: .leading, spacing: 16) {
                        if app.activity.isEmpty {
                            Text("Completed operations will appear here.").foregroundStyle(.secondary)
                        }
                        ForEach(app.activity) { event in
                            HStack(alignment: .top, spacing: 10) {
                                Image(systemName: event.succeeded ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                                    .foregroundStyle(event.succeeded ? accent : .orange)
                                    .accessibilityLabel(event.succeeded ? "Completed" : "Needs attention")
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack {
                                        Text(event.title).fontWeight(.medium)
                                        Spacer()
                                        Text(event.date, style: .time).foregroundStyle(.secondary)
                                    }
                                    Text(event.detail).foregroundStyle(.secondary).textSelection(.enabled)
                                }
                            }
                            .font(.callout)
                        }
                    }
                    .padding(.top, 14)
                } label: {
                    Label("Activity · \(app.activity.count)", systemImage: "clock.arrow.circlepath")
                        .font(.callout.weight(.medium))
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Browser sign-in  ·  Keychain storage  ·  Secure Enclave proofs")
                        .font(.caption.weight(.medium))
                    Text("Sign in, make a request, then relaunch to try restoring saved credentials.")
                        .font(.caption)
                }
                .foregroundStyle(.secondary)
            }
            .padding(32)
            .frame(maxWidth: 780)
            .frame(maxWidth: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(accent)
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.2), value: app.active)
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
