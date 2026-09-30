import SwiftUI
import Darwin

@main
struct HuskarlExample: App {
    init() {
#if os(macOS)
        // Verification runs before opening a window, once per fresh process.
        let args = ProcessInfo.processInfo.arguments
        if let index = args.firstIndex(of: "--check"), args.count > index + 2,
           let action = Int32(args[index + 1]), let expected = Int32(args[index + 2]) {
            let result = huskarl_example_token_operation(action)
            print("HUSKARL_CHECK action=\(action) result=\(result)")
            fflush(stdout)
            exit(result == expected ? 0 : 1)
        }
#endif
    }

    var body: some Scene {
        WindowGroup {
            TokenView()
#if os(macOS)
                .frame(minWidth: 460, minHeight: 340)
#endif
        }
    }
}

struct TokenView: View {
    @State private var status = "Load to check for a saved token."
    @State private var busy = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 24) {
                Text("Refresh-token storage").font(.title2)
                Text("Store a disposable token, close the app, then reopen it and tap Load to check persistence.")
                Text(status).accessibilityIdentifier("token-status")
                HStack {
                    Button("Store") { perform(1) }
                    Button("Load") { perform(0) }
                    Button("Clear") { perform(2) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy)
                if busy { ProgressView() }
                Text("Uses Keychain storage. No OAuth server or Secure Enclave is involved.")
                    .font(.footnote).foregroundStyle(.secondary)
                Spacer()
            }
            .padding()
            .navigationTitle("Huskarl")
#if os(iOS)
            .task {
                // Let UIKit finish launching before the verification process exits.
                let args = ProcessInfo.processInfo.arguments
                if let index = args.firstIndex(of: "--check"), args.count > index + 2,
                   let action = Int32(args[index + 1]), let expected = Int32(args[index + 2]) {
                    let result = await Task.detached {
                        huskarl_example_token_operation(action)
                    }.value
                    print("HUSKARL_CHECK action=\(action) result=\(result)")
                    fflush(stdout)
                    exit(result == expected ? 0 : 1)
                }
            }
#endif
        }
    }

    private func perform(_ action: Int32) {
        busy = true
        Task {
            let result = await Task.detached {
                huskarl_example_token_operation(action)
            }.value
            switch result {
            case 0: status = "No token stored."
            case 1: status = "Saved example token loaded and verified."
            case 2: status = "Example token stored. You can now restart the app."
            default: status = "Operation failed (\(result)). See the app console for details."
            }
            busy = false
        }
    }
}
