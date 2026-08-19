import SwiftUI
import VaultCore

struct RootView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Group {
            switch model.phase {
            case .loading: ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            case .noVault, .recoveryKit: OnboardingView()
            case .locked: LockView()
            case .unlocked: MainView()
            }
        }
        .animation(.easeInOut(duration: 0.2), value: model.phase)
    }
}
