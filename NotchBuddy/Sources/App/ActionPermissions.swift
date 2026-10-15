import Foundation

// MARK: - Actions permission model
//
// Shared "cadre Actions" infrastructure: the per-Action configuration that decides what an
// Action may touch and how it runs. None of this is secret (secrets live in the Keychain,
// see KeychainStore in ClaudeService.swift) — it's stored in UserDefaults like the app's
// other settings, and it is the one place to see and change what every Action is allowed
// to do.

/// How an Action is started.
enum ActionTriggerMode: String, Codable, Sendable {
    /// A time-boxed window, started explicitly each time ("surveille Telegram pour le
    /// prochain code"). Nothing is read outside that window.
    case onDemand
    /// Runs continuously while Coucou is running, with no need to ask each time. Only ever
    /// applies to the narrow scope the person explicitly allowed for this Action.
    case permanent
}

/// How long something an Action retrieved (e.g. a verification code) stays available
/// locally before Coucou deletes its own copy.
enum ActionRetention: String, Codable, Sendable {
    /// Deleted automatically after `ActionConfig.retentionSeconds` — matches how briefly a
    /// verification code is actually valid, and limits exposure if the Mac is compromised.
    case quickExpiry
    /// Kept until the person clears it by hand.
    case history
}

/// Per-Action configuration.
struct ActionConfig: Codable, Sendable, Equatable {
    var enabled: Bool = false
    /// What the Action may touch, in human terms (e.g. the one Telegram chat it may read).
    /// Empty means nothing is allowed yet — an Action must never assume a default scope.
    var allowedTargets: [String] = []
    var triggerMode: ActionTriggerMode = .onDemand
    var retention: ActionRetention = .quickExpiry
    var retentionSeconds: TimeInterval = 15 * 60
}

enum ActionPermissions {
    private static func key(_ actionId: String) -> String { "actionConfig.\(actionId)" }

    static func load(_ actionId: String) -> ActionConfig {
        guard let data = UserDefaults.standard.data(forKey: key(actionId)),
              let config = try? JSONDecoder().decode(ActionConfig.self, from: data) else {
            return ActionConfig()
        }
        return config
    }

    static func save(_ config: ActionConfig, for actionId: String) {
        guard let data = try? JSONEncoder().encode(config) else { return }
        UserDefaults.standard.set(data, forKey: key(actionId))
    }
}
