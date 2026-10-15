import Foundation

// MARK: - Actions audit trail
//
// Shared "cadre Actions" infrastructure: every Action (a thing Coucou does on the person's
// behalf without them watching each step — reading a Telegram chat, sending a mail, later
// a per-project agent setup, …) must record one entry per attempt here, whether it
// succeeded, failed, or was denied. This is the one place to look to know what Coucou did
// while the person was away. Never logs secret values themselves (a code, a password) —
// only what happened and where.

/// One line of the Actions audit trail.
struct ActionAuditEntry: Sendable {
    let date: Date
    /// Stable id of the Action, e.g. "telegram.recuperer_code".
    let actionId: String
    /// "onDemand" or "permanent" — see `ActionTriggerMode`.
    let trigger: String
    /// What the Action touched, in human terms, e.g. "Telegram > Telegram (service)".
    let scope: String
    let outcome: Outcome
    /// Short, human-readable detail. Never the secret value itself.
    let detail: String

    enum Outcome: String, Sendable { case success, failure, denied }
}

enum ActionAudit {
    private static let fileName = "ActionsAudit.log"

    /// Appends one structured, timestamped line via the shared app log writer (rotates at
    /// 1 MB, file mode 0600, never blocks the calling thread).
    static func record(actionId: String, trigger: ActionTriggerMode, scope: String,
                       outcome: ActionAuditEntry.Outcome, detail: String) {
        let line = "action=\(actionId) trigger=\(trigger.rawValue) scope=\"\(scope)\" " +
                   "outcome=\(outcome.rawValue) detail=\"\(detail)\""
        appendAppLog(fileName, line)
    }

    /// Reads the last `limit` lines of the audit trail, most recent first. Best-effort — for
    /// display in Settings only; returns [] if nothing has been logged yet.
    static func tail(limit: Int = 20) -> [String] {
        let url = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Logs/NotchBuddy/\(fileName)")
        guard let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8) else { return [] }
        let lines = text.split(separator: "\n").map(String.init)
        return Array(lines.suffix(limit).reversed())
    }
}
