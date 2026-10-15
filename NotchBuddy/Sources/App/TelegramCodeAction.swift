#if !APPSTORE
import Foundation
import AppKit
import ApplicationServices
import Combine

// MARK: - Telegram verification-code retrieval (first Action built on the Actions cadre)
//
// Reads ONE Telegram Desktop conversation the person has explicitly allowed (by default,
// Telegram's own "Telegram" service chat, where login codes arrive), extracts a
// verification code from its newest message, mails it via SMTPMailer, and keeps a
// short-lived local copy. Every attempt is written to ActionAudit — success, failure, or
// denied — never the code itself.
//
// GitHub build only: Accessibility automation is not allowed in the App Store sandbox,
// same restriction as MailController and WindowContextCapture.
//
// IMPORTANT — verify live before relying on this: Telegram Desktop's accessibility tree
// (it's a Qt app) is not guaranteed to expose stable roles/titles the way AppKit apps do.
// `locateServiceChatRow` and `extractLatestMessageText` below are a reasonable first guess
// built from how Qt typically surfaces its accessibility tree on macOS, but they need to be
// checked with Accessibility Inspector (Xcode > Open Developer Tool) against the actual
// running app before depending on this for a real login. If the structure differs, only
// those two functions should need to change — everything else (polling, dedupe, audit,
// mail, local retention) stays the same.

@MainActor
final class TelegramCodeAction: ObservableObject {
    static let shared = TelegramCodeAction()
    static let actionId = "telegram.recuperer_code"

    /// Human label for the one chat this Action is allowed to read by default. The person
    /// can widen `ActionConfig.allowedTargets` later; this Action only ever acts on
    /// `allowedTargets`, never on "all of Telegram".
    static let defaultTarget = "Telegram > Telegram (service)"

    /// App name as Telegram Desktop reports itself via NSRunningApplication.localizedName.
    /// Covers both the legacy Mac-native client and the current cross-platform (Qt) one.
    private static let candidateBundleIDs = ["org.telegram.desktop", "ru.keepcoder.Telegram"]
    private static let appDisplayName = "Telegram"

    /// First 4–8 consecutive digits in a message — Telegram's login codes ("Login code:
    /// 12345", "Code de connexion : 12345", …) are always a short digit run.
    private static let codePattern = try! NSRegularExpression(pattern: #"\b(\d{4,8})\b"#)

    @Published private(set) var isWatching = false
    @Published private(set) var lastRunAt: Date?
    @Published private(set) var lastOutcome: ActionAuditEntry.Outcome?

    private var timer: Timer?
    private var onDemandDeadline: Date?
    /// Signature of the last message already processed, so the same code is never mailed
    /// twice. Cleared when watching stops.
    private var lastSeenSignature: String?

    private init() {}

    // MARK: - Public controls (Settings calls these)

    /// Starts a time-boxed watch: polls until `windowSeconds` elapse, then stops on its own.
    func startOnDemand(windowSeconds: TimeInterval = 15 * 60) {
        var config = ActionPermissions.load(Self.actionId)
        guard config.enabled, !config.allowedTargets.isEmpty else {
            ActionAudit.record(actionId: Self.actionId, trigger: .onDemand, scope: "-",
                               outcome: .denied, detail: "Action not enabled or no allowed target configured.")
            return
        }
        config.triggerMode = .onDemand
        ActionPermissions.save(config, for: Self.actionId)
        onDemandDeadline = Date().addingTimeInterval(windowSeconds)
        beginPolling()
    }

    /// Starts continuous watching. Only ever touches `ActionConfig.allowedTargets` — this is
    /// the "mode permanent" the person explicitly asked for, scoped to what they allowed.
    func startPermanent() {
        var config = ActionPermissions.load(Self.actionId)
        guard config.enabled, !config.allowedTargets.isEmpty else {
            ActionAudit.record(actionId: Self.actionId, trigger: .permanent, scope: "-",
                               outcome: .denied, detail: "Action not enabled or no allowed target configured.")
            return
        }
        config.triggerMode = .permanent
        ActionPermissions.save(config, for: Self.actionId)
        onDemandDeadline = nil
        beginPolling()
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        onDemandDeadline = nil
        isWatching = false
        lastSeenSignature = nil
    }

    // MARK: - Polling

    private func beginPolling() {
        timer?.invalidate()
        isWatching = true
        // Every 8 s: a verification code is only useful if caught promptly.
        timer = Timer.scheduledTimer(withTimeInterval: 8, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.pollOnce() }
        }
        timer?.tolerance = 2
    }

    private func pollOnce() {
        if let deadline = onDemandDeadline, Date() >= deadline {
            stop()
            return
        }

        let config = ActionPermissions.load(Self.actionId)
        guard config.enabled, config.allowedTargets.contains(Self.defaultTarget) else {
            stop()
            return
        }

        lastRunAt = Date()
        let trigger: ActionTriggerMode = config.triggerMode

        guard let app = Self.launchOrFindTelegram() else {
            lastOutcome = .failure
            ActionAudit.record(actionId: Self.actionId, trigger: trigger, scope: Self.defaultTarget,
                               outcome: .failure, detail: "Telegram could not be launched or found.")
            return
        }

        let axApp = AXUIElementCreateApplication(app.processIdentifier)
        guard let chatRow = Self.locateServiceChatRow(in: axApp) else {
            // Not necessarily an error on every poll: the app may still be starting up.
            return
        }

        AXUIElementPerformAction(chatRow, kAXPressAction as CFString)

        guard let messageText = Self.extractLatestMessageText(in: axApp) else { return }
        let signature = String(messageText.prefix(120))
        guard signature != lastSeenSignature else { return } // already handled
        lastSeenSignature = signature

        guard let code = Self.extractCode(from: messageText) else { return }

        Task { await self.deliver(code: code, config: config, trigger: trigger) }
    }

    // MARK: - Delivery (mail + local copy), once a code has been found

    private func deliver(code: String, config: ActionConfig, trigger: ActionTriggerMode) async {
        guard let address = KeychainStore.shared.get("smtp-gmail-address"), !address.isEmpty,
              let appPassword = KeychainStore.shared.get("smtp-gmail-app-password"), !appPassword.isEmpty else {
            lastOutcome = .failure
            ActionAudit.record(actionId: Self.actionId, trigger: trigger, scope: Self.defaultTarget,
                               outcome: .failure, detail: "SMTP credentials are not configured.")
            return
        }

        RetrievedCodeStore.shared.store(code: code, source: Self.defaultTarget, config: config)

        do {
            try await SMTPMailer.shared.send(
                subject: "Code Telegram récupéré par Coucou",
                body: "Coucou a repéré un code dans \(Self.defaultTarget) :\n\n\(code)\n\n" +
                      "Ce code n'est valable que quelques minutes — utilise-le au plus vite.",
                to: address,
                from: SMTPCredentials(address: address, appPassword: appPassword)
            )
            lastOutcome = .success
            ActionAudit.record(actionId: Self.actionId, trigger: trigger, scope: Self.defaultTarget,
                               outcome: .success, detail: "Code extrait et envoyé par mail.")
        } catch {
            lastOutcome = .failure
            ActionAudit.record(actionId: Self.actionId, trigger: trigger, scope: Self.defaultTarget,
                               outcome: .failure, detail: "Échec d'envoi mail: \(error)")
        }
    }

    // MARK: - Telegram app lookup / launch

    private static func launchOrFindTelegram() -> NSRunningApplication? {
        if let running = NSWorkspace.shared.runningApplications.first(where: {
            $0.localizedName == appDisplayName
        }) {
            return running
        }

        // Not running: the person explicitly asked for Coucou to open it even if closed.
        var appURL: URL?
        for bundleID in candidateBundleIDs {
            if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) {
                appURL = url
                break
            }
        }
        guard let url = appURL else { return nil }

        let config = NSWorkspace.OpenConfiguration()
        config.activates = false // read in the background; don't steal focus from the person
        NSWorkspace.shared.openApplication(at: url, configuration: config, completionHandler: nil)
        // The caller polls every 8 s, so the next tick picks the app up once it has launched.
        return nil
    }

    // MARK: - Accessibility tree search (see the file-level note — verify live)

    /// Depth-first search for the chat-list row whose visible text matches `appDisplayName`
    /// exactly (the chat named "Telegram", not the app's own window chrome). Bounded depth
    /// and node count so a large chat list can't hang the poll.
    private static func locateServiceChatRow(in root: AXUIElement) -> AXUIElement? {
        search(root, depth: 0, budget: Budget()) { element in
            guard let role = Self.attribute(element, kAXRoleAttribute as CFString) as? String,
                  role == kAXRowRole as String || role == kAXCellRole as String else { return false }
            let text = [Self.attribute(element, kAXTitleAttribute as CFString),
                        Self.attribute(element, kAXDescriptionAttribute as CFString),
                        Self.attribute(element, kAXValueAttribute as CFString)]
                .compactMap { $0 as? String }
            return text.contains(appDisplayName)
        }
    }

    /// After selecting the chat, finds the newest message bubble's text: the AXStaticText
    /// leaf with the greatest vertical position inside the conversation's scroll area
    /// (messages flow top-to-bottom, so the most recent one sits lowest).
    private static func extractLatestMessageText(in root: AXUIElement) -> String? {
        var best: (text: String, y: CGFloat)?
        _ = search(root, depth: 0, budget: Budget()) { element in
            guard let role = Self.attribute(element, kAXRoleAttribute as CFString) as? String,
                  role == kAXStaticTextRole as String,
                  let value = Self.attribute(element, kAXValueAttribute as CFString) as? String,
                  !value.isEmpty else { return false }
            let y = Self.frame(element)?.origin.y ?? -.greatestFiniteMagnitude
            if best == nil || y > best!.y { best = (value, y) }
            return false // keep searching — we want the best match, not the first
        }
        return best?.text
    }

    private static func extractCode(from text: String) -> String? {
        let range = NSRange(text.startIndex..., in: text)
        guard let match = codePattern.firstMatch(in: text, range: range),
              let group = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[group])
    }

    // MARK: - AX helpers

    private struct Budget { var nodesVisited = 0; static let max = 4000 }

    /// Depth-first traversal; `match` returning true stops the search and returns that
    /// element — unless the caller always returns false to visit everything (see above).
    private static func search(_ element: AXUIElement, depth: Int, budget: Budget,
                               match: (AXUIElement) -> Bool) -> AXUIElement? {
        var budget = budget
        budget.nodesVisited += 1
        guard depth < 40, budget.nodesVisited < Budget.max else { return nil }

        if match(element) { return element }

        var childrenRef: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &childrenRef) == .success,
              let children = childrenRef as? [AXUIElement] else { return nil }

        for child in children {
            if let found = search(child, depth: depth + 1, budget: budget, match: match) {
                return found
            }
        }
        return nil
    }

    private static func attribute(_ element: AXUIElement, _ name: CFString) -> Any? {
        var ref: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, name, &ref) == .success else { return nil }
        return ref
    }

    private static func frame(_ element: AXUIElement) -> CGRect? {
        guard let posRef = attribute(element, kAXPositionAttribute as CFString),
              let sizeRef = attribute(element, kAXSizeAttribute as CFString) else { return nil }
        var position = CGPoint.zero
        var size = CGSize.zero
        // swiftlint:disable force_cast
        guard AXValueGetValue(posRef as! AXValue, .cgPoint, &position),
              AXValueGetValue(sizeRef as! AXValue, .cgSize, &size) else { return nil }
        return CGRect(origin: position, size: size)
    }
}

// MARK: - Local short-lived copy of the retrieved code (so it can be copied on the Mac)

@MainActor
final class RetrievedCodeStore: ObservableObject {
    static let shared = RetrievedCodeStore()

    struct Entry: Codable, Equatable {
        let code: String
        let source: String
        let retrievedAt: Date
        /// nil when retention is `.history` (kept until cleared by hand).
        let expiresAt: Date?
    }

    @Published private(set) var current: Entry?
    private var expiryTimer: Timer?
    private static let key = "retrievedCode.telegram"

    private init() {
        current = Self.load()
        scheduleExpiryIfNeeded()
    }

    func store(code: String, source: String, config: ActionConfig) {
        let expiresAt: Date? = config.retention == .quickExpiry
            ? Date().addingTimeInterval(config.retentionSeconds) : nil
        let entry = Entry(code: code, source: source, retrievedAt: Date(), expiresAt: expiresAt)
        current = entry
        Self.save(entry)
        scheduleExpiryIfNeeded()
    }

    func clear() {
        current = nil
        UserDefaults.standard.removeObject(forKey: Self.key)
        expiryTimer?.invalidate()
    }

    private func scheduleExpiryIfNeeded() {
        expiryTimer?.invalidate()
        guard let expiresAt = current?.expiresAt else { return }
        let interval = max(0, expiresAt.timeIntervalSinceNow)
        expiryTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { [weak self] _ in
            Task { @MainActor [weak self] in self?.clear() }
        }
    }

    private static func load() -> Entry? {
        guard let data = UserDefaults.standard.data(forKey: key),
              let entry = try? JSONDecoder().decode(Entry.self, from: data) else { return nil }
        if let expiresAt = entry.expiresAt, expiresAt <= Date() { return nil }
        return entry
    }

    private static func save(_ entry: Entry) {
        guard let data = try? JSONEncoder().encode(entry) else { return }
        UserDefaults.standard.set(data, forKey: key)
    }
}
#endif
