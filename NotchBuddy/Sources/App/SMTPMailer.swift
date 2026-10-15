import Foundation
import Network

// MARK: - Minimal SMTP client (Gmail, implicit TLS)
//
// Coucou has no mail-sending dependency today (MailController only reads Apple Mail), so
// this is a small, self-contained SMTP client rather than a new third-party package.
// It targets Gmail's implicit-TLS port (465) specifically to avoid the STARTTLS upgrade
// dance, which Network.framework does not support cleanly on an already-open connection:
// the TLS handshake happens as soon as the socket connects, before any SMTP command is
// sent, exactly like IMAPS/POP3S.
//
// Auth is "AUTH LOGIN" with a Gmail *App Password* (not the account password) — the same
// credential kind the person already types into Google's own "App passwords" page.

enum SMTPError: Error, Sendable {
    case connectionFailed(String)
    case unexpectedReply(String)
    case authenticationFailed(String)
    case sendFailed(String)
}

/// One Gmail sender identity: the address codes are sent from, and its App Password.
/// Never logged, never included in `ActionAudit` details — only read from the Keychain.
struct SMTPCredentials: Sendable {
    let address: String
    let appPassword: String
}

actor SMTPMailer {
    static let shared = SMTPMailer()

    /// Sends a plain-text email through Gmail's SMTP relay. Throws on any failure; callers
    /// (Actions) are expected to record the outcome via `ActionAudit`, never the message body.
    func send(subject: String, body: String, to recipient: String,
              from credentials: SMTPCredentials) async throws {
        let connection = NWConnection(
            host: NWEndpoint.Host("smtp.gmail.com"),
            port: 465,
            using: .tls
        )

        let session = Session(connection: connection)
        defer { connection.cancel() }

        try await session.waitUntilReady()
        try await session.expect(startingWith: "220")

        try await session.send("EHLO localhost")
        try await session.expectMultiline(startingWith: "250")

        try await session.send("AUTH LOGIN")
        try await session.expect(startingWith: "334")

        let encodedUser = Data(credentials.address.utf8).base64EncodedString()
        try await session.send(encodedUser)
        try await session.expect(startingWith: "334")

        let encodedPass = Data(credentials.appPassword.utf8).base64EncodedString()
        try await session.send(encodedPass)
        do {
            try await session.expect(startingWith: "235")
        } catch {
            throw SMTPError.authenticationFailed(
                "Gmail refused the App Password. Check it was generated for this address and hasn't been revoked.")
        }

        try await session.send("MAIL FROM:<\(credentials.address)>")
        try await session.expect(startingWith: "250")

        try await session.send("RCPT TO:<\(recipient)>")
        try await session.expect(startingWith: "250")

        try await session.send("DATA")
        try await session.expect(startingWith: "354")

        let message = Self.buildMessage(
            from: credentials.address, to: recipient, subject: subject, body: body)
        try await session.sendRaw(message + "\r\n.\r\n")
        try await session.expect(startingWith: "250")

        try await session.send("QUIT")
        // Best-effort: don't fail the whole send if QUIT's reply is slow or missing.
        _ = try? await session.expect(startingWith: "221")
    }

    private static func buildMessage(from: String, to: String, subject: String, body: String) -> String {
        let date = Self.rfc2822Date()
        // Headers end with a blank line before the body; CRLF throughout, as SMTP requires.
        return [
            "From: \(from)",
            "To: \(to)",
            "Subject: \(subject)",
            "Date: \(date)",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=UTF-8",
            "",
            body,
        ].joined(separator: "\r\n")
    }

    private static func rfc2822Date() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter.string(from: Date())
    }

    // MARK: - Session (one connection's worth of request/response plumbing)

    private final class Session: @unchecked Sendable {
        private let connection: NWConnection
        private let queue = DispatchQueue(label: "fr.louisraille.NotchBuddy.smtp")
        /// Bytes received but not yet consumed as a full line.
        private var buffer = Data()

        init(connection: NWConnection) {
            self.connection = connection
            connection.start(queue: queue)
        }

        func waitUntilReady() async throws {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        continuation.resume()
                    case .failed(let error):
                        continuation.resume(throwing: SMTPError.connectionFailed(error.localizedDescription))
                    case .cancelled:
                        continuation.resume(throwing: SMTPError.connectionFailed("cancelled"))
                    default:
                        break
                    }
                }
            }
        }

        func send(_ line: String) async throws { try await sendRaw(line + "\r\n") }

        func sendRaw(_ raw: String) async throws {
            guard let data = raw.data(using: .utf8) else {
                throw SMTPError.sendFailed("Could not encode command as UTF-8.")
            }
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                connection.send(content: data, completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: SMTPError.sendFailed(error.localizedDescription))
                    } else {
                        continuation.resume()
                    }
                })
            }
        }

        /// Reads one single-line reply (e.g. "250 OK") and throws unless it starts with `code`.
        func expect(startingWith code: String) async throws {
            let line = try await readLine()
            guard line.hasPrefix(code) else { throw SMTPError.unexpectedReply(line) }
        }

        /// Reads a possibly multi-line reply (e.g. EHLO's capability list: "250-STARTTLS" …
        /// "250 AUTH LOGIN") and throws unless every line starts with `code`.
        func expectMultiline(startingWith code: String) async throws {
            while true {
                let line = try await readLine()
                guard line.hasPrefix(code) else { throw SMTPError.unexpectedReply(line) }
                // SMTP continuation: "CODE-text" means more lines follow; "CODE text" (or
                // "CODE" alone) means this was the last one.
                let afterCode = line.dropFirst(code.count)
                if afterCode.first != "-" { return }
            }
        }

        /// Reads bytes until a CRLF, decodes it as a line, and leaves any remainder buffered
        /// for the next read.
        private func readLine() async throws -> String {
            while true {
                if let range = buffer.range(of: Data([0x0D, 0x0A])) {
                    let lineData = buffer.subdata(in: buffer.startIndex..<range.lowerBound)
                    buffer.removeSubrange(buffer.startIndex..<range.upperBound)
                    guard let line = String(data: lineData, encoding: .utf8) else {
                        throw SMTPError.unexpectedReply("<non-UTF8 reply>")
                    }
                    return line
                }
                let chunk = try await receiveChunk()
                buffer.append(chunk)
            }
        }

        private func receiveChunk() async throws -> Data {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, isComplete, error in
                    if let error {
                        continuation.resume(throwing: SMTPError.connectionFailed(error.localizedDescription))
                    } else if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else if isComplete {
                        continuation.resume(throwing: SMTPError.connectionFailed("Connection closed by smtp.gmail.com."))
                    } else {
                        continuation.resume(throwing: SMTPError.connectionFailed("Empty read."))
                    }
                }
            }
        }
    }
}
