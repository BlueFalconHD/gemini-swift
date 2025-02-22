import Foundation
import Network
import Security
import CryptoKit

/// A GeminiClient is responsible for making requests to Gemini servers.
public class GeminiClient: @unchecked Sendable {
    private actor ConnectionState {
        var isCancelled = false

        func setCancelled() {
            isCancelled = true
        }

        func checkCancelled() -> Bool {
            return isCancelled
        }
    }

    private actor BodyData {
        var data = Data()

        func append(_ data: Data) {
            self.data.append(data)
        }

        func getData() -> Data {
            return data
        }
    }

    /// Initializes a new GeminiClient
    public init() {}

    /// Sends a request to the given URL.
    /// - Parameter url: The Gemini URL to request.
    /// - Returns: A `GeminiResponse` containing the status, meta, and body.
    public func get(url: URL) async throws -> GeminiResponse {
        guard url.scheme == "gemini" else {
            throw GeminiError.invalidURL
        }

        let (status, meta, body) = try await fetchGeminiURL(url)
        return GeminiResponse(status: GeminiStatus(rawValue: status), meta: meta, body: body)
    }

    /// Fetches the Gemini URL.
    private func fetchGeminiURL(_ url: URL) async throws -> (Int, String, Data) {
        // Establish a TLS connection using Network framework
        guard let host = url.host else {
            throw GeminiError.invalidURL
        }
        let port = url.port ?? 1965
        let params = NWParameters(tls: tlsOptions(host: host))
        let connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(integerLiteral: UInt16(port)), using: params)

        let connectionState = ConnectionState()

        // Start the connection
        connection.stateUpdateHandler = { newState in
            switch newState {
            case .ready:
                break
            case .failed(let error):
                Task {
                    if !(await connectionState.checkCancelled()) {
                        throw error
                    }
                }
            case .cancelled:
                Task {
                    await connectionState.setCancelled()
                }
            default:
                break
            }
        }
        connection.start(queue: .global())

        // Send the request
        let requestLine = "\(url.absoluteString)\r\n"
        guard let requestData = requestLine.data(using: .utf8) else {
            throw GeminiError.invalidURL
        }
        try await send(data: requestData, over: connection)

        // Receive the response header
        let (headerData, extraData) = try await receiveLine(over: connection)
        guard let headerLine = String(data: headerData, encoding: .utf8) else {
            throw GeminiError.invalidResponse
        }

        // Parse the status and meta
        let parts = headerLine.components(separatedBy: " ")
        guard parts.count >= 2, let status = Int(parts[0]) else {
            throw GeminiError.invalidResponse
        }
        let meta = parts.dropFirst().joined(separator: " ").trimmingCharacters(in: .whitespacesAndNewlines)

        // Handle redirection
        if status >= 30 && status < 40 {
            print("Redirecting to \(meta)")
            guard let redirectURL = URL(string: meta, relativeTo: url) else {
                throw GeminiError.invalidRedirectURL
            }
            // Limit redirection depth to avoid infinite loops (max 5)
            var redirects = url.redirects ?? 0
            redirects += 1
            if redirects > 5 {
                throw GeminiError.tooManyRedirects
            }
            var redirectedURL = redirectURL
            redirectedURL.redirects = redirects
            connection.cancel()
            return try await fetchGeminiURL(redirectedURL)
        }

        // Read the body if applicable
        var bodyData = Data()
        if status >= 20 && status < 30 {
            bodyData.append(extraData)
            bodyData = try await receiveBody(over: connection)
        }

        connection.cancel()
        return (status, meta, bodyData)
    }

    /// Sets up TLS options with TOFU certificate validation.
    private func tlsOptions(host: String) -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()

        sec_protocol_options_set_min_tls_protocol_version(options.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(options.securityProtocolOptions, .TLSv13)

        // Implement TOFU using Keychain
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { [weak self] secProtocolMetadata, secTrust, secProtocolVerifyComplete in
            guard let self = self else {
                print("self is nil")
                secProtocolVerifyComplete(false)
                return
            }
            
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()

            guard let certChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  let firstCert = certChain.first else {
                print("failed to get certificate chain")
                secProtocolVerifyComplete(false)
                return
            }

            let serverCertData = SecCertificateCopyData(firstCert) as Data
            let fingerprint = self.sha256(data: serverCertData)

            do {
                if let savedFingerprint = try KeychainHelper.getFingerprint(forHost: host) {
                    // Host is known; verify fingerprint
                    if savedFingerprint == fingerprint {
                        print("Fingerprint matches; connection verified")
                        secProtocolVerifyComplete(true)
                    } else {
                        // Fingerprint mismatch; possible MITM attack
                        print("Fingerprint mismatch; possible MITM attack")
                        secProtocolVerifyComplete(false)
                    }
                } else {
                    // First time seeing this host; save the fingerprint
                    print("First time seeing host; saving fingerprint")
                    try KeychainHelper.saveFingerprint(fingerprint, forHost: host)
                    secProtocolVerifyComplete(true)
                }
            } catch {
                // Handle Keychain errors appropriately
                print("Keychain error: \(error)")
                secProtocolVerifyComplete(false)
            }

        }, DispatchQueue.global())

        return options
    }

    /// Calculates the SHA256 fingerprint of the certificate data.
    private func sha256(data: Data) -> String {
        let hash = SHA256.hash(data: data)
        return Data(hash).base64EncodedString()
    }

    /// Sends data over the connection.
    private func send(data: Data, over connection: NWConnection) async throws {
        print("sending data")
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    print("error sending data: \(error)")
                    continuation.resume(throwing: error)
                } else {
                    print("data sent")
                    continuation.resume()
                }
            })
        }
    }

    /// Receives a line of data over the connection.
    private func receiveLine(over connection: NWConnection) async throws -> (line: Data, remainder: Data) {
        var lineData = Data()
        var remainder = Data()
        while true {
            let data = try await receiveData(over: connection)
            if let index = data.firstIndex(of: 0x0A) {
                lineData.append(data.prefix(upTo: index))
                remainder = data.suffix(from: index + 1)
                break
            } else {
                lineData.append(data)
            }
        }
        return (lineData, remainder)
    }

    /// Receives the body data over the connection.
    private func receiveBody(over connection: NWConnection) async throws -> Data {
        print("receiving body data")
        var bodyData = Data()
        var i = 0
        repeat {
            i += 1
            print("receiving body data \(i)")
            let data = try await receiveData(over: connection)
            if data.isEmpty {
                break;
            }
            print("length: \(data.count), hash: \(sha256(data: data))")
            
            bodyData.append(data)
        } while true
        return bodyData
    }

    /// Receives data over the connection.
    private func receiveData(over connection: NWConnection) async throws -> Data {
        print("receiving data")
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: 0, maximumLength: 65536) { data, _, isComplete, error in
                if let error = error {
                    print("error getting data: \(error)")
                    continuation.resume(throwing: error)
                } else if let data = data {
                    print("got data with length: \(data.count)")
                    continuation.resume(returning: data)
                } else if isComplete {
                    print("no data received, connection closed")
                    continuation.resume(returning: Data())
                } else {
                    print("no data received, connection still open")
                    continuation.resume(throwing: GeminiError.custom("No data received"))
                }
            }
        }
    }
}
