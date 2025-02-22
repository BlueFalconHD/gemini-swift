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

    private let dataBuffer = DataBuffer()

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
        let headerData = try await receiveLine(over: connection)
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
                secProtocolVerifyComplete(false)
                return
            }
            
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()

            guard let certChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
            let firstCert = certChain.first else {
                secProtocolVerifyComplete(false)
                return
            }

            let serverCertData = SecCertificateCopyData(firstCert) as Data
            let fingerprint = self.sha256(data: serverCertData)

            do {
                if let savedFingerprint = try KeychainHelper.getFingerprint(forHost: host) {
                    if savedFingerprint == fingerprint {
                        secProtocolVerifyComplete(true)
                    } else {
                        secProtocolVerifyComplete(false)
                    }
                } else {
                    try KeychainHelper.saveFingerprint(fingerprint, forHost: host)
                    secProtocolVerifyComplete(true)
                }
            } catch {
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
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    /// Receives a line of data over the connection.
    private func receiveLine(over connection: NWConnection) async throws -> Data {
        var lineData = Data()
        while true {
            let data = try await receiveData(over: connection)
            if let index = data.firstIndex(of: 0x0A) { // Newline character
                lineData.append(data.prefix(upTo: index))
                // Save the rest of the data (after newline) to buffer
                let restOfData = data.suffix(from: data.index(after: index))
                if !restOfData.isEmpty {
                    // Append the restOfData to dataBuffer
                    await dataBuffer.append(restOfData)
                }
                break
            } else {
                lineData.append(data)
            }
        }
        return lineData
    }


    /// Receives the body data over the connection.
    private func receiveBody(over connection: NWConnection) async throws -> Data {
        var bodyData = Data()
        var i = 0
        repeat {
            i += 1
            let data = try await receiveData(over: connection)
            if data.isEmpty {
                break;
            }
            bodyData.append(data)
        } while true
        return bodyData
    }

    /// Receives data over the connection.
    private func receiveData(over connection: NWConnection) async throws -> Data {
        // First, check if there's data in buffer
        if await !dataBuffer.isEmpty {
            let data = await dataBuffer.getData()
            await dataBuffer.empty()
            return data
        }
        // If buffer is empty, read from connection
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let data = data {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(returning: Data())
                } else {
                    continuation.resume(throwing: GeminiError.custom("No data received"))
                }
            }
        }
    }
}
