import Foundation
import Network
import Security
import CommonCrypto

/// A GeminiClient is responsible for making requests to Gemini servers.
public class GeminiClient: @unchecked Sendable {
    /// The directory where known hosts and their certificate fingerprints are stored.
    private let knownHostsDirectory: URL
    
    private actor ConnectionState {
        var isCancelled = false
        
        func setCancelled() {
            isCancelled = true
        }
        
        func checkCancelled() -> Bool {
            return isCancelled
        }
    }
    
    /// Initializes a new GeminiClient with the given directory for storing known hosts.
    public init(knownHostsDirectory: URL) {
        self.knownHostsDirectory = knownHostsDirectory
        try? FileManager.default.createDirectory(at: knownHostsDirectory, withIntermediateDirectories: true)
    }
    
    /// Sends a request to the given URL.
    /// - Parameter url: The Gemini URL to request.
    /// - Returns: A `GeminiResponse` containing the status, meta, and body.
    public func get(url: URL) async throws -> GeminiResponse {
        guard url.scheme == "gemini" else {
            throw GeminiError.invalidURL
        }
        
        let (status, meta, body) = try await fetchGeminiURL(url)
        return GeminiResponse(status: status, meta: meta, body: body)
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
        
        // Implement TOFU
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { [weak self] secProtocolMetadata, secTrust, secProtocolVerifyComplete in
            guard let self = self else {
                secProtocolVerifyComplete(false)
                return
            }
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            
            // serverCert is CFArray<UnsafeRawPointer<SecCertificate>>
            guard let serverCert = SecTrustCopyCertificateChain(trust) else {
                secProtocolVerifyComplete(false)
                return
            }
            
            // make sure there is at least one certificate
            if CFArrayGetCount(serverCert) == 0 {
                secProtocolVerifyComplete(false)
                //FIXME: handle error better
                return
            }
            
            // Print first item
            print(CFArrayGetValueAtIndex(serverCert, 0))
            
            if let serverCertArray = SecTrustCopyCertificateChain(trust) as? NSArray {
                print(serverCertArray)
            }
            
            if let certChain1 = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                // Now you have an array of SecCertificate objects
                print(certChain1)
                for cert in certChain1 {
                    // Work with individual certificates
                    print(cert)
                }
            }
            
            if let certChain = SecTrustCopyCertificateChain(trust) {
                let certCount = CFArrayGetCount(certChain)
                if certCount > 0 {
                    for index in 0..<certCount {
                        // Get the certificate at the current index
                        if let certPointer = CFArrayGetValueAtIndex(certChain, index) {
                            // Convert the pointer to CFTypeRef
                            let certRef = unsafeBitCast(certPointer, to: CFTypeRef.self)
                            // Verify that the CFTypeRef is actually a SecCertificate
                            if CFGetTypeID(certRef) == SecCertificateGetTypeID() {
                                // It's safe to treat certRef as a SecCertificate
                                let certificate = certRef as! SecCertificate
                                // Now you can use 'certificate' as a SecCertificate
                                // For example, get the certificate data
                                if let certData = SecCertificateCopyData(certificate) as Data? {
                                    // Do something with certData
                                }
                            } else {
                                // The type did not match; handle the error appropriately
                                print("Element at index \(index) is not a SecCertificate")
                            }
                        } else {
                            // Failed to get value at index; handle the error appropriately
                            print("Failed to get certificate at index \(index)")
                        }
                    }
                } else {
                    print("Certificate chain is empty")
                }
            } else {
                print("Failed to copy certificate chain from serverTrust")
            }


            
            
            

            
            
//            let serverCertData = SecCertificateCopyData(serverCert!) as Data
//            let fingerprint = sha256(data: serverCertData)
//            
//            let knownHostFile = self.knownHostsDirectory.appendingPathComponent(host)
//            if FileManager.default.fileExists(atPath: knownHostFile.path) {
//                // Host is known; verify fingerprint
//                do {
//                    let savedFingerprint = try String(contentsOf: knownHostFile, encoding: .utf8)
//                    if savedFingerprint == fingerprint {
//                        secProtocolVerifyComplete(true)
//                    } else {
//                        // Fingerprint mismatch; possible MITM attack
//                        secProtocolVerifyComplete(false)
//                    }
//                } catch {
//                    secProtocolVerifyComplete(false)
//                }
//            } else {
//                // First time seeing this host; save the fingerprint
//                do {
//                    try fingerprint.write(to: knownHostFile, atomically: true, encoding: .utf8)
//                    secProtocolVerifyComplete(true)
//                } catch {
//                    secProtocolVerifyComplete(false)
//                }
//            }
            
            //FIXME: do actual TOFU verification
            secProtocolVerifyComplete(true)
        }, DispatchQueue.global())
        
        return options
    }
    
    /// Calculates the SHA256 fingerprint of the certificate data.
    private func sha256(data: Data) -> String {
        var sha256 = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &sha256)
        }
        return Data(sha256).base64EncodedString()
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
        while true {
            guard let data = try? await receiveData(over: connection), !data.isEmpty else {
                break
            }
            bodyData.append(data)
        }
        return bodyData
    }
    
    /// Receives data over the connection.
    private func receiveData(over connection: NWConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
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
