//
//  GeminiClient.swift
//  gemini-swift
//
//  Created by Hayes Dombroski on 2/20/25.
//

import Foundation
import Network

import Foundation
import Network

public class GeminiClient: @unchecked Sendable {
    public init() {}
    
    public func get(url: URL) async throws -> GeminiResponse {
        guard url.scheme == "gemini" else {
            throw GeminiError.invalidURL
        }
        
        let (status, meta, body) = try await fetchGeminiURL(url)
        return GeminiResponse(status: status, meta: meta, body: body)
    }
    
    private func fetchGeminiURL(_ url: URL) async throws -> (Int, String, Data) {
        guard let host = url.host else {
            throw GeminiError.invalidURL
        }
        guard let port = NWEndpoint.Port(rawValue: UInt16(url.port ?? 1965)) else {
            throw GeminiError.invalidURL
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tls)
        
        return try await withCheckedThrowingContinuation { continuation in
            connection.stateUpdateHandler = { (state: NWConnection.State) in
                switch state {
                case .ready:
                    Task {
                        do {
                            try await self.sendRequest(url: url, over: connection)
                            let (status, meta, body) = try await self.receiveResponse(over: connection)
                            connection.cancel()
                            continuation.resume(returning: (status, meta, body))
                        } catch {
                            connection.cancel()
                            continuation.resume(throwing: error)
                        }
                    }
                case .failed(let error):
                    continuation.resume(throwing: error)
                case .cancelled:
                    continuation.resume(throwing: GeminiError.connectionClosed)
                default:
                    break
                }
            }
            connection.start(queue: .global())
        }
    }
    
    private func sendRequest(url: URL, over connection: NWConnection) async throws {
        let requestLine = "\(url.absoluteString)\r\n"
        guard let requestData = requestLine.data(using: .utf8) else {
            throw GeminiError.invalidURL
        }
        try await send(data: requestData, over: connection)
    }
    
    private func receiveResponse(over connection: NWConnection) async throws -> (Int, String, Data) {
        let headerData = try await receiveLine(over: connection)
        guard let headerLine = String(data: headerData, encoding: .utf8) else {
            throw GeminiError.invalidResponse
        }
        
        let trimmedHeader = headerLine.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmedHeader.components(separatedBy: " ")
        guard parts.count >= 2, let status = Int(parts[0]) else {
            throw GeminiError.invalidResponse
        }
        let meta = parts.dropFirst().joined(separator: " ")
        
        var bodyData = Data()
        if status >= 20 && status < 30 {
            while true {
                if let chunk = try await receiveData(over: connection) {
                    bodyData.append(chunk)
                } else {
                    break
                }
            }
        }
        
        return (status, meta, bodyData)
    }
    
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
    
    private func receiveLine(over connection: NWConnection) async throws -> Data {
        var lineData = Data()
        while true {
            guard let data = try await receiveData(over: connection) else {
                throw GeminiError.connectionClosed
            }
            if let index = data.firstIndex(of: 0x0A) { // Newline character '\n'
                lineData.append(data.prefix(upTo: index))
                break
            } else {
                lineData.append(data)
            }
        }
        return lineData
    }
    
    private func receiveData(over connection: NWConnection) async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let data = data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(returning: nil)
                } else {
                    continuation.resume(returning: nil)
                }
            }
        }
    }
}
