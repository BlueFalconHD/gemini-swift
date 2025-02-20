//
//  GeminiError.swift
//  gemini-swift
//
//  Created by Hayes Dombroski on 2/20/25.
//

import Foundation

/// Represents errors that can occur in the Gemini client.
public enum GeminiError: Error {
    case invalidURL
    case invalidResponse
    case badStatusCode(Int)
    case connectionClosed
    case custom(String)
}
