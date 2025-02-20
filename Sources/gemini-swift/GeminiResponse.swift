//
//  GeminiResponse.swift
//  gemini-swift
//
//  Created by Hayes Dombroski on 2/20/25.
//

import Foundation

/// Represents a response from a Gemini server.
public struct GeminiResponse {
    /// The status code of the response.
    public let status: Int
    
    /// The meta text of the response.
    public let meta: String
    
    /// The body data of the response.
    public let body: Data
}
