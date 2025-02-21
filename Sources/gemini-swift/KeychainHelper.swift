//
//  KeychainHelper.swift
//  gemini-swift
//
//  Created by Hayes Dombroski on 2/20/25.
//

import Security
import Foundation

struct KeychainHelper {
    enum KeychainError: Error {
        case unexpectedData
        case unhandledError(status: OSStatus)
    }
    
    static func saveFingerprint(_ fingerprint: String, forHost host: String) throws {
        guard let data = fingerprint.data(using: .utf8) else { return }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: host,
            kSecValueData as String: data,
            // Optional: Specify access level
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        // Delete any existing item
        SecItemDelete(query as CFDictionary)
        
        // Add new item
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status: status)
        }
    }

    static func getFingerprint(forHost host: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: host,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            if let data = result as? Data,
               let fingerprint = String(data: data, encoding: .utf8) {
                return fingerprint
            } else {
                throw KeychainError.unexpectedData
            }
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unhandledError(status: status)
        }
    }

    static func deleteFingerprint(forHost host: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: host
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status: status)
        }
    }
}
