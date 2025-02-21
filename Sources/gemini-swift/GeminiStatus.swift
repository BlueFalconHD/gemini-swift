//
//  GeminiStatus.swift
//  gemini-swift
//
//  Created by Hayes Dombroski on 2/20/25.
//


// 10-19 Input expected
// 20-29 Success
// 30-39 Redirection
// 40-49 Temporary failure
// 50-59 Permanent failure
// 60-69 Client certificates

/// Represents a response code from a Gemini server. Splits them up into general categories as described by the spec, but also allows access to the raw value.
public enum GeminiStatus {
    case inputExpected(Int)
    case success(Int)
    case redirection(Int)
    case temporaryFailure(Int)
    case permanentFailure(Int)
    case clientCertificates(Int)
    case other(Int)
    
    func description() -> String {
        switch self {
        case .inputExpected(let code):
            return "Input expected: \(code)"
        case .success(let code):
            return "Success: \(code)"
        case .redirection(let code):
            return "Redirection: \(code)"
        case .temporaryFailure(let code):
            return "Temporary failure: \(code)"
        case .permanentFailure(let code):
            return "Permanent failure: \(code)"
        case .clientCertificates(let code):
            return "Client certificates: \(code)"
        case .other(let code):
            return "Other: \(code)"
        }
    }
}

public extension GeminiStatus {
    init(rawValue: Int) {
        switch rawValue {
        case 10...19:
            self = .inputExpected(rawValue)
        case 20...29:
            self = .success(rawValue)
        case 30...39:
            self = .redirection(rawValue)
        case 40...49:
            self = .temporaryFailure(rawValue)
        case 50...59:
            self = .permanentFailure(rawValue)
        case 60...69:
            self = .clientCertificates(rawValue)
        default:
            self = .other(rawValue)
        }
    }
}
