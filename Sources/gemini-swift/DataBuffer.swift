//
//  DataBuffer.swift
//  gemini-swift
//
//  Created by Hayes Dombroski on 2/21/25.
//

import Foundation

internal actor DataBuffer {
    var buffer = Data()
    
    func append(_ data: Data) {
        buffer.append(data)
    }
    
    func getData() -> Data {
        let data = buffer
        buffer = Data()
        return data
    }
    
    func hasData() -> Bool {
        return !buffer.isEmpty
    }
    
    var isEmpty: Bool {
        return buffer.isEmpty
    }
    
    func empty() {
        buffer = Data()
    }
}
