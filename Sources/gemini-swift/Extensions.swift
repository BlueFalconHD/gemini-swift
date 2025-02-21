//
//  Extensions.swift
//  gemini-swift
//
//  Created by Hayes Dombroski on 2/20/25.
//

import Foundation

// Extension to add redirect count to URL
extension URL {
    //FIXME: This is a workaround for the lack of static stored properties in Swift
    nonisolated(unsafe) private static var redirectsKey = "redirectsKey"
    
    var redirects: Int? {
        get {
            return objc_getAssociatedObject(self, &URL.redirectsKey) as? Int
        }
        set {
            objc_setAssociatedObject(self, &URL.redirectsKey, newValue, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
        }
    }
}
