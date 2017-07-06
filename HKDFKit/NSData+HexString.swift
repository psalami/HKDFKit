//
//  NSData+HexString.swift
//  HKDFKit
//
//  Created by silenteh on 07/02/16.
//  Copyright © 2016 silenteh. All rights reserved.
//

import Foundation

extension String {
    
    public func dataFromHexString() -> Data {
        var bytes = [UInt8]()
        for i in 0..<(self.characters.count/2) {
            let stringBytes = self.substring(with: (self.characters.index(self.startIndex, offsetBy: 2*i) ..< self.characters.index(self.startIndex, offsetBy: 2*i+2)))
            let byte = strtol((stringBytes as NSString).utf8String, nil, 16)
            bytes.append(UInt8(byte))
        }

        return Data(bytes: UnsafePointer<UInt8>(bytes), count:bytes.count)
    }
}

extension Data {
    
    func toHexString() -> String {
        
        var hexString: String = ""
        let dataBytes =  (self as NSData).bytes.bindMemory(to: CUnsignedChar.self, capacity: self.count)
        
		for i:Int in 0..<self.count {
            hexString +=  String(format: "%02x", dataBytes[i])
        }
        
        return hexString
    }
}
