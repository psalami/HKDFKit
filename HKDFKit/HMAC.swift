//
//  hmac.swift
//  HKDFKit
//
//  Created by silenteh on 07/02/16.
//  Copyright © 2016 silenteh. All rights reserved.
//

import Foundation
import CommonCrypto

public final class HMAC {
    var context: CCHmacContext = CCHmacContext()
    var algorithm:HKDFKit.Hash
    
    init(algorithm: HKDFKit.Hash, key: Data) {
        self.algorithm = algorithm
        CCHmacInit(
            &context,
            algorithm.function,
            (key as NSData).bytes,
            key.count
        )
    }
    
    func updateWithData(_ data: Data) {
        //CCHmacUpdate(&context, (data as NSData).bytes, data.count)
		data.withUnsafeBytes({ (dataPtr) -> Void in
			CCHmacUpdate(&context, dataPtr, data.count)
		})
		
    }
    
    func finalData() -> Data {
        let hmac = NSMutableData(length: algorithm.length)!
        CCHmacFinal(&context, hmac.mutableBytes)
        return hmac as Data
    }
}
