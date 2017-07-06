//
//  HKDFKit.swift
//  HKDFKit
//
//  Created by silenteh on 06/02/16.
//  Copyright © 2016 silenteh. All rights reserved.
//

import Foundation
import CommonCrypto

open class HKDFKit {
    
    // MARK: - Types
    
    public enum Hash {
        case sha256
        case sha384
        case sha512
        case sha224
        
        public var function: CCHmacAlgorithm {
            switch self {
            case .sha224: return CCHmacAlgorithm(kCCHmacAlgSHA224)
            case .sha256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
            case .sha384: return CCHmacAlgorithm(kCCHmacAlgSHA384)
            case .sha512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
            }
        }
        
        public var length: Int {
            switch self {
            case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
            case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
            case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
            case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
    }

    /**
     *  Standard HKDF implementation. http://tools.ietf.org/html/rfc5869
     *
     *  @param algorithm  Hash.[SHA256,SHA224,SHA384,SHA512]
     *  @param seed       Original keying material
     *  @param info       Expansion "salt"
     *  @param salt       Extraction salt
     *  @param outputSize Size of the output
     *
     *  @return The derived key material
     */
    static func deriveKey(_ algorithm: Hash, seed:Data, info:Data, salt:Data, outputSize:Int) -> Data {
        return deriveKey(algorithm, seed:seed, info:info, salt:salt, outputSize:outputSize, offset:1)
    }
    
    /**
    *  TextSecure v2 HKDF implementation
    *
    *  @param algorithm  Hash.[SHA256,SHA224,SHA384,SHA512]
    *  @param seed       Original keying material
    *  @param info       Expansion "salt"
    *  @param salt       Extraction salt
    *  @param outputSize Size of the output
    *
    *  @return The derived key material
    */
    
    static func TextSecureV2deriveKey(_ algorithm: Hash, seed:Data, info:Data, salt:Data, outputSize:Int) -> Data {
        return deriveKey(algorithm, seed:seed, info:info, salt:salt, outputSize:outputSize, offset:0)
    }
    
    // MARK: - Private Methods
    fileprivate static func deriveKey(_ algorithm: Hash,
        seed:Data, info:Data, salt:Data, outputSize:Int, offset:Int) -> Data {
            
        // extract phase
        let prk:Data = extract(algorithm, key: seed, salt: salt)
            
        // expand phase
        let okm:Data = expand(algorithm, prk: prk, info: info, outputSize: outputSize, offset: offset)
        return okm;
    }
    
    internal static func extract(_ algorithm: Hash, key:Data, salt:Data) -> Data {
        
        // simpler variant
        //var prk = [CChar](count:algorithm.length, repeatedValue: 0)
        
        // malloc the pointer
        let prk = UnsafeMutablePointer<CChar>.allocate(capacity: algorithm.length)
        // initialize the pointer so that it does nto contain garbage
        prk.initialize(to: 0)        
        
        CCHmac(algorithm.function, (salt as NSData).bytes, salt.count, (key as NSData).bytes, key.count, prk);
		let result: Data = Data(bytes: prk, count:algorithm.length)
		/*let result:Data = prk.withMemoryRebound(to: UInt8.self, capacity: algorithm.length, { (prkRebound) in
			return Data(bytes: prkRebound, count: algorithm.length)
		})*/
		
        
        // destroy the pointer (we clean up the memory)
        prk.deinitialize()
        // free the pointer
        prk.deallocate(capacity: algorithm.length)
        
        return result
        
    }

    // prk = pseudo random key. Please note this is NOT a password !!!
    internal static func expand(_ algorithm: Hash, prk:Data, info:Data, outputSize:Int, offset:Int) -> Data {
        // calculate N in T(N)
        let iterations = Int(ceil(Double(outputSize)/Double(algorithm.length)))
        
        var mixin = Data()
        
        let results = NSMutableData()

        for var index in offset ..< (iterations + offset) {
            
            let hmac = HMAC(algorithm: algorithm, key: prk)
        
            // T(0) = empty string | info | index
            if index != 1 {
                hmac.updateWithData(mixin)
            }
            
            if info.count > 0 {
                hmac.updateWithData(info)
            }
			
			let counter = Data(buffer: UnsafeBufferPointer(start: &index, count:1))

            hmac.updateWithData(counter)
			let stepResult = hmac.finalData().withUnsafeBytes({ (hmacPtr) in
				return Data(bytes:hmacPtr, count:hmac.finalData().count)
			})
			
            
            results.append(stepResult)
            mixin = (stepResult as NSData).copy() as! Data
        }
		return Data(referencing: results).subdata(in: 0 ..< outputSize)
    }
    
}



