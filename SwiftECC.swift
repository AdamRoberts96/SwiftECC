//
//  SwiftECC.swift
//  Scanner
//
//  Created by Adam Roberts on 23/03/2017.
//  Copyright © 2017 Adam Roberts. All rights reserved.
//

import Foundation
import Security

func hashSHA512Hex(data:Data) -> String{
return "test"
}

class Point{
    let x: BInt
    let y: BInt
    
    init(x:BInt, y:BInt){
        self.x = x
        self.y = y
    }
    
    static func ==(lhs: Point, rhs: Point) -> Bool{
        return(lhs.x == rhs.x && lhs.y == rhs.y)
    }
    
}


class KPair{
    let privKey: BInt
    let pubKey: Point
    let curve: Curve
    
    init(curve: Curve){
        let initKey = randomBInt(bits: 96)
        self.privKey = initKey % curve.n
        self.pubKey = scalarMultiply(k: privKey, point: curve.basePoint, curve: curve)
        self.curve = curve
    }
}

class Curve {
    let name: String
    //Field parameter
    let p: BInt
    
    //Curve coefficients
    let a: BInt
    let b: BInt
    
    //Base point
    let basePoint:Point
    
    //Subgroup order
    let n: BInt
    
    //Subgroup cofactor 64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
    let h: BInt
    
    init(curveName: String = "secp192r1"){
        
        //Parameters specified by NIST at http://www.secg.org/SEC2-Ver-1.0.pdf
        
        self.name = "secp192r1"
        self.p = BInt(number: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF".lowercased(), withBase: 16)
        self.a = BInt(-3)
        self.b = BInt(number: "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1".lowercased(), withBase: 16)
        self.basePoint = Point(x: BInt(number: "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012".lowercased(), withBase: 16),
                            y: BInt(number: "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811".lowercased(), withBase: 16))
        self.n = BInt(number: "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831".lowercased(), withBase: 16)
        self.h = BInt(1)
        
        
    }
    
}

//Returns the inverse of k modulo p
func inverseMod(k:BInt, p:BInt) -> BInt{
    
    if (k == 0){
        print ("Cannot divide by 0")
        return BInt(0)
    }
    
    if (k < 0){
        return p - inverseMod(k: -k, p: p)
    }
    var s = BInt(0)
    var oldS = BInt(1)
    var t = BInt(1)
    var oldT = BInt(0)
    var r = p
    var oldR = k
    var quotient = BInt(0)
    var temp = BInt(0)
    
    while (r != 0){
        quotient = (oldR / r)
        
        temp = r
        r = oldR - (quotient * r)
        oldR = temp
        
        temp = t
        t = oldT - (quotient * t)
        oldT = temp
        
        temp = s
        s = oldS - (quotient * s)
        oldS = temp
    }
    
    
    let gcd = oldR
    
    //+p to make positive as BInt has trouble with negative mod
    let x = oldS + p
    let y = oldT
    return x % p
}

func isOnCurve(point:Point, curve:Curve) -> Bool{
    let nullPoint = Point(x: 0,y: 0)
    
    if (point == nullPoint){
        return true
    }
    let test = (((point.y * point.y) - (point.x * point.x * point.x) - (curve.a * point.x) - curve.b) % curve.p)
    return (((point.y * point.y) - (point.x * point.x * point.x) - (curve.a * point.x) - curve.b) % curve.p == 0)
}

func pointNeg(point:Point, curve:Curve) -> Point{
    //assert(isOnCurve(point: point, curve: curve))
    return Point(x: point.x, y:((curve.p - point.y) % curve.p))
}

func pointAdd(point1: Point, point2: Point, curve: Curve) -> Point{
    let nullPoint = Point(x: 0,y: 0)
    
    if(point1 == nullPoint){
        return point2
    }
    
    if (point2 == nullPoint){
        return point1
    }
    

    let x1 = point1.x
    let y1 = point1.y
    
    let x2 = point2.x
    let y2 = point2.y
    
    if(x1 == x2 && y1 != y2){
        return Point(x: 0,y: 0)
    }
    var m = BInt(0)
    
    if (x1 == x2){
        m = (3 * x1 * x1 + curve.a) * inverseMod(k: 2 * y1, p: curve.p)
    } else {
        m = (y1 - y2) * inverseMod(k: x1 - x2, p: curve.p)
    }
    
    var x3 = m * m - x1 - x2
    var y3 = y1 + m * (x3 - x1)
    x3 = x3 % curve.p
    y3 = y3 % curve.p
    return Point(x: x3, y: -y3)
    
}

//Returns a scalar multiple of the point using the double and add method
func scalarMultiply(k: BInt, point: Point, curve:Curve) -> Point{
    let nullPoint = Point(x: 0,y: 0)
    if (k % curve.n == 0 || point == nullPoint){
        return nullPoint
    }
    var mult = k
    if (mult < 0){
        //-k * point == k * -point
        return scalarMultiply(k: -k, point: pointNeg(point: point, curve: curve), curve: curve)
    }
    var result = nullPoint
    var add = point
    while (mult != 0) {
        if (mult.isOdd()){
            result = pointAdd(point1: result, point2: add, curve: curve)
        }
        add = pointAdd(point1: add, point2: add, curve: curve)
        mult = mult >> 1
    }
    return result
}

func createKeyPairSwiftECC(curve: Curve){
    let aliceKey = KPair(curve: curve)
    let bobKey = KPair(curve: curve)
    let s1 = scalarMultiply(k: aliceKey.privKey, point: bobKey.pubKey, curve: curve)
    let s2 = scalarMultiply(k: bobKey.privKey, point: aliceKey.pubKey, curve: curve)
    print("ECDH - Checking if shared secret matches")
    print(s1==s2)
}

func generateSharedSecret(selfKey: KPair, recievedPublicKey: Point, curve: Curve) -> BInt{
    let sharedSecret = scalarMultiply(k: selfKey.privKey, point: recievedPublicKey, curve: curve)
    return sharedSecret.x
}



extension String {
    
    func sha256() -> String {
        let data = self.data(using: .utf8)!
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes({
            _ = CC_SHA256($0, CC_LONG(data.count), &digest)
        })
        return digest.map({ String(format: "%02hhx", $0) }).joined(separator: "")
    }
    
}

func hashMessage(message: String, curve: Curve) -> BInt{
    let hash = message.sha256()
    var intHash = BInt(number: hash, withBase: 16)
    
    while(intHash > curve.n){
        intHash = intHash >> 1
    }
    return intHash
}

func signMessage(privateKey: BInt, message: String, curve: Curve) -> (BInt, BInt) {
    
    let hash = hashMessage(message: message, curve: curve)
    var r: BInt = 0
    var s: BInt = 0
    var k: BInt = 0
    
    while(r != 0 || s != 0){
        while(k == 0 || k >= curve.p){
            k = randomBInt(bits: 500)
            k = k % curve.p
        }
        let point = scalarMultiply(k: k, point: curve.basePoint, curve: curve)
        r = point.x
        s = ((hash + r * privateKey) * inverseMod(k: k, p: curve.n)) % curve.n
    }
    return (r, s)
}

func verifySignature(publicKey: Point, message: String, r: BInt, s: BInt, curve: Curve) -> Bool{
    let hash = hashMessage(message: message, curve: curve)
    let w = inverseMod(k: s, p: curve.n)
    let u1 = (hash * w) % curve.n
    let u2 = (r * w) % curve.n
    let point1 = scalarMultiply(k: u1, point: curve.basePoint, curve: curve)
    let point2 = scalarMultiply(k: u2, point: publicKey, curve: curve)
    let checkPoint = pointAdd(point1: point1, point2: point2, curve: curve)
    
    if( (r % curve.n) == (checkPoint.x % curve.n)){
        return true
    }
    else {
        return false
    }
    
}

