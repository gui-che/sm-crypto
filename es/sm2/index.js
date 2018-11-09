import { BigInteger } from 'jsbn';
import { encodeDer, decodeDer } from './asn1';
import { ECPointFp, ECFieldElementFp, ECCurveFp } from './ec';

import SM3Digest from './sm3';
import SM2Cipher from './sm2';
import _ from './utils';

var _$generateEcparam = _.generateEcparam(),
    G = _$generateEcparam.G,
    curve = _$generateEcparam.curve,
    n = _$generateEcparam.n;

var C1C2C3 = 0;

/**
 * 加密
 */
function doEncrypt(msg, publicKey) {
    var cipherMode = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 1;

    var cipher = new SM2Cipher();
    msg = _.hexToArray(_.parseUtf8StringToHex(msg));

    if (publicKey.length > 128) {
        publicKey = publicKey.substr(publicKey.length - 128);
    }
    var xHex = publicKey.substr(0, 64);
    var yHex = publicKey.substr(64);
    publicKey = cipher.createPoint(xHex, yHex);

    var c1 = cipher.initEncipher(publicKey);

    cipher.encryptBlock(msg);
    var c2 = _.arrayToHex(msg);

    var c3 = new Array(32);
    cipher.doFinal(c3);
    c3 = _.arrayToHex(c3);

    return cipherMode === C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2;
}

/**
 * 解密
 */
function doDecrypt(encryptData, privateKey) {
    var cipherMode = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 1;

    var cipher = new SM2Cipher(cipherMode);

    privateKey = new BigInteger(privateKey, 16);

    var c1X = encryptData.substr(0, 64);
    var c1Y = encryptData.substr(0 + c1X.length, 64);
    var c1Length = c1X.length + c1Y.length;

    var c3 = encryptData.substr(c1Length, 64);
    var c2 = encryptData.substr(c1Length + 64);

    if (cipherMode === C1C2C3) {
        c3 = encryptData.substr(encryptData.length - 64);
        c2 = encryptData.substr(c1Length, encryptData.length - c1Length - 64);
    }

    var data = _.hexToArray(c2);

    var c1 = cipher.createPoint(c1X, c1Y);
    cipher.initDecipher(privateKey, c1);
    cipher.decryptBlock(data);
    var c3_ = new Array(32);
    cipher.doFinal(c3_);

    var isDecrypt = _.arrayToHex(c3_) == c3;

    if (isDecrypt) {
        var decryptData = _.arrayToUtf8(data);
        return decryptData;
    } else {
        return '';
    }
}

/**
 * 签名
 */
function doSignature(msg, privateKey) {
    var _ref = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {},
        pointPool = _ref.pointPool,
        der = _ref.der,
        hash = _ref.hash,
        publicKey = _ref.publicKey;

    var hashHex = typeof msg === 'string' ? _.parseUtf8StringToHex(msg) : _.parseArrayBufferToHex(msg);

    if (hash) {
        // sm3杂凑
        publicKey = publicKey || getPublicKeyFromPrivateKey(privateKey);
        hashHex = doSm3Hash(hashHex, publicKey);
    }

    var dA = new BigInteger(privateKey, 16);
    var e = new BigInteger(hashHex, 16);

    // k
    var k = null;
    var r = null;
    var s = null;

    do {
        do {
            var point = void 0;
            if (pointPool && pointPool.length) {
                point = pointPool.pop();
            } else {
                point = getPoint();
            }
            k = point.k;

            // r = (e + x1) mod n
            r = e.add(point.x1).mod(n);
        } while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));

        // s = ((1 + dA)^-1 * (k - r * dA)) mod n
        s = dA.add(BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(dA))).mod(n);
    } while (s.equals(BigInteger.ZERO));

    if (der) {
        // asn1 der编码
        return encodeDer(r, s);
    }

    return _.leftPad(r.toString(16), 64) + _.leftPad(s.toString(16), 64);
}

/**
 * 验签
 */
function doVerifySignature(msg, signHex, publicKey) {
    var _ref2 = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : {},
        der = _ref2.der,
        hash = _ref2.hash;

    var hashHex = typeof msg === 'string' ? _.parseUtf8StringToHex(msg) : _.parseArrayBufferToHex(msg);

    if (hash) {
        // sm3杂凑
        hashHex = doSm3Hash(hashHex, publicKey);
    }

    var r = void 0,
        s = void 0;
    if (der) {
        var decodeDerObj = decodeDer(signHex);
        r = decodeDerObj.r;
        s = decodeDerObj.s;
    } else {
        r = new BigInteger(signHex.substring(0, 64), 16);
        s = new BigInteger(signHex.substring(64), 16);
    }

    var PA = ECPointFp.decodeFromHex(curve, publicKey);
    var e = new BigInteger(hashHex, 16);

    // t = (r + s) mod n
    var t = r.add(s).mod(n);

    if (t.equals(BigInteger.ZERO)) return false;

    // x1y1 = s * G + t * PA
    var x1y1 = G.multiply(s).add(PA.multiply(t));

    // R = (e + x1) mod n
    var R = e.add(x1y1.getX().toBigInteger()).mod(n);

    return r.equals(R);
}

/**
 * sm3杂凑算法
 */
function doSm3Hash(hashHex, publicKey) {
    var smDigest = new SM3Digest();

    var z = new SM3Digest().getZ(G, publicKey.substr(2, 128));
    var zValue = _.hexToArray(_.arrayToHex(z).toString());

    var p = hashHex;
    var pValue = _.hexToArray(p);

    var hashData = new Array(smDigest.getDigestSize());
    smDigest.blockUpdate(zValue, 0, zValue.length);
    smDigest.blockUpdate(pValue, 0, pValue.length);
    smDigest.doFinal(hashData, 0);

    return _.arrayToHex(hashData).toString();
}

/**
 * 计算公钥
 */
function getPublicKeyFromPrivateKey(privateKey) {
    var PA = G.multiply(new BigInteger(privateKey, 16));
    var x = _.leftPad(PA.getX().toBigInteger().toString(16), 64);
    var y = _.leftPad(PA.getY().toBigInteger().toString(16), 64);
    return '04' + x + y;
}

/**
 * 获取椭圆曲线点
 */
function getPoint() {
    var keypair = _.generateKeyPairHex();
    var PA = ECPointFp.decodeFromHex(curve, keypair.publicKey);

    keypair.k = new BigInteger(keypair.privateKey, 16);
    keypair.x1 = PA.getX().toBigInteger();

    return keypair;
};

export default {
    generateKeyPairHex: _.generateKeyPairHex,
    doEncrypt: doEncrypt,
    doDecrypt: doDecrypt,
    doSignature: doSignature,
    doVerifySignature: doVerifySignature,
    getPoint: getPoint
};