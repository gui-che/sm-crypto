'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _jsbn = require('jsbn');

var _asn = require('./asn1');

var _ec = require('./ec');

var _sm = require('./sm3');

var _sm2 = _interopRequireDefault(_sm);

var _sm3 = require('./sm2');

var _sm4 = _interopRequireDefault(_sm3);

var _utils = require('./utils');

var _utils2 = _interopRequireDefault(_utils);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }

var _$generateEcparam = _utils2['default'].generateEcparam(),
    G = _$generateEcparam.G,
    curve = _$generateEcparam.curve,
    n = _$generateEcparam.n;

var C1C2C3 = 0;

/**
 * 加密
 */
function doEncrypt(msg, publicKey) {
    var cipherMode = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 1;

    var cipher = new _sm4['default']();
    msg = _utils2['default'].hexToArray(_utils2['default'].parseUtf8StringToHex(msg));

    if (publicKey.length > 128) {
        publicKey = publicKey.substr(publicKey.length - 128);
    }
    var xHex = publicKey.substr(0, 64);
    var yHex = publicKey.substr(64);
    publicKey = cipher.createPoint(xHex, yHex);

    var c1 = cipher.initEncipher(publicKey);

    cipher.encryptBlock(msg);
    var c2 = _utils2['default'].arrayToHex(msg);

    var c3 = new Array(32);
    cipher.doFinal(c3);
    c3 = _utils2['default'].arrayToHex(c3);

    return cipherMode === C1C2C3 ? c1 + c2 + c3 : c1 + c3 + c2;
}

/**
 * 解密
 */
function doDecrypt(encryptData, privateKey) {
    var cipherMode = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 1;

    var cipher = new _sm4['default'](cipherMode);

    privateKey = new _jsbn.BigInteger(privateKey, 16);

    var c1X = encryptData.substr(0, 64);
    var c1Y = encryptData.substr(0 + c1X.length, 64);
    var c1Length = c1X.length + c1Y.length;

    var c3 = encryptData.substr(c1Length, 64);
    var c2 = encryptData.substr(c1Length + 64);

    if (cipherMode === C1C2C3) {
        c3 = encryptData.substr(encryptData.length - 64);
        c2 = encryptData.substr(c1Length, encryptData.length - c1Length - 64);
    }

    var data = _utils2['default'].hexToArray(c2);

    var c1 = cipher.createPoint(c1X, c1Y);
    cipher.initDecipher(privateKey, c1);
    cipher.decryptBlock(data);
    var c3_ = new Array(32);
    cipher.doFinal(c3_);

    var isDecrypt = _utils2['default'].arrayToHex(c3_) == c3;

    if (isDecrypt) {
        var decryptData = _utils2['default'].arrayToUtf8(data);
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

    var hashHex = typeof msg === 'string' ? _utils2['default'].parseUtf8StringToHex(msg) : _utils2['default'].parseArrayBufferToHex(msg);

    if (hash) {
        // sm3杂凑
        publicKey = publicKey || getPublicKeyFromPrivateKey(privateKey);
        hashHex = doSm3Hash(hashHex, publicKey);
    }

    var dA = new _jsbn.BigInteger(privateKey, 16);
    var e = new _jsbn.BigInteger(hashHex, 16);

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
        } while (r.equals(_jsbn.BigInteger.ZERO) || r.add(k).equals(n));

        // s = ((1 + dA)^-1 * (k - r * dA)) mod n
        s = dA.add(_jsbn.BigInteger.ONE).modInverse(n).multiply(k.subtract(r.multiply(dA))).mod(n);
    } while (s.equals(_jsbn.BigInteger.ZERO));

    if (der) {
        // asn1 der编码
        return (0, _asn.encodeDer)(r, s);
    }

    return _utils2['default'].leftPad(r.toString(16), 64) + _utils2['default'].leftPad(s.toString(16), 64);
}

/**
 * 验签
 */
function doVerifySignature(msg, signHex, publicKey) {
    var _ref2 = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : {},
        der = _ref2.der,
        hash = _ref2.hash;

    var hashHex = typeof msg === 'string' ? _utils2['default'].parseUtf8StringToHex(msg) : _utils2['default'].parseArrayBufferToHex(msg);

    if (hash) {
        // sm3杂凑
        hashHex = doSm3Hash(hashHex, publicKey);
    }

    var r = void 0,
        s = void 0;
    if (der) {
        var decodeDerObj = (0, _asn.decodeDer)(signHex);
        r = decodeDerObj.r;
        s = decodeDerObj.s;
    } else {
        r = new _jsbn.BigInteger(signHex.substring(0, 64), 16);
        s = new _jsbn.BigInteger(signHex.substring(64), 16);
    }

    var PA = _ec.ECPointFp.decodeFromHex(curve, publicKey);
    var e = new _jsbn.BigInteger(hashHex, 16);

    // t = (r + s) mod n
    var t = r.add(s).mod(n);

    if (t.equals(_jsbn.BigInteger.ZERO)) return false;

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
    var smDigest = new _sm2['default']();

    var z = new _sm2['default']().getZ(G, publicKey.substr(2, 128));
    var zValue = _utils2['default'].hexToArray(_utils2['default'].arrayToHex(z).toString());

    var p = hashHex;
    var pValue = _utils2['default'].hexToArray(p);

    var hashData = new Array(smDigest.getDigestSize());
    smDigest.blockUpdate(zValue, 0, zValue.length);
    smDigest.blockUpdate(pValue, 0, pValue.length);
    smDigest.doFinal(hashData, 0);

    return _utils2['default'].arrayToHex(hashData).toString();
}

/**
 * 计算公钥
 */
function getPublicKeyFromPrivateKey(privateKey) {
    var PA = G.multiply(new _jsbn.BigInteger(privateKey, 16));
    var x = _utils2['default'].leftPad(PA.getX().toBigInteger().toString(16), 64);
    var y = _utils2['default'].leftPad(PA.getY().toBigInteger().toString(16), 64);
    return '04' + x + y;
}

/**
 * 获取椭圆曲线点
 */
function getPoint() {
    var keypair = _utils2['default'].generateKeyPairHex();
    var PA = _ec.ECPointFp.decodeFromHex(curve, keypair.publicKey);

    keypair.k = new _jsbn.BigInteger(keypair.privateKey, 16);
    keypair.x1 = PA.getX().toBigInteger();

    return keypair;
};

exports['default'] = {
    generateKeyPairHex: _utils2['default'].generateKeyPairHex,
    doEncrypt: doEncrypt,
    doDecrypt: doDecrypt,
    doSignature: doSignature,
    doVerifySignature: doVerifySignature,
    getPoint: getPoint
};
module.exports = exports['default'];