'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.generateEcparam = generateEcparam;
exports.generateKeyPairHex = generateKeyPairHex;
exports.parseUtf8StringToHex = parseUtf8StringToHex;
exports.parseArrayBufferToHex = parseArrayBufferToHex;
exports.leftPad = leftPad;
exports.arrayToHex = arrayToHex;
exports.arrayToUtf8 = arrayToUtf8;
exports.hexToArray = hexToArray;

var _jsbn = require('jsbn');

var _ec = require('./ec');

var rng = new _jsbn.SecureRandom();

var _generateEcparam = generateEcparam(),
    G = _generateEcparam.G,
    n = _generateEcparam.n;

/**
* 生成ecparam
*/


function generateEcparam() {
    var p = new _jsbn.BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
    var a = new _jsbn.BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
    var b = new _jsbn.BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
    var n = new _jsbn.BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);
    var gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
    var gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
    var curve = new _ec.ECCurveFp(p, a, b);
    var G = curve.decodePointHex('04' + gxHex + gyHex);

    return { curve: curve, G: G, n: n };
}

/**
 * 生成密钥对
 */
function generateKeyPairHex() {
    var d = new _jsbn.BigInteger(n.bitLength(), rng).mod(n.subtract(_jsbn.BigInteger.ONE)).add(_jsbn.BigInteger.ONE); // 随机数
    var privateKey = leftPad(d.toString(16), 64);

    var P = G.multiply(d);
    var Px = leftPad(P.getX().toBigInteger().toString(16), 64);
    var Py = leftPad(P.getY().toBigInteger().toString(16), 64);
    var publicKey = '04' + Px + Py;

    return {
        privateKey: privateKey,
        publicKey: publicKey
    };
}

/**
 * 解析utf8字符串到16进制
 */
function parseUtf8StringToHex(input) {
    input = unescape(encodeURIComponent(input));

    var length = input.length;

    // 转换到字数组
    var words = [];
    for (var i = 0; i < length; i++) {
        words[i >>> 2] |= (input.charCodeAt(i) & 0xff) << 24 - i % 4 * 8;
    }

    // 转换到16进制
    var hexChars = [];
    for (var _i = 0; _i < length; _i++) {
        var bite = words[_i >>> 2] >>> 24 - _i % 4 * 8 & 0xff;
        hexChars.push((bite >>> 4).toString(16));
        hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
}

/**
 * 解析arrayBuffer到16进制字符串
 */
function parseArrayBufferToHex(input) {
    return Array.prototype.map.call(new Uint8Array(input), function (x) {
        return ('00' + x.toString(16)).slice(-2);
    }).join('');
}

/**
 * 补全16进制字符串
 */
function leftPad(input, num) {
    if (input.length >= num) return input;

    return new Array(num - input.length + 1).join('0') + input;
}

/**
 * 转成16进制串
 */
function arrayToHex(arr) {
    var words = [];
    var j = 0;
    for (var i = 0; i < arr.length * 2; i += 2) {
        words[i >>> 3] |= parseInt(arr[j]) << 24 - i % 8 * 4;
        j++;
    }

    // 转换到16进制
    var hexChars = [];
    for (var _i2 = 0; _i2 < arr.length; _i2++) {
        var bite = words[_i2 >>> 2] >>> 24 - _i2 % 4 * 8 & 0xff;
        hexChars.push((bite >>> 4).toString(16));
        hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
}

/**
 * 转成utf8串
 */
function arrayToUtf8(arr) {
    var words = [];
    var j = 0;
    for (var i = 0; i < arr.length * 2; i += 2) {
        words[i >>> 3] |= parseInt(arr[j]) << 24 - i % 8 * 4;
        j++;
    }

    try {
        var latin1Chars = [];

        for (var _i3 = 0; _i3 < arr.length; _i3++) {
            var bite = words[_i3 >>> 2] >>> 24 - _i3 % 4 * 8 & 0xff;
            latin1Chars.push(String.fromCharCode(bite));
        }

        return decodeURIComponent(escape(latin1Chars.join('')));
    } catch (e) {
        throw new Error('Malformed UTF-8 data');
    }
}

/**
 * 转成ascii码数组
 */
function hexToArray(hexStr) {
    var words = [];
    var hexStrLength = hexStr.length;

    if (hexStrLength % 2 !== 0) {
        hexStr = leftPad(hexStr, hexStrLength + 1);
    }

    hexStrLength = hexStr.length;

    for (var i = 0; i < hexStrLength; i += 2) {
        words.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return words;
}

exports['default'] = {
    generateEcparam: generateEcparam,
    generateKeyPairHex: generateKeyPairHex,
    parseUtf8StringToHex: parseUtf8StringToHex,
    parseArrayBufferToHex: parseArrayBufferToHex,
    leftPad: leftPad,
    arrayToHex: arrayToHex,
    arrayToUtf8: arrayToUtf8,
    hexToArray: hexToArray
};