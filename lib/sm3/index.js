'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

exports['default'] = function (str) {
    var binary = str2binary(str);

    // 填充
    var len = binary.length;

    // k是满足len + 1 + k = 448mod512的最小的非负整数
    var k = len % 512;

    // 如果 448 <= (512 % len) < 512，需要多补充 (len % 448) 比特'0'以满足总比特长度为512的倍数
    k = k >= 448 ? 512 - k % 448 - 1 : 448 - k - 1;

    var m = (binary + '1' + leftPad('', k) + leftPad(len.toString(2), 64)).toString(); // k个0

    // 迭代压缩
    var n = (len + k + 65) / 512;

    var V = hex2binary('7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e');
    for (var i = 0; i <= n - 1; i++) {
        var B = m.substr(512 * i, 512);
        V = CF(V, B);
    }
    return binary2hex(V);
};

/**
 * 左补0到指定长度
 */
function leftPad(input, num) {
    if (input.length >= num) return input;

    return new Array(num - input.length + 1).join('0') + input;
}

/**
 * 二进制转化为十六进制
 */
function binary2hex(binary) {
    var binaryLength = 8;
    var hex = '';
    for (var i = 0; i < binary.length / binaryLength; i++) {
        hex += leftPad(parseInt(binary.substr(i * binaryLength, binaryLength), 2).toString(16), 2);
    }
    return hex;
}

/**
 * 十六进制转化为二进制
 */
function hex2binary(hex) {
    var hexLength = 2;
    var binary = '';
    for (var i = 0; i < hex.length / hexLength; i++) {
        binary += leftPad(parseInt(hex.substr(i * hexLength, hexLength), 16).toString(2), 8);
    }
    return binary;
}

/**
 * 普通字符串转化为二进制
 */
function str2binary(str) {
    var binary = '';
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;

    try {
        for (var _iterator = str[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
            var ch = _step.value;

            binary += leftPad(ch.codePointAt(0).toString(2), 8);
        }
    } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
    } finally {
        try {
            if (!_iteratorNormalCompletion && _iterator['return']) {
                _iterator['return']();
            }
        } finally {
            if (_didIteratorError) {
                throw _iteratorError;
            }
        }
    }

    return binary;
}

/**
 * 循环左移
 */
function rol(str, n) {
    return str.substring(n % str.length) + str.substr(0, n % str.length);
}

/**
 * 二进制运算
 */
function binaryCal(x, y, method) {
    var a = x || '';
    var b = y || '';
    var result = [];
    var prevResult = void 0;

    for (var i = a.length - 1; i >= 0; i--) {
        // 大端
        prevResult = method(a[i], b[i], prevResult);
        result[i] = prevResult[0];
    }
    return result.join('');
}

/**
 * 二进制异或运算
 */
function xor(x, y) {
    return binaryCal(x, y, function (a, b) {
        return [a === b ? '0' : '1'];
    });
}

/**
 * 二进制与运算
 */
function and(x, y) {
    return binaryCal(x, y, function (a, b) {
        return [a === '1' && b === '1' ? '1' : '0'];
    });
}

/**
 * 二进制或运算
 */
function or(x, y) {
    return binaryCal(x, y, function (a, b) {
        return [a === '1' || b === '1' ? '1' : '0'];
    }); // a === '0' && b === '0' ? '0' : '1'
}

/**
 * 二进制与运算
 */
function add(x, y) {
    var result = binaryCal(x, y, function (a, b, prevResult) {
        var carry = prevResult ? prevResult[1] : '0' || '0';

        // a,b不等时,carry不变，结果与carry相反
        // a,b相等时，结果等于原carry，新carry等于a
        if (a !== b) return [carry === '0' ? '1' : '0', carry];

        return [carry, a];
    });

    return result;
}

/**
 * 二进制非运算
 */
function not(x) {
    return binaryCal(x, undefined, function (a) {
        return [a === '1' ? '0' : '1'];
    });
}

function calMulti(method) {
    return function () {
        for (var _len = arguments.length, arr = Array(_len), _key = 0; _key < _len; _key++) {
            arr[_key] = arguments[_key];
        }

        return arr.reduce(function (prev, curr) {
            return method(prev, curr);
        });
    };
}

/**
 * 压缩函数中的置换函数 P1(X) = X xor (X <<< 9) xor (X <<< 17)
 */
function P0(X) {
    return calMulti(xor)(X, rol(X, 9), rol(X, 17));
}

/**
 * 消息扩展中的置换函数 P1(X) = X xor (X <<< 15) xor (X <<< 23)
 */
function P1(X) {
    return calMulti(xor)(X, rol(X, 15), rol(X, 23));
}

function FF(X, Y, Z, j) {
    return j >= 0 && j <= 15 ? calMulti(xor)(X, Y, Z) : calMulti(or)(and(X, Y), and(X, Z), and(Y, Z));
}

function GG(X, Y, Z, j) {
    return j >= 0 && j <= 15 ? calMulti(xor)(X, Y, Z) : or(and(X, Y), and(not(X), Z));
}

function T(j) {
    return j >= 0 && j <= 15 ? hex2binary('79cc4519') : hex2binary('7a879d8a');
}

/**
 * 压缩函数
 */
function CF(V, Bi) {
    // 消息扩展
    var wordLength = 32;
    var W = [];
    var M = []; // W'

    // 将消息分组B划分为16个字W0， W1，…… ，W15 （字为长度为32的比特串）
    for (var i = 0; i < 16; i++) {
        W.push(Bi.substr(i * wordLength, wordLength));
    }

    // W[j] <- P1(W[j−16] xor W[j−9] xor (W[j−3] <<< 15)) xor (W[j−13] <<< 7) xor W[j−6]
    for (var j = 16; j < 68; j++) {
        W.push(calMulti(xor)(P1(calMulti(xor)(W[j - 16], W[j - 9], rol(W[j - 3], 15))), rol(W[j - 13], 7), W[j - 6]));
    }

    // W′[j] = W[j] xor W[j+4]
    for (var _j = 0; _j < 64; _j++) {
        M.push(xor(W[_j], W[_j + 4]));
    }

    // 压缩
    var wordRegister = []; // 字寄存器
    for (var _j2 = 0; _j2 < 8; _j2++) {
        wordRegister.push(V.substr(_j2 * wordLength, wordLength));
    }

    var A = wordRegister[0];
    var B = wordRegister[1];
    var C = wordRegister[2];
    var D = wordRegister[3];
    var E = wordRegister[4];
    var F = wordRegister[5];
    var G = wordRegister[6];
    var H = wordRegister[7];

    // 中间变量
    var SS1 = void 0;
    var SS2 = void 0;
    var TT1 = void 0;
    var TT2 = void 0;
    for (var _j3 = 0; _j3 < 64; _j3++) {
        SS1 = rol(calMulti(add)(rol(A, 12), E, rol(T(_j3), _j3)), 7);
        SS2 = xor(SS1, rol(A, 12));

        TT1 = calMulti(add)(FF(A, B, C, _j3), D, SS2, M[_j3]);
        TT2 = calMulti(add)(GG(E, F, G, _j3), H, SS1, W[_j3]);

        D = C;
        C = rol(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rol(F, 19);
        F = E;
        E = P0(TT2);
    }

    return xor([A, B, C, D, E, F, G, H].join(''), V);
}

;
module.exports = exports['default'];