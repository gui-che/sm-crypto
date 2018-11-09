import _possibleConstructorReturn from 'babel-runtime/helpers/possibleConstructorReturn';
import _inherits from 'babel-runtime/helpers/inherits';
import _classCallCheck from 'babel-runtime/helpers/classCallCheck';
import _createClass from 'babel-runtime/helpers/createClass';
import { BigInteger } from 'jsbn';

function bigIntToMinTwosComplementsHex(bigIntegerValue) {
    var h = bigIntegerValue.toString(16);
    if (h.substr(0, 1) !== '-') {
        if (h.length % 2 === 1) {
            h = '0' + h;
        } else if (!h.match(/^[0-7]/)) {
            h = '00' + h;
        }
    } else {
        var hPos = h.substr(1);
        var xorLen = hPos.length;
        if (xorLen % 2 === 1) {
            xorLen += 1;
        } else if (!h.match(/^[0-7]/)) {
            xorLen += 2;
        }
        var hMask = '';
        for (var i = 0; i < xorLen; i++) {
            hMask += 'f';
        }
        var biMask = new BigInteger(hMask, 16);
        var biNeg = biMask.xor(bigIntegerValue).add(BigInteger.ONE);
        h = biNeg.toString(16).replace(/^-/, '');
    }
    return h;
}

/**
 * base class for ASN.1 DER encoder object
 */

var ASN1Object = function () {
    function ASN1Object() {
        _classCallCheck(this, ASN1Object);

        this.isModified = true;
        this.hTLV = null;
        this.hT = '00';
        this.hL = '00';
        this.hV = '';
    }

    /**
     * get hexadecimal ASN.1 TLV length(L) bytes from TLV value(V)
     */


    _createClass(ASN1Object, [{
        key: 'getLengthHexFromValue',
        value: function getLengthHexFromValue() {
            var n = this.hV.length / 2;
            var hN = n.toString(16);
            if (hN.length % 2 == 1) {
                hN = '0' + hN;
            }
            if (n < 128) {
                return hN;
            } else {
                var hNlen = hN.length / 2;
                var head = 128 + hNlen;
                return head.toString(16) + hN;
            }
        }

        /**
         * get hexadecimal string of ASN.1 TLV bytes
         */

    }, {
        key: 'getEncodedHex',
        value: function getEncodedHex() {
            if (this.hTLV == null || this.isModified) {
                this.hV = this.getFreshValueHex();
                this.hL = this.getLengthHexFromValue();
                this.hTLV = this.hT + this.hL + this.hV;
                this.isModified = false;
            }
            return this.hTLV;
        }
    }, {
        key: 'getFreshValueHex',
        value: function getFreshValueHex() {
            return '';
        }
    }]);

    return ASN1Object;
}();

;

/**
 * class for ASN.1 DER Integer
 */

var DERInteger = function (_ASN1Object) {
    _inherits(DERInteger, _ASN1Object);

    function DERInteger(options) {
        _classCallCheck(this, DERInteger);

        var _this = _possibleConstructorReturn(this, (DERInteger.__proto__ || Object.getPrototypeOf(DERInteger)).call(this));

        _this.hT = '02';
        if (options && options.bigint) {
            _this.hTLV = null;
            _this.isModified = true;
            _this.hV = bigIntToMinTwosComplementsHex(options.bigint);
        }
        return _this;
    }

    _createClass(DERInteger, [{
        key: 'getFreshValueHex',
        value: function getFreshValueHex() {
            return this.hV;
        }
    }]);

    return DERInteger;
}(ASN1Object);

/**
 * class for ASN.1 DER Sequence
 */


var DERSequence = function (_ASN1Object2) {
    _inherits(DERSequence, _ASN1Object2);

    function DERSequence(options) {
        _classCallCheck(this, DERSequence);

        var _this2 = _possibleConstructorReturn(this, (DERSequence.__proto__ || Object.getPrototypeOf(DERSequence)).call(this));

        _this2.hT = '30';
        _this2.asn1Array = [];
        if (options && options.array) {
            _this2.asn1Array = options.array;
        }
        return _this2;
    }

    _createClass(DERSequence, [{
        key: 'getFreshValueHex',
        value: function getFreshValueHex() {
            var h = '';
            for (var i = 0; i < this.asn1Array.length; i++) {
                var asn1Obj = this.asn1Array[i];
                h += asn1Obj.getEncodedHex();
            }
            this.hV = h;
            return this.hV;
        }
    }]);

    return DERSequence;
}(ASN1Object);

/**
 * get byte length for ASN.1 L(length) bytes
 */


function getByteLengthOfL(s, pos) {
    if (s.substring(pos + 2, pos + 3) !== '8') return 1;
    var i = parseInt(s.substring(pos + 3, pos + 4));
    if (i === 0) return -1; // length octet '80' indefinite length
    if (0 < i && i < 10) return i + 1; // including '8?' octet;
    return -2; // malformed format
}

/**
 * get hexadecimal string for ASN.1 L(length) bytes
 */
function getHexOfL(s, pos) {
    var len = getByteLengthOfL(s, pos);
    if (len < 1) return '';
    return s.substring(pos + 2, pos + 2 + len * 2);
}

/**
 * get integer value of ASN.1 length for ASN.1 data
 */
function getIntOfL(s, pos) {
    var hLength = getHexOfL(s, pos);
    if (hLength === '') return -1;
    var bi = void 0;
    if (parseInt(hLength.substring(0, 1)) < 8) {
        bi = new BigInteger(hLength, 16);
    } else {
        bi = new BigInteger(hLength.substring(2), 16);
    }
    return bi.intValue();
}

/**
 * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
 */
function getStartPosOfV(s, pos) {
    var lLen = getByteLengthOfL(s, pos);
    if (lLen < 0) return l_len;
    return pos + (lLen + 1) * 2;
}

/**
 * get hexadecimal string of ASN.1 V(value)
 */
function getHexOfV(s, pos) {
    var pos1 = getStartPosOfV(s, pos);
    var len = getIntOfL(s, pos);
    return s.substring(pos1, pos1 + len * 2);
}

/**
 * get next sibling starting index for ASN.1 object string
 */
function getPosOfNextSibling(s, pos) {
    var pos1 = getStartPosOfV(s, pos);
    var len = getIntOfL(s, pos);
    return pos1 + len * 2;
}

/**
 * get array of indexes of child ASN.1 objects
 */
function getPosArrayOfChildren(h, pos) {
    var a = [];
    var p0 = getStartPosOfV(h, pos);
    a.push(p0);

    var len = getIntOfL(h, pos);
    var p = p0;
    var k = 0;
    while (1) {
        var pNext = getPosOfNextSibling(h, p);
        if (pNext === null || pNext - p0 >= len * 2) break;
        if (k >= 200) break;

        a.push(pNext);
        p = pNext;

        k++;
    }

    return a;
}

/**
 * ASN.1 DER编码
 */
export function encodeDer(r, s) {
    var derR = new DERInteger({ bigint: r });
    var derS = new DERInteger({ bigint: s });
    var derSeq = new DERSequence({ array: [derR, derS] });

    return derSeq.getEncodedHex();
}

/**
 * 解析 ASN.1 DER
 */
export function decodeDer(input) {
    // 1. Items of ASN.1 Sequence Check
    var a = getPosArrayOfChildren(input, 0);

    // 2. Integer check
    var iTLV1 = a[0];
    var iTLV2 = a[1];

    // 3. getting value
    var hR = getHexOfV(input, iTLV1);
    var hS = getHexOfV(input, iTLV2);

    var r = new BigInteger(hR, 16);
    var s = new BigInteger(hS, 16);

    return { r: r, s: s };
}