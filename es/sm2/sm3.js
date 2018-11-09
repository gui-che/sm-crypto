import _classCallCheck from 'babel-runtime/helpers/classCallCheck';
import _createClass from 'babel-runtime/helpers/createClass';
import { BigInteger } from 'jsbn';
import _ from './utils';

var copyArray = function copyArray(sourceArray, sourceIndex, destinationArray, destinationIndex, length) {
    for (var i = 0; i < length; i++) {
        destinationArray[destinationIndex + i] = sourceArray[sourceIndex + i];
    }
};

var Int32 = {
    minValue: -parseInt('10000000000000000000000000000000', 2),
    maxValue: parseInt('1111111111111111111111111111111', 2),
    parse: function parse(n) {
        if (n < this.minValue) {
            var bigInteger = new Number(-n);
            var bigIntegerRadix = bigInteger.toString(2);
            var subBigIntegerRadix = bigIntegerRadix.substr(bigIntegerRadix.length - 31, 31);
            var reBigIntegerRadix = '';
            for (var i = 0; i < subBigIntegerRadix.length; i++) {
                var subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0';
            }
            var result = parseInt(reBigIntegerRadix, 2);
            return result + 1;
        } else if (n > this.maxValue) {
            var _bigInteger = Number(n);
            var _bigIntegerRadix = _bigInteger.toString(2);
            var _subBigIntegerRadix = _bigIntegerRadix.substr(_bigIntegerRadix.length - 31, 31);
            var _reBigIntegerRadix = '';
            for (var _i = 0; _i < _subBigIntegerRadix.length; _i++) {
                var _subBigIntegerRadixItem = _subBigIntegerRadix.substr(_i, 1);
                _reBigIntegerRadix += _subBigIntegerRadixItem == '0' ? '1' : '0';
            }
            var _result = parseInt(_reBigIntegerRadix, 2);
            return -(_result + 1);
        } else {
            return n;
        }
    },
    parseByte: function parseByte(n) {
        if (n < 0) {
            var bigInteger = new Number(-n);
            var bigIntegerRadix = bigInteger.toString(2);
            var subBigIntegerRadix = bigIntegerRadix.substr(bigIntegerRadix.length - 8, 8);
            var reBigIntegerRadix = '';
            for (var i = 0; i < subBigIntegerRadix.length; i++) {
                var subBigIntegerRadixItem = subBigIntegerRadix.substr(i, 1);
                reBigIntegerRadix += subBigIntegerRadixItem == '0' ? '1' : '0';
            }
            var result = parseInt(reBigIntegerRadix, 2);
            return result + 1;
        } else if (n > 255) {
            var _bigInteger2 = Number(n);
            var _bigIntegerRadix2 = _bigInteger2.toString(2);
            return parseInt(_bigIntegerRadix2.substr(_bigIntegerRadix2.length - 8, 8), 2);
        } else {
            return n;
        }
    }
};

var SM3Digest = function () {
    function SM3Digest() {
        _classCallCheck(this, SM3Digest);

        this.xBuf = new Array();
        this.xBufOff = 0;
        this.byteCount = 0;
        this.DIGEST_LENGTH = 32;
        this.v0 = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
        this.v0 = [0x7380166f, 0x4914b2b9, 0x172442d7, -628488704, -1452330820, 0x163138aa, -477237683, -1325724082];
        this.v = new Array(8);
        this.v_ = new Array(8);
        this.X0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        this.X = new Array(68);
        this.xOff = 0;
        this.T_00_15 = 0x79cc4519;
        this.T_16_63 = 0x7a879d8a;
        if (arguments.length > 0) {
            this.initDigest(arguments[0]);
        } else {
            this.init();
        }
    }

    _createClass(SM3Digest, [{
        key: 'init',
        value: function init() {
            this.xBuf = new Array(4);
            this.reset();
        }
    }, {
        key: 'initDigest',
        value: function initDigest(t) {
            this.xBuf = [].concat(t.xBuf);
            this.xBufOff = t.xBufOff;
            this.byteCount = t.byteCount;
            copyArray(t.X, 0, this.X, 0, t.X.length);
            this.xOff = t.xOff;
            copyArray(t.v, 0, this.v, 0, t.v.length);
        }
    }, {
        key: 'getDigestSize',
        value: function getDigestSize() {
            return this.DIGEST_LENGTH;
        }
    }, {
        key: 'reset',
        value: function reset() {
            this.byteCount = 0;
            this.xBufOff = 0;
            for (var elem in this.xBuf) {
                this.xBuf[elem] = null;
            }copyArray(this.v0, 0, this.v, 0, this.v0.length);
            this.xOff = 0;
            copyArray(this.X0, 0, this.X, 0, this.X0.length);
        }
    }, {
        key: 'processBlock',
        value: function processBlock() {
            var i = void 0;
            var ww = this.X;
            var ww_ = new Array(64);
            for (i = 16; i < 68; i++) {
                ww[i] = this.p1(ww[i - 16] ^ ww[i - 9] ^ this.rotate(ww[i - 3], 15)) ^ this.rotate(ww[i - 13], 7) ^ ww[i - 6];
            }
            for (i = 0; i < 64; i++) {
                ww_[i] = ww[i] ^ ww[i + 4];
            }
            var vv = this.v;
            var vv_ = this.v_;
            copyArray(vv, 0, vv_, 0, this.v0.length);
            var SS1 = void 0,
                SS2 = void 0,
                TT1 = void 0,
                TT2 = void 0,
                aaa = void 0;
            for (i = 0; i < 16; i++) {
                aaa = this.rotate(vv_[0], 12);
                SS1 = Int32.parse(Int32.parse(aaa + vv_[4]) + this.rotate(this.T_00_15, i));
                SS1 = this.rotate(SS1, 7);
                SS2 = SS1 ^ aaa;
                TT1 = Int32.parse(Int32.parse(this.ff_00_15(vv_[0], vv_[1], vv_[2]) + vv_[3]) + SS2) + ww_[i];
                TT2 = Int32.parse(Int32.parse(this.gg_00_15(vv_[4], vv_[5], vv_[6]) + vv_[7]) + SS1) + ww[i];
                vv_[3] = vv_[2];
                vv_[2] = this.rotate(vv_[1], 9);
                vv_[1] = vv_[0];
                vv_[0] = TT1;
                vv_[7] = vv_[6];
                vv_[6] = this.rotate(vv_[5], 19);
                vv_[5] = vv_[4];
                vv_[4] = this.p0(TT2);
            }
            for (i = 16; i < 64; i++) {
                aaa = this.rotate(vv_[0], 12);
                SS1 = Int32.parse(Int32.parse(aaa + vv_[4]) + this.rotate(this.T_16_63, i));
                SS1 = this.rotate(SS1, 7);
                SS2 = SS1 ^ aaa;
                TT1 = Int32.parse(Int32.parse(this.ff_16_63(vv_[0], vv_[1], vv_[2]) + vv_[3]) + SS2) + ww_[i];
                TT2 = Int32.parse(Int32.parse(this.gg_16_63(vv_[4], vv_[5], vv_[6]) + vv_[7]) + SS1) + ww[i];
                vv_[3] = vv_[2];
                vv_[2] = this.rotate(vv_[1], 9);
                vv_[1] = vv_[0];
                vv_[0] = TT1;
                vv_[7] = vv_[6];
                vv_[6] = this.rotate(vv_[5], 19);
                vv_[5] = vv_[4];
                vv_[4] = this.p0(TT2);
            }
            for (i = 0; i < 8; i++) {
                vv[i] ^= Int32.parse(vv_[i]);
            }
            this.xOff = 0;
            copyArray(this.X0, 0, this.X, 0, this.X0.length);
        }
    }, {
        key: 'processWord',
        value: function processWord(in_Renamed, inOff) {
            var n = in_Renamed[inOff] << 24;
            n |= (in_Renamed[++inOff] & 0xff) << 16;
            n |= (in_Renamed[++inOff] & 0xff) << 8;
            n |= in_Renamed[++inOff] & 0xff;
            this.X[this.xOff] = n;
            if (++this.xOff == 16) {
                this.processBlock();
            }
        }
    }, {
        key: 'processLength',
        value: function processLength(bitLength) {
            if (this.xOff > 14) {
                this.processBlock();
            }
            this.X[14] = this.urShiftLong(bitLength, 32);
            this.X[15] = bitLength & 0xffffffff;
        }
    }, {
        key: 'intToBigEndian',
        value: function intToBigEndian(n, bs, off) {
            bs[off] = Int32.parseByte(this.urShift(n, 24));
            bs[++off] = Int32.parseByte(this.urShift(n, 16));
            bs[++off] = Int32.parseByte(this.urShift(n, 8));
            bs[++off] = Int32.parseByte(n);
        }
    }, {
        key: 'doFinal',
        value: function doFinal(out_Renamed, outOff) {
            this.finish();
            for (var i = 0; i < 8; i++) {
                this.intToBigEndian(this.v[i], out_Renamed, outOff + i * 4);
            }
            this.reset();
            return this.DIGEST_LENGTH;
        }
    }, {
        key: 'update',
        value: function update(input) {
            this.xBuf[this.xBufOff++] = input;
            if (this.xBufOff == this.xBuf.length) {
                this.processWord(this.xBuf, 0);
                this.xBufOff = 0;
            }
            this.byteCount++;
        }
    }, {
        key: 'blockUpdate',
        value: function blockUpdate(input, inOff, length) {
            while (this.xBufOff != 0 && length > 0) {
                this.update(input[inOff]);
                inOff++;
                length--;
            }
            while (length > this.xBuf.length) {
                this.processWord(input, inOff);
                inOff += this.xBuf.length;
                length -= this.xBuf.length;
                this.byteCount += this.xBuf.length;
            }
            while (length > 0) {
                this.update(input[inOff]);
                inOff++;
                length--;
            }
        }
    }, {
        key: 'finish',
        value: function finish() {
            var bitLength = this.byteCount << 3;
            this.update(128);
            while (this.xBufOff != 0) {
                this.update(0);
            }this.processLength(bitLength);
            this.processBlock();
        }
    }, {
        key: 'rotate',
        value: function rotate(x, n) {
            return x << n | this.urShift(x, 32 - n);
        }
    }, {
        key: 'p0',
        value: function p0(X) {
            return X ^ this.rotate(X, 9) ^ this.rotate(X, 17);
        }
    }, {
        key: 'p1',
        value: function p1(X) {
            return X ^ this.rotate(X, 15) ^ this.rotate(X, 23);
        }
    }, {
        key: 'ff_00_15',
        value: function ff_00_15(X, Y, Z) {
            return X ^ Y ^ Z;
        }
    }, {
        key: 'ff_16_63',
        value: function ff_16_63(X, Y, Z) {
            return X & Y | X & Z | Y & Z;
        }
    }, {
        key: 'gg_00_15',
        value: function gg_00_15(X, Y, Z) {
            return X ^ Y ^ Z;
        }
    }, {
        key: 'gg_16_63',
        value: function gg_16_63(X, Y, Z) {
            return X & Y | ~X & Z;
        }
    }, {
        key: 'urShift',
        value: function urShift(number, bits) {
            if (number > Int32.maxValue || number < Int32.minValue) {
                number = Int32.parse(number);
            }
            if (number >= 0) {
                return number >> bits;
            } else {
                return (number >> bits) + (2 << ~bits);
            }
        }
    }, {
        key: 'urShiftLong',
        value: function urShiftLong(number, bits) {
            var returnV = void 0;
            var big = new BigInteger();
            big.fromInt(number);
            if (big.signum() >= 0) {
                returnV = big.shiftRight(bits).intValue();
            } else {
                var bigAdd = new BigInteger();
                bigAdd.fromInt(2);
                var shiftLeftBits = ~bits;
                var shiftLeftNumber = '';
                if (shiftLeftBits < 0) {
                    var shiftRightBits = 64 + shiftLeftBits;
                    for (var i = 0; i < shiftRightBits; i++) {
                        shiftLeftNumber += '0';
                    }
                    var shiftLeftNumberBigAdd = new BigInteger();
                    shiftLeftNumberBigAdd.fromInt(number >> bits);
                    var shiftLeftNumberBig = new BigInteger("10" + shiftLeftNumber, 2);
                    shiftLeftNumber = shiftLeftNumberBig.toRadix(10);
                    var r = shiftLeftNumberBig.add(shiftLeftNumberBigAdd);
                    returnV = r.toRadix(10);
                } else {
                    shiftLeftNumber = bigAdd.shiftLeft(~bits).intValue();
                    returnV = (number >> bits) + shiftLeftNumber;
                }
            }
            return returnV;
        }
    }, {
        key: 'getZ',
        value: function getZ(g, publicKey) {
            var userId = _.parseUtf8StringToHex('1234567812345678');
            var len = userId.length * 4;
            this.update(len >> 8 & 0x00ff);
            this.update(len & 0x00ff);
            var userIdWords = _.hexToArray(userId);
            this.blockUpdate(userIdWords, 0, userIdWords.length);
            var aWords = _.hexToArray(g.curve.a.toBigInteger().toRadix(16));
            var bWords = _.hexToArray(g.curve.b.toBigInteger().toRadix(16));
            var gxWords = _.hexToArray(g.getX().toBigInteger().toRadix(16));
            var gyWords = _.hexToArray(g.getY().toBigInteger().toRadix(16));
            var pxWords = _.hexToArray(publicKey.substr(0, 64));
            var pyWords = _.hexToArray(publicKey.substr(64, 64));
            this.blockUpdate(aWords, 0, aWords.length);
            this.blockUpdate(bWords, 0, bWords.length);
            this.blockUpdate(gxWords, 0, gxWords.length);
            this.blockUpdate(gyWords, 0, gyWords.length);
            this.blockUpdate(pxWords, 0, pxWords.length);
            this.blockUpdate(pyWords, 0, pyWords.length);
            var md = new Array(this.getDigestSize());
            this.doFinal(md, 0);
            return md;
        }
    }]);

    return SM3Digest;
}();

export default SM3Digest;