import _classCallCheck from 'babel-runtime/helpers/classCallCheck';
import _createClass from 'babel-runtime/helpers/createClass';
import { BigInteger } from 'jsbn';
import { ECPointFp, ECFieldElementFp, ECCurveFp } from './ec';

import SM3Digest from './sm3';
import _ from './utils';

var SM2Cipher = function () {
    function SM2Cipher() {
        _classCallCheck(this, SM2Cipher);

        this.ct = 1;
        this.p2 = null;
        this.sm3keybase = null;
        this.sm3c3 = null;
        this.key = new Array(32);
        this.keyOff = 0;
    }

    _createClass(SM2Cipher, [{
        key: 'reset',
        value: function reset() {
            this.sm3keybase = new SM3Digest();
            this.sm3c3 = new SM3Digest();
            var xWords = _.hexToArray(this.p2.getX().toBigInteger().toRadix(16));
            var yWords = _.hexToArray(this.p2.getY().toBigInteger().toRadix(16));
            this.sm3keybase.blockUpdate(xWords, 0, xWords.length);
            this.sm3c3.blockUpdate(xWords, 0, xWords.length);
            this.sm3keybase.blockUpdate(yWords, 0, yWords.length);
            this.ct = 1;
            this.nextKey();
        }
    }, {
        key: 'nextKey',
        value: function nextKey() {
            var sm3keycur = new SM3Digest(this.sm3keybase);
            sm3keycur.update(this.ct >> 24 & 0x00ff);
            sm3keycur.update(this.ct >> 16 & 0x00ff);
            sm3keycur.update(this.ct >> 8 & 0x00ff);
            sm3keycur.update(this.ct & 0x00ff);
            sm3keycur.doFinal(this.key, 0);
            this.keyOff = 0;
            this.ct++;
        }
    }, {
        key: 'initEncipher',
        value: function initEncipher(userKey) {
            var keypair = _.generateKeyPairHex();
            var k = new BigInteger(keypair.privateKey, 16);
            var publicKey = keypair.publicKey;

            this.p2 = userKey.multiply(k);
            this.reset();

            if (publicKey.length > 128) {
                publicKey = publicKey.substr(publicKey.length - 128);
            }

            return publicKey;
        }
    }, {
        key: 'encryptBlock',
        value: function encryptBlock(data) {
            this.sm3c3.blockUpdate(data, 0, data.length);
            for (var i = 0; i < data.length; i++) {
                if (this.keyOff === this.key.length) {
                    this.nextKey();
                }
                data[i] ^= this.key[this.keyOff++];
            }
        }
    }, {
        key: 'initDecipher',
        value: function initDecipher(userD, c1) {
            this.p2 = c1.multiply(userD);
            this.reset();
        }
    }, {
        key: 'decryptBlock',
        value: function decryptBlock(data) {
            for (var i = 0; i < data.length; i++) {
                if (this.keyOff === this.key.length) {
                    this.nextKey();
                }
                data[i] ^= this.key[this.keyOff++];
            }
            this.sm3c3.blockUpdate(data, 0, data.length);
        }
    }, {
        key: 'doFinal',
        value: function doFinal(c3) {
            var yWords = _.hexToArray(this.p2.getY().toBigInteger().toRadix(16));
            this.sm3c3.blockUpdate(yWords, 0, yWords.length);
            this.sm3c3.doFinal(c3, 0);
            this.reset();
        }
    }, {
        key: 'createPoint',
        value: function createPoint(x, y) {
            var publicKey = '04' + x + y;
            var point = ECPointFp.decodeFromHex(_.generateEcparam().curve, publicKey);
            return point;
        }
    }]);

    return SM2Cipher;
}();

export default SM2Cipher;