'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _classCallCheck2 = require('babel-runtime/helpers/classCallCheck');

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = require('babel-runtime/helpers/createClass');

var _createClass3 = _interopRequireDefault(_createClass2);

var _jsbn = require('jsbn');

var _ec = require('./ec');

var _sm = require('./sm3');

var _sm2 = _interopRequireDefault(_sm);

var _utils = require('./utils');

var _utils2 = _interopRequireDefault(_utils);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }

var SM2Cipher = function () {
    function SM2Cipher() {
        (0, _classCallCheck3['default'])(this, SM2Cipher);

        this.ct = 1;
        this.p2 = null;
        this.sm3keybase = null;
        this.sm3c3 = null;
        this.key = new Array(32);
        this.keyOff = 0;
    }

    (0, _createClass3['default'])(SM2Cipher, [{
        key: 'reset',
        value: function reset() {
            this.sm3keybase = new _sm2['default']();
            this.sm3c3 = new _sm2['default']();
            var xWords = _utils2['default'].hexToArray(this.p2.getX().toBigInteger().toRadix(16));
            var yWords = _utils2['default'].hexToArray(this.p2.getY().toBigInteger().toRadix(16));
            this.sm3keybase.blockUpdate(xWords, 0, xWords.length);
            this.sm3c3.blockUpdate(xWords, 0, xWords.length);
            this.sm3keybase.blockUpdate(yWords, 0, yWords.length);
            this.ct = 1;
            this.nextKey();
        }
    }, {
        key: 'nextKey',
        value: function nextKey() {
            var sm3keycur = new _sm2['default'](this.sm3keybase);
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
            var keypair = _utils2['default'].generateKeyPairHex();
            var k = new _jsbn.BigInteger(keypair.privateKey, 16);
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
            var yWords = _utils2['default'].hexToArray(this.p2.getY().toBigInteger().toRadix(16));
            this.sm3c3.blockUpdate(yWords, 0, yWords.length);
            this.sm3c3.doFinal(c3, 0);
            this.reset();
        }
    }, {
        key: 'createPoint',
        value: function createPoint(x, y) {
            var publicKey = '04' + x + y;
            var point = _ec.ECPointFp.decodeFromHex(_utils2['default'].generateEcparam().curve, publicKey);
            return point;
        }
    }]);
    return SM2Cipher;
}();

exports['default'] = SM2Cipher;
module.exports = exports['default'];