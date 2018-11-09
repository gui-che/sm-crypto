import _classCallCheck from 'babel-runtime/helpers/classCallCheck';
import _createClass from 'babel-runtime/helpers/createClass';
import { BigInteger } from 'jsbn';

/**
 * thanks for Tom Wu : http://www-cs-students.stanford.edu/~tjw/jsbn/
 *
 * Basic Javascript Elliptic Curve implementation
 * Ported loosely from BouncyCastle's Java EC code
 * Only Fp curves implemented for now
 */

var THREE = new BigInteger('3');

export var ECFieldElementFp = function () {
    function ECFieldElementFp(q, x) {
        _classCallCheck(this, ECFieldElementFp);

        this.x = x;
        this.q = q;
        // TODO if(x.compareTo(q) >= 0) error
    }

    _createClass(ECFieldElementFp, [{
        key: 'equals',
        value: function equals(other) {
            if (other === this) return true;
            return this.q.equals(other.q) && this.x.equals(other.x);
        }
    }, {
        key: 'toBigInteger',
        value: function toBigInteger() {
            return this.x;
        }
    }, {
        key: 'negate',
        value: function negate() {
            return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
        }
    }, {
        key: 'add',
        value: function add(b) {
            return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
        }
    }, {
        key: 'subtract',
        value: function subtract(b) {
            return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
        }
    }, {
        key: 'multiply',
        value: function multiply(b) {
            return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
        }
    }, {
        key: 'square',
        value: function square() {
            return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
        }
    }, {
        key: 'divide',
        value: function divide(b) {
            return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
        }
    }]);

    return ECFieldElementFp;
}();

export var ECPointFp = function () {
    function ECPointFp(curve, x, y, z) {
        _classCallCheck(this, ECPointFp);

        this.curve = curve;
        this.x = x;
        this.y = y;
        // Projective coordinates: either zinv == null or z * zinv == 1
        // z and zinv are just BigIntegers, not fieldElements
        this.z = z == null ? BigInteger.ONE : z;
        this.zinv = null;
        //TODO: compression flag
    }

    _createClass(ECPointFp, [{
        key: 'getX',
        value: function getX() {
            if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

            return this.curve.fromBigInteger(this.x.toBigInteger().multiply(this.zinv).mod(this.curve.q));
        }
    }, {
        key: 'getY',
        value: function getY() {
            if (this.zinv === null) this.zinv = this.z.modInverse(this.curve.q);

            return this.curve.fromBigInteger(this.y.toBigInteger().multiply(this.zinv).mod(this.curve.q));
        }
    }, {
        key: 'equals',
        value: function equals(other) {
            if (other === this) return true;
            if (this.isInfinity()) return other.isInfinity();
            if (other.isInfinity()) return this.isInfinity();

            // u = Y2 * Z1 - Y1 * Z2
            var u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
            if (!u.equals(BigInteger.ZERO)) return false;

            // v = X2 * Z1 - X1 * Z2
            var v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
            return v.equals(BigInteger.ZERO);
        }
    }, {
        key: 'isInfinity',
        value: function isInfinity() {
            if (this.x === null && this.y === null) return true;
            return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
        }
    }, {
        key: 'negate',
        value: function negate() {
            return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
        }
    }, {
        key: 'add',
        value: function add(b) {
            if (this.isInfinity()) return b;
            if (b.isInfinity()) return this;

            // u = Y2 * Z1 - Y1 * Z2
            var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
            // v = X2 * Z1 - X1 * Z2
            var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);

            if (BigInteger.ZERO.equals(v)) {
                if (BigInteger.ZERO.equals(u)) {
                    return this.twice(); // this == b, so double
                }
                return this.curve.getInfinity(); // this = -b, so infinity
            }

            var x1 = this.x.toBigInteger();
            var y1 = this.y.toBigInteger();

            var v2 = v.square();
            var v3 = v2.multiply(v);
            var x1v2 = x1.multiply(v2);
            var zu2 = u.square().multiply(this.z);

            // x3 = v * (z2 * (z1 * u^2 - 2 * x1 * v^2) - v^3)
            var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
            // y3 = z2 * (3 * x1 * u * v^2 - y1 * v^3 - z1 * u^3) + u * v^3
            var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
            // z3 = v^3 * z1 * z2
            var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);

            return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
        }
    }, {
        key: 'twice',
        value: function twice() {
            if (this.isInfinity()) return this;
            if (this.y.toBigInteger().signum() == 0) return this.curve.getInfinity();

            var x1 = this.x.toBigInteger();
            var y1 = this.y.toBigInteger();

            var y1z1 = y1.multiply(this.z);
            var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
            var a = this.curve.a.toBigInteger();

            // w = 3 * x1^2 + a * z1^2
            var w = x1.square().multiply(THREE);
            if (!BigInteger.ZERO.equals(a)) {
                w = w.add(this.z.square().multiply(a));
            }
            w = w.mod(this.curve.q);
            // x3 = 2 * y1 * z1 * (w^2 - 8 * x1 * y1^2 * z1)
            var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
            // y3 = 4 * y1^2 * z1 * (3 * w * x1 - 2 * y1^2 * z1) - w^3
            var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
            // z3 = 8 * (y1 * z1)^3
            var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);

            return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
        }
    }, {
        key: 'multiply',
        value: function multiply(k) {
            // Simple NAF (Non-Adjacent Form) multiplication algorithm
            if (this.isInfinity()) return this;
            if (k.signum() == 0) return this.curve.getInfinity();

            var e = k;
            var h = e.multiply(new BigInteger('3'));

            var neg = this.negate();
            var R = this;

            for (var i = h.bitLength() - 2; i > 0; --i) {
                R = R.twice();

                var hBit = h.testBit(i);
                var eBit = e.testBit(i);

                if (hBit != eBit) {
                    R = R.add(hBit ? this : neg);
                }
            }

            return R;
        }
    }, {
        key: 'multiplyTwo',
        value: function multiplyTwo(j, x, k) {
            // Compute this * j + x * k (simultaneous multiplication)
            var i = j.bitLength() > k.bitLength() ? j.bitLength() - 1 : k.bitLength() - 1;
            var R = this.curve.getInfinity();
            var both = this.add(x);
            while (i >= 0) {
                R = R.twice();
                if (j.testBit(i)) {
                    if (k.testBit(i)) R = R.add(both);else R = R.add(this);
                } else if (k.testBit(i)) R = R.add(x);
                --i;
            }

            return R;
        }
    }], [{
        key: 'decodeFromHex',
        value: function decodeFromHex(curve, encHex) {
            var dataLen = encHex.length - 2;

            // Extract x and y as byte arrays
            var xHex = encHex.substr(2, dataLen / 2);
            var yHex = encHex.substr(2 + dataLen / 2, dataLen / 2);

            // Convert to BigIntegers
            var x = new BigInteger(xHex, 16);
            var y = new BigInteger(yHex, 16);

            // Return point
            return new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
        }
    }]);

    return ECPointFp;
}();

export var ECCurveFp = function () {
    function ECCurveFp(q, a, b) {
        _classCallCheck(this, ECCurveFp);

        this.q = q;
        this.a = this.fromBigInteger(a);
        this.b = this.fromBigInteger(b);
        this.infinity = new ECPointFp(this, null, null);
    }

    _createClass(ECCurveFp, [{
        key: 'getQ',
        value: function getQ() {
            return this.q;
        }
    }, {
        key: 'getA',
        value: function getA() {
            return this.a;
        }
    }, {
        key: 'getB',
        value: function getB() {
            return this.b;
        }
    }, {
        key: 'equals',
        value: function equals(other) {
            if (other === this) return true;
            return this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b);
        }
    }, {
        key: 'getInfinity',
        value: function getInfinity() {
            return this.infinity;
        }
    }, {
        key: 'fromBigInteger',
        value: function fromBigInteger(x) {
            return new ECFieldElementFp(this.q, x);
        }
    }, {
        key: 'decodePointHex',
        value: function decodePointHex(s) {
            // for now, work with hex strings because they're easier in JS
            switch (parseInt(s.substr(0, 2), 16)) {
                // first byte
                case 0:
                    return this.infinity;
                case 2:
                case 3:
                    // point compression not supported yet
                    return null;
                case 4:
                case 6:
                case 7:
                    var len = (s.length - 2) / 2;
                    var xHex = s.substr(2, len);
                    var yHex = s.substr(len + 2, len);

                    return new ECPointFp(this, this.fromBigInteger(new BigInteger(xHex, 16)), this.fromBigInteger(new BigInteger(yHex, 16)));

                default:
                    // unsupported
                    return null;
            }
        }
    }]);

    return ECCurveFp;
}();