#include "keys/ECDHKeyExchange.h"
#include "exceptions/IllegalStateException.h"
#include "exceptions/BadParameterException.h"
#include "random/FortunaSecureRandom.h"
#include <cmath>

namespace CK {

// Static initialization.
const ECDHKeyExchange::Point ECDHKeyExchange::PAI =
        { BigInteger::ZERO, BigInteger::ZERO };


static const uint8_t n256bytes[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
                                    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51 };
static const uint8_t a256bytes[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC };
static const uint8_t b256bytes[] = { 0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
                                    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
                                    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
                                    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B };
static const uint8_t xg256bytes[] = { 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
                                    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
                                    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
                                    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96 };
static const uint8_t yg256bytes[] = { 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
                                    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
                                    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
                                    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5 };
static const uint8_t p256bytes[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const ECDHKeyExchange::CurveParams ECDHKeyExchange::SECP256R1 = {
    0,
    BigInteger(coder::ByteArray(n256bytes, sizeof(n256bytes))),
    BigInteger(coder::ByteArray(a256bytes, sizeof(a256bytes))),
    BigInteger(coder::ByteArray(b256bytes, sizeof(b256bytes))),
    BigInteger(coder::ByteArray(xg256bytes, sizeof(xg256bytes))),
    BigInteger(coder::ByteArray(yg256bytes, sizeof(yg256bytes))),
    BigInteger(coder::ByteArray(p256bytes, sizeof(p256bytes))),
    0x01 };
static const uint8_t n384bytes[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
                                    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
                                    0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73 };
static const uint8_t a384bytes[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC };
static const uint8_t b384bytes[] = { 0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
                                    0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
                                    0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
                                    0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
                                    0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
                                    0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF };
static const uint8_t xg384bytes[] = { 0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37,
                                    0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
                                    0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
                                    0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
                                    0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C,
                                    0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7 };
static const uint8_t yg384bytes[] = { 0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F,
                                    0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
                                    0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C,
                                    0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
                                    0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D,
                                    0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F };
static const uint8_t p384bytes[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
const ECDHKeyExchange::CurveParams ECDHKeyExchange::SECP384R1 = {
    0,
    BigInteger(coder::ByteArray(n384bytes, sizeof(n384bytes))),
    BigInteger(coder::ByteArray(a384bytes, sizeof(a384bytes))),
    BigInteger(coder::ByteArray(b384bytes, sizeof(b384bytes))),
    BigInteger(coder::ByteArray(xg384bytes, sizeof(xg384bytes))),
    BigInteger(coder::ByteArray(yg384bytes, sizeof(yg384bytes))),
    BigInteger(coder::ByteArray(p384bytes, sizeof(p384bytes))),
    0x01 };

static const uint8_t p256kbytes[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f };
static const uint8_t a256kbytes[] = { 0x00 };
static const uint8_t b256kbytes[] = { 0x07 };
static const uint8_t xg256kbytes[] = { 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
                                    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
                                    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
                                    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98 };
static const uint8_t yg256kbytes[] = { 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
                                    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
                                    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
                                    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8 };
static const uint8_t n256kbytes[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                                    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                                    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41 };
const ECDHKeyExchange::CurveParams ECDHKeyExchange::SECP256K1 = {
    0,
    BigInteger(coder::ByteArray(n256kbytes, sizeof(n256kbytes))),
    BigInteger(coder::ByteArray(a256kbytes, sizeof(a256kbytes))),
    BigInteger(coder::ByteArray(b256kbytes, sizeof(b256kbytes))),
    BigInteger(coder::ByteArray(xg256kbytes, sizeof(xg256kbytes))),
    BigInteger(coder::ByteArray(yg256kbytes, sizeof(yg256kbytes))),
    BigInteger(coder::ByteArray(p256kbytes, sizeof(p256kbytes))),
    0x01 };

ECDHKeyExchange::ECDHKeyExchange()
: curveSet(false),
  galois(false) {

      H.x = H.y = s.x = s.y = BigInteger::ZERO;

}

ECDHKeyExchange::~ECDHKeyExchange() {
}
/*
 * Converts a field element (point coordinate) to an octet string.
 * The conversion depends on whether the curve is defined in terms
 * of a prime modulus or a finite (Galois) field.
 *
 * Certicom Research, SEC 01, v2, section 2.3.5.
 */
coder::ByteArray ECDHKeyExchange::elementToString(const BigInteger& e) const {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    coder::ByteArray result;

    if (galois) {
        double mDouble = m;
        int mlen = ceil(mDouble / 8);
        result.setLength(mlen);
        for (int i = 1; i < mlen; ++i) {
            uint8_t octet = 0;
            for (int j = 7; j >= 0; --j) {
                octet = octet << 1;
                if (e.testBit(j + (8 * (mlen - i - 1)))) {
                    octet |= 0x01;
                }
            }
            result[i] = octet;
        }
        uint8_t m0 = 0;
        int bit = m - 1;
        for (uint32_t i = 0; i < 8 - ((8 * mlen) - m); ++i) {
            m0 = m0 << 1;
            if (e.testBit(bit)) {
                m0 |= 0x01;
            }
        }
        result[0] = m0;
    }
    else {
        double pDouble = p.bitLength();
        int mlen = ceil(pDouble / 8);
        coder::ByteArray encoded(e.getEncoded());
        result.setLength(encoded.getLength() - mlen);
        result.append(encoded);
    }

    return result;

}

coder::ByteArray ECDHKeyExchange::getPublicKey() {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    if (H.x == BigInteger::ZERO) {
        FortunaSecureRandom rnd;
        BigInteger n1 = n - BigInteger::ONE;
        d = BigInteger(n.bitLength(), true, rnd);
        while (d >= n1) {
            d = BigInteger(n.bitLength(), true, rnd);
        }
        H = scalarMultiply(d, G);
    }

    return pointToString(H, false);

}

/*
 * Returns the shared secret. Computes it if it hasn't been
 * done.
 */
ECDHKeyExchange::Point ECDHKeyExchange::getSecret(const coder::ByteArray& fk) {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    Point keyPoint = stringToPoint(fk);
    if (!isOnCurve(keyPoint)) {
        throw BadParameterException("Invalid foreign public key");
    }

    if (s.x == BigInteger::ZERO) {
        s = scalarMultiply(d, keyPoint);
    }

    return s;

}

bool ECDHKeyExchange::isOnCurve(const Point& point) const {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    if (point == PAI) {
        // Point at infinity is always on the curve.
        return true;
    }

    return (point.y.pow(2) - point.x.pow(3) - a * point.x - b) % p == BigInteger::ZERO;

}

/*
 * Point addition.
 */
ECDHKeyExchange::Point
ECDHKeyExchange::pointAdd(const Point& P, const Point& Q) const {

    if (!isOnCurve(P) || !isOnCurve(Q)) {
        throw IllegalStateException("Invalid point input for addition");
    }

    if (P == PAI) {
        return Q;
    }

    if (Q == PAI) {
        return P;
    }

    BigInteger x1 = P.x;
    BigInteger y1 = P.y;
    BigInteger x2 = Q.x;
    BigInteger y2 = Q.y;

    if (x1 == x2 && y2 != y1) {
        // Point + (-Point) = 0
        return PAI;
    }

    BigInteger m;
    BigInteger x3;
    BigInteger y3;

    if (P == Q) {
        BigInteger two(2L);
        BigInteger three(3L);
        m = (three * x1.pow(2) + a) * (two * y1).modInverse(p);
    }
    else {
        m = (y1 - y2) * (x1 - x2).modInverse(p);
    }

    x3 = m.pow(2) - x1 - x2;
    y3 = y1 + m * (x3 - x1);

    Point result = { x3 % p, -y3 % p };

    if (!isOnCurve(result)) {   // Something went horribly, horribly wrong.
        throw IllegalStateException("Invalid point addition result");
    }

    return result;

}

/*
 * Convert a curve coordinate to an octet string with or without compression.
 *
 * Certicom Research, SEC 01, v2, section 2.3.3.
 */
coder::ByteArray ECDHKeyExchange::pointToString(const Point& point, bool compress) {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    if (point.x == BigInteger::ZERO && point.y == BigInteger::ZERO) {
        return coder::ByteArray(1, 0);
    }

    coder::ByteArray result;
    coder::ByteArray x(elementToString(point.x));
    if (compress) {
        uint8_t yP;
        if (galois) {
            if (point.x == BigInteger::ZERO) {
                yP = 0;
            }
            else {
                BigInteger z = point.y / point.x;
                yP = z.testBit(0) ? 1 : 0;
            }
        }
        else {
            yP = point.y.testBit(0) ? 1 : 0;
        }
        result.setLength(0x02 | yP);
        result.append(x);
    }
    else {
        coder::ByteArray y(elementToString(point.y));
        result.setLength(1, 0x04);
        result.append(x);
        result.append(y);
    }

    return result;

}

/*
 * Multiplication by double and add. There is probably a better way.
 */
ECDHKeyExchange::Point
ECDHKeyExchange::scalarMultiply(const BigInteger& m, const Point& point) const {

    if (!isOnCurve(point)) {   // Something went horribly, horribly wrong.
        throw IllegalStateException("Invalid point input to scalar multiplication");
    }

    if (m % n == BigInteger::ZERO || point == PAI) {
        std::cout << " m mod n = 0 or point = PAI. Returning PAI." << std::endl;
        return PAI;
    }

    std::cout << "m = " << m << std::endl;
    if (m < BigInteger::ZERO) {
        // k * point = -k * (-point)
        std::cout << "Negating." << std::endl;
        Point neg = { point.x, -point.y % p };
        if (!isOnCurve(neg)) {   // Something went horribly, horribly wrong.
            throw IllegalStateException("Point negation off curve");
        }
        return scalarMultiply(-m, neg);
    }

    Point result = PAI;
    Point addend = point;
    BigInteger k(m);

    int i = 0;
    while (k != BigInteger::ZERO) {
        if ((k & BigInteger::ONE) != BigInteger::ZERO) {
            // Add.
            result = pointAdd(result, addend);
        }

        // Double.
        addend = pointAdd(addend, addend);

        k = k >> 1;
        std::cout << ++i << ": result = " << result.x << ", " << result.y << std::endl;
        std::cout << i << ": addend = " << addend.x << ", " << addend.y << std::endl;
    }


    if (!isOnCurve(result)) {   // Something went horribly, horribly wrong.
        throw IllegalStateException("Invalid scalar multiplication result");
    }

    return result;

}

/*
 * Set the curve parameters.
 */
void ECDHKeyExchange::setCurve(const CurveParams& params) {

    n = params.n;
    a = params.a;
    b = params.b;
    p = params.p;
    G.x = params.xG;
    G.y = params.yG;
    m = params.m;
    if (m > 0) {
        galois = true;
    }

    curveSet = true;

}

/*
 * Convert an octet string to a field element.
 *
 * Certicom Research, SEC 01, Section 2.3.6.
 */
BigInteger ECDHKeyExchange::stringToElement(const coder::ByteArray& encoded) const {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    BigInteger result;
    double q = galois ? m : p.bitLength();
    if (encoded.getLength() != ceil(q / 8)) {
        throw BadParameterException("Invalid element length");
    }

    if (galois) {
        // Figure this out.
    }
    else {
       result.decode(encoded);
       if (result < BigInteger::ZERO || result >= p) {
           throw BadParameterException("Invalid element");
       }
    }

    return result;

}

/*
 * Convert octet string to curve coordinates.
 *
 * Certicom Research, SEC 01, v2, Section 2.3.4.
 */
ECDHKeyExchange::Point
ECDHKeyExchange::stringToPoint(const coder::ByteArray& encoded) const {

    if (!curveSet) {
        throw IllegalStateException("Curve parameters not set");
    }

    if (encoded[0] == 0) {
        return PAI;
    }

    Point result;
    double q = galois ? m : p.bitLength();

    if  (encoded.getLength() == ceil(q / 8) + 1) {   // Compressed
        if (galois) {
        }
        else {
        }
    }
    else if (encoded.getLength() == (2 * ceil(q / 8)) + 1) {   // Uncompressed
        if (encoded[0] != 0x04) {
            throw BadParameterException("Invalid point format");
        }
        uint32_t eLen = ceil(q / 8);
        result.x = stringToElement(encoded.range(1, eLen));
        result.y = stringToElement(encoded.range(eLen+1, eLen));
        if (!isOnCurve(result)) {
            throw BadParameterException("Invalid point");
        }
    }

    return result;

}

}

bool operator== (const CK::ECDHKeyExchange::Point& lhs, const CK::ECDHKeyExchange::Point& rhs) {
    return lhs.x == rhs.x && lhs.y == rhs.y;
}

bool operator!= (const CK::ECDHKeyExchange::Point& lhs, const CK::ECDHKeyExchange::Point& rhs) {
    return lhs.x != rhs.x || lhs.y != rhs.y;
}

