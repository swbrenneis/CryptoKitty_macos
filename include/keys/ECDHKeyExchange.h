#ifndef ECDHKEYEXCHANGE_H_INCLUDED
#define ECDHKEYEXCHANGE_H_INCLUDED

#include "../data/BigInteger.h"

namespace CK {

class ECDHKeyExchange {

    public:
        ECDHKeyExchange();
        ~ECDHKeyExchange();

    private:
        ECDHKeyExchange(const ECDHKeyExchange& other);
        ECDHKeyExchange& operator= (const ECDHKeyExchange& other);

    public:
        struct Point {
            BigInteger x;
            BigInteger y;
        };

        struct CurveParams {
            uint32_t m;     // bitsize
            BigInteger n;   // order
            BigInteger a;   // a coefficient
            BigInteger b;   // b coefficient
            BigInteger xG;  // Base X coordinate
            BigInteger yG;  // Base Y coordinate
            BigInteger p;   // Modulus
            uint32_t h;     // Cofactor
        };

        static const CurveParams SECP256R1;
        static const CurveParams SECP384R1;
        static const CurveParams SECP256K1;

    public:
        coder::ByteArray getPublicKey();
        void setCurve(const CurveParams& params);
        Point getSecret(const coder::ByteArray& fk);

    private:
        coder::ByteArray elementToString(const BigInteger& e) const;
        bool isOnCurve(const Point& point) const;
        Point pointAdd(const Point& P, const Point& Q) const;
        coder::ByteArray pointToString(const Point& point, bool compress);
        Point scalarMultiply(const BigInteger& m,
                                const Point& point) const;
        BigInteger stringToElement(const coder::ByteArray& encoded) const;
        Point stringToPoint(const coder::ByteArray& encoded) const;

    private:
        bool curveSet;      // Curve parameters set.
        bool galois;        // Finite field flag
        BigInteger n;       // Subgroup order.
        BigInteger a;       // Curve coefficient a;
        BigInteger b;       // Curve coefficient b;
        BigInteger p;       // Curve modulus.
        Point G;            // Base Point.
        Point H;            // Public key.
        BigInteger d;       // Secret key
        Point s;            // Shared secret.
        uint32_t m;         // Galois field size.

        static const Point PAI;  // Point at infinity.

};

}

bool operator== (const CK::ECDHKeyExchange::Point& lhs, const CK::ECDHKeyExchange::Point& rhs);
bool operator!= (const CK::ECDHKeyExchange::Point& lhs, const CK::ECDHKeyExchange::Point& rhs);

#endif  // ECDHKEYEXCHANGE_H_INCLUDED
