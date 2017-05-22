#ifndef RSAPRIVATECRTKEY_H_INCLUDED
#define RSAPRIVATECRTKEY_H_INCLUDED

#include "RSAPrivateKey.h"
#include "../data/BigInteger.h"

namespace CK {

class RSAPrivateCrtKey : public RSAPrivateKey {

    private:
        RSAPrivateCrtKey();

    public:
        RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                            const BigInteger& d, const BigInteger& e);
        RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                            const BigInteger& dp, const BigInteger& dq,
                            const BigInteger& qi);
        RSAPrivateCrtKey(const RSAPrivateCrtKey& other);
        RSAPrivateCrtKey& operator= (const RSAPrivateCrtKey& other);
        ~RSAPrivateCrtKey();

    public:
        const BigInteger& getInverse() const;
        const BigInteger& getModulus() const { return n; }
        const BigInteger& getPrimeExponentP() const;
        const BigInteger& getPrimeExponentQ() const;
        const BigInteger& getPrimeP() const;
        const BigInteger& getPrimeQ() const;
        const BigInteger& getPrivateExponent() const { return d; }
        void setModulus(const BigInteger& mod) { n = mod; }
        void setPrivateExponent(const BigInteger& exp) { d = exp; }

    protected:
        // Decryption primitive.
        BigInteger rsadp(const BigInteger& c) const;
        // Signature generation primitive.
        BigInteger rsasp1(const BigInteger& m) const;

    private:
        BigInteger p;  // First prime.
        BigInteger q;  // Second prime
        BigInteger dP;   // First prime exponent
        BigInteger dQ;   // Second prime exponent
        BigInteger qInv;    // qInv
        BigInteger d;       // Private exponent
        BigInteger n; // Modulus

};

}

#endif  // RSAPRIVATECRTKEY_H_INCLUDED
