#include "keys/RSAPrivateCrtKey.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/DecryptionException.h"

namespace CK {

RSAPrivateCrtKey::RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                                    const BigInteger& d, const BigInteger& e)
: RSAPrivateKey(crt),
  p(p),
  q(q) {

    BigInteger pp(p - BigInteger::ONE);
    BigInteger qq(q - BigInteger::ONE);
    dP = e.modInverse(pp);
    dQ = e.modInverse(qq);
    qInv = q.modInverse(p);
    n = p * q;
    bitLength = n.bitLength();

}

RSAPrivateCrtKey::RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                                    const BigInteger& dp, const BigInteger& dq,
                                    const BigInteger& qi)
: RSAPrivateKey(crt),
  p(p),
  q(q),
  dP(dp),
  dQ(dq),
  qInv(qi) {

    n = p * q;
    bitLength = n.bitLength();

}

RSAPrivateCrtKey::RSAPrivateCrtKey(const RSAPrivateCrtKey& other)
: RSAPrivateKey(crt) {

    p = other.p;
    q = other.q;
    dP = other.dP;
    dQ = other.dQ;
    qInv = other.qInv;
    n = other.n;
    d = other.d;
    bitLength = other.bitLength;

}

RSAPrivateCrtKey& RSAPrivateCrtKey::operator =(const RSAPrivateCrtKey& other) {

    p = other.p;
    q = other.q;
    dP = other.dP;
    dQ = other.dQ;
    qInv = other.qInv;
    n = other.n;
    d = other.d;
    bitLength = other.bitLength;
    keyType = crt;
    algorithm = "RSA";
    return *this;

}

RSAPrivateCrtKey::~RSAPrivateCrtKey() {
}

const BigInteger& RSAPrivateCrtKey::getInverse() const {

    return qInv;

}

const BigInteger& RSAPrivateCrtKey::getPrimeExponentP() const {

    return dP;

}

const BigInteger& RSAPrivateCrtKey::getPrimeExponentQ() const {

    return dQ;

}

const BigInteger& RSAPrivateCrtKey::getPrimeP() const {

    return p;

}

const BigInteger& RSAPrivateCrtKey::getPrimeQ() const {

    return q;

}

/*
 * RSA decryption primitive, CRT method.
 */
BigInteger RSAPrivateCrtKey::rsadp(const BigInteger& c) const {

    //   1. If the ciphertext representative c is not between 0 and n - 1,
    //      output "ciphertext representative out of range" and stop.
    if (c < BigInteger::ZERO || c >= n) {
        throw DecryptionException();
    }

    // i.    Let m_1 = c^dP mod p and m_2 = c^dQ mod q.
    BigInteger m_1 = c.modPow(dP, p);
    BigInteger m_2 = c.modPow(dQ, q);

    // iii.  Let h = (m_1 - m_2) * qInv mod p.
    BigInteger h = (m_1 - m_2) * qInv % p;

    // iv.   Let m = m_2 + q * h.
    return  m_2 + q * h;

}

/*
 * RSA signature primitive, CRT method.
 */
BigInteger RSAPrivateCrtKey::rsasp1(const BigInteger& m) const {

    //   1. If the message representative c is not between 0 and n - 1,
    //      output "message representative out of range" and stop.
    if (m < BigInteger::ZERO || m >= n) {
        /* std::cout << "m = " << m << std::endl << "n = " << n << std::endl;
        std::cout << "m bit length = " << m.bitLength()
                << std::endl << "n bit length = " << n.bitLength() << std::endl; */
        throw BadParameterException("Message representative out of range");
    }

    //std::cout << "rsasp1 (CRT) m = " << m << std::endl;
    // i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
    BigInteger s_1(m.modPow(dP, p));
    BigInteger s_2(m.modPow(dQ, q));

    // iii.  Let h = (s_1 - s_2) * qInv mod p.
    BigInteger h(((s_1 - s_2) * qInv) % p);

    // iv.   Let s = s_2 + q * h.
    BigInteger result((q * h) + s_2);
    //std::cout << "rsasp1 (CRT) result = " << result << std::endl;
    return result;

}

}

