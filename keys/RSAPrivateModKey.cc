#include "keys/RSAPrivateModKey.h"
#include "exceptions/BadParameterException.h"

namespace CK {

RSAPrivateModKey::RSAPrivateModKey(const BigInteger& d,
                const BigInteger& n)
: RSAPrivateKey(KeyType::mod),
  prvExp(d),
  mod(n) {

    bitLength = mod.bitLength();

}

RSAPrivateModKey::~RSAPrivateModKey() {
}

/*
 * Modulus method RSA decryption primitive
 */
BigInteger RSAPrivateModKey::rsadp(const BigInteger& c) const {

    //   1. If the message representative c is not between 0 and n - 1,
    //      output "message representative out of range" and stop.
    if (c < BigInteger::ZERO || c >= mod) {
        throw BadParameterException("Message representative out of range");
    }

    return c.modPow(prvExp, mod);

}

/*
 * Modulus method RSA signature primitive.
 */
BigInteger RSAPrivateModKey::rsasp1(const BigInteger& m) const {

    //   1. If the message representative c is not between 0 and n - 1,
    //      output "message representative out of range" and stop.
    if (m < BigInteger::ZERO || m >= mod) {
        throw BadParameterException("Message representative out of range");
    }

    // Let s = m^d mod n.
    return BigInteger(m.modPow(prvExp, mod));

}

}
