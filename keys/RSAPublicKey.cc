#include "keys/RSAPublicKey.h"

namespace CK {

RSAPublicKey::RSAPublicKey(const BigInteger& n, const BigInteger& e)
: PublicKey("RSA"),
  exp(e),
  mod(n) {

      bitLength = mod.bitLength();

}

RSAPublicKey::RSAPublicKey(const RSAPublicKey& other)
: PublicKey("RSA") {    

    bitLength = other.bitLength;
    exp = other.exp;
    mod = other.mod;

}

RSAPublicKey& RSAPublicKey::operator =(const RSAPublicKey& other) {

    algorithm = "RSA";
    bitLength = other.bitLength;
    exp = other.exp;
    mod = other.mod;
    return *this;

}

RSAPublicKey::~RSAPublicKey() {
}

int RSAPublicKey::getBitLength() const {

    return bitLength;

}

const BigInteger& RSAPublicKey::getPublicExponent() const {

    return exp;

}

const BigInteger& RSAPublicKey::getModulus() const {

    return mod;

}

}

