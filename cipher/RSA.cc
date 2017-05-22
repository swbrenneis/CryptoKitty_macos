#include "cipher/RSA.h"
#include "keys/RSAPublicKey.h"
#include "random/CMWCRandom.h"
#include "data/NanoTime.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/SignatureException.h"
#include <coder/ByteArray.h>
#include <cmath>
#include <time.h>

namespace CK {

// Static initialization.
const BigInteger RSA::MASK(0xff);

RSA::RSA() {
}

RSA::~RSA() {
}

/*
 * Convert an integer representation to an octet string.
 */
coder::ByteArray RSA::i2osp(const BigInteger& x, unsigned xLen) {

    // This was a Java limitation. Since I don't want
    // to have to configure the memory size kernel parameters,
    // I'll leave it in. Any reasonable sized key won't even come
    // close to violating this.
    /*if (x > (BigInteger(256).pow(xLen))) {
        coder::ByteArray xb(x.getEncoded());
        std::cout << "limit = " << (BigInteger(256).pow(xLen)) << std::endl;
        std::cout << "x = " << x << std::endl;
        std::cout << "xLen = " << xLen << std::endl;
        std::cout << "xb = " << xb.toString() << std::endl;
        std::cout << "xb length = " << xb.getLength() << std::endl;
        throw BadParameterException("Integer too large");
    }*/

    //std::cout << "i2sop x = " << x << std::endl;
    coder::ByteArray work(x.getEncoded());
    if (work.getLength() > xLen) {
        if (work[0] == 0) {
            // BigInteger encoding places a sign byte in the LSB when necessary.
            // It needs to be removed to make the encoded integer the specified
            // length.
            work = work.range(1);
        }
        else {
            throw BadParameterException("Invalid specified length");
        }
    }
    coder::ByteArray pad(xLen - work.getLength());
    pad.append(work);

    //std::cout << "worked = " << worked << std::endl;
    return pad;

}

/*
 * Convert an octet string to an integer. Just using the constructor gives
 * unreliable results, so we'll do it the hard way.
 */
BigInteger RSA::os2ip(const coder::ByteArray& X) {

    return BigInteger(X);

}

/*
 * Encryption primitive.
 *
 * K is the public key. p is the plaintext representative.
 *
 * returns the ciphertext representative.
 */
BigInteger RSA::rsaep(const RSAPublicKey& K, const BigInteger& p) {

    // 1. If the message representative m is not between 0 and n - 1, output
    //  "message representative out of range" and stop.
    if (p < BigInteger::ZERO || p >= K.getModulus()) {
        throw new BadParameterException("Message representative out of range");
    }

    // 2. Let c = m^e mod n.
    return p.modPow(K.getPublicExponent(), K.getModulus());

}

/*
 * Signature verification primitive.
 * 
 * K is the public key. s is the signature representative.
 * 
 * Returns the message representative.
 * 
 */
BigInteger RSA::rsavp1(const RSAPublicKey& K, const BigInteger& s) {

    // 1. If the signature representative m is not between 0 and n - 1, output
    //  "signature representative out of range" and stop.
    if (s < BigInteger::ZERO || s >= K.getModulus()) {
        throw SignatureException("Signature representative out of range");
    }

    // Randomize the amount of time to verify to prevent timing attacks.
    CMWCRandom rnd;
    NanoTime nt;
    rnd.setSeed(nt.getFullTime());
    timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = rnd.nextUnsignedInt();
    nanosleep(&ts, 0);

    //std:: cout << "rsavp1 s = " << s << std::endl;
    // 2. Let m = s^e mod n.
    BigInteger result(s.modPow(K.getPublicExponent(), K.getModulus()));
    //std::cout << "rsavp1 result = " << result << std::endl;
    return result;

}

}
