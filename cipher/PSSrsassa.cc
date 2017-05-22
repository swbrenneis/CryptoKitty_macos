#include "cipher/PSSrsassa.h"
#include "cipher/PSSmgf1.h"
#include "digest/Digest.h"
#include "random/FortunaSecureRandom.h"
#include "keys/RSAPrivateKey.h"
#include "keys/RSAPublicKey.h"
#include "exceptions/IllegalOperationException.h"
#include "exceptions/NoSuchAlgorithmException.h"
#include "exceptions/EncodingException.h"
#include "exceptions/BadParameterException.h"
#include <cmath>

namespace CK {

PSSrsassa::PSSrsassa(Digest *d)
: digest(d),
  algorithmOID(d->getDER()),
  saltLength(10) {
}

PSSrsassa::PSSrsassa(Digest *d, int sLen)
: digest(d),
  algorithmOID(d->getDER()),
  saltLength(sLen) {
}

PSSrsassa::~PSSrsassa() {

    delete digest;

}

coder::ByteArray PSSrsassa::decrypt(const RSAPrivateKey& K, const coder::ByteArray& C) {
    throw IllegalOperationException("Unsupported signature operation");
}

/**
 * Message signature encoding operation.
 * 
 * M is the essage octet string. emBits is themaximal bit length of
 * the integer representation of the encoded message.
 * 
 * Returns the encoded octet string.
 * 
 */
coder::ByteArray PSSrsassa::emsaPSSEncode(const coder::ByteArray& M, int emBits) {

    // The check here for message size with respect to the hash input
    // size (~= 2 exabytes for SHA1) isn't necessary.

    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    coder::ByteArray mHash(digest->digest(M));

    // 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
    int hLen = digest->getDigestLength();
    double emDouble = emBits;
    int emLen = std::ceil(emDouble / 8);
    if (emLen < hLen + saltLength + 2) {
        throw EncodingException("Encoding error");
    }

    // 4.  Generate a random octet string salt of length sLen; if sLen = 0,
    //     then salt is the empty string.
    coder::ByteArray salt(saltLength);
    if (salt.getLength() > 0) {
        FortunaSecureRandom rnd;
        rnd.nextBytes(salt);
    }

    //std::cout << "emsaPSSEncode salt = " << salt << std::endl << std::endl;

    // 5.  Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    //
    // M' is an octet string of length 8 + hLen + sLen with eight
    // initial zero octets.
    coder::ByteArray mPrime(8, 0);
    mPrime.append(mHash);;
    mPrime.append(salt);

    // 6.  Let H = Hash(M'), an octet string of length hLen.
    digest->reset();
    coder::ByteArray H(digest->digest(mPrime));

    // 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
    //     zero octets.  The length of PS may be 0.
    coder::ByteArray PS(emLen - saltLength - hLen - 2, 0);

    // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
    //     emLen - hLen - 1.
    coder::ByteArray DB;
    DB.append(PS);
    DB.append(0x01);
    DB.append(salt);

    //std:: cout << "emsaPSSEncode DB = " << DB << std::endl << std::endl;

    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    PSSmgf1 dbmgf(digest);
    coder::ByteArray dbMask;
    try {
        dbMask = dbmgf.generateMask(H, emLen - hLen - 1);
    }
    catch (BadParameterException& e) {
        // Fail silently
        return false;
    }

    //std:: cout << "emsaPSSEncode dbMask = " << dbMask << std::endl << std::endl;

    // 10. Let maskedDB = DB \xor dbMask.
    //coder::ByteArray maskedDB(rsaXor(DB, dbMask));
    coder::ByteArray maskedDB(DB ^ dbMask);

    //std::cout << "emsaPSSEncode maskedDB = " << maskedDB << std::endl
    //        << std::endl << "emsaPSSEncode H = " << H << std::endl;

    // 11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
    //     maskedDB to zero.
    unsigned char bitmask = 0xff;
    bitmask = bitmask >> ((8 * emLen) - emBits);
    //for (int i = 0; i < (8 * emLen) - emBits; i++) {
    //    bitmask = bitmask >> 1;
    //}
    //int ibit = bitmask;
    //std::cout << "emsaPSSEncode bitmask = " << ibit << std::endl << std::endl;
    maskedDB[0] = maskedDB[0] & bitmask;

    // 12. Let EM = maskedDB || H || 0xbc.
    coder::ByteArray EM;
    EM.append(maskedDB);
    EM.append(H);
    EM.append(0xbc);

    //std::cout << "emsaPSSencode EM = " << EM << std::endl;;

    // 13. Output EM.
    return EM;

}

/**
 * Verify an EMSA-PSS encoded signature.
 * 
 * M is the message to be verified. EM is the encoded message octet
 * string. emBits is the maximal bit length of the integer
 * representation of EM
 *                 
 * Returns true if the encoding is consistent, otherwise false.
 */
bool PSSrsassa::emsaPSSVerify(const coder::ByteArray& M, const coder::ByteArray& EM, 
                                                        int emBits) {

    //std::cout << "emsaPSSVerify EM = " << EM << std::endl;

    // 1.  If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    //     and stop.
    //
    // As noted before, this test is impractical since the actual size limit
    // for SHA1 is 2^64 - 1 octets and Java cannot create a string or array
    // longer than 2^63 - 1.

    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    coder::ByteArray mHash(digest->digest(M));

    // 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.

    int hLen = digest->getDigestLength();
    double emDouble = emBits;
    int emLen = std::ceil(emDouble / 8);
    if (emLen < hLen + saltLength + 2) {
        return false;
    }

    // 4.  If the rightmost octet of EM does not have hexadecimal value
    //     0xbc, output "inconsistent" and stop.
    if (EM[EM.getLength() - 1] != 0xbc) {
        return false;
    }

    // 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //     let H be the next hLen octets.
    int maskLength = emLen - hLen - 1;
    coder::ByteArray maskedDB(EM.range(0, maskLength));
    coder::ByteArray H(EM.range(maskLength, hLen));

    //std::cout << "emsaPSSVerify maskedDB = " << maskedDB << std::endl
    //        << std::endl << "emsaPSSVerify H = " << H << std::endl;

    // 6.  If the leftmost 8emLen - emBits bits of the leftmost octet in
    //     maskedDB are not all equal to zero, output "inconsistent" and
    //     stop.
    unsigned char bitmask = 0xff;
    bitmask = bitmask >> ((8 * emLen) - emBits);
    unsigned char invert = bitmask ^ 0xff;
    if ((maskedDB[0] & invert) != 0) {
        //std::cout << "Mask failed" << std::endl;
        return false;
    }

    // 7.  Let dbMask = MGF(H, emLen - hLen - 1).
    PSSmgf1 dbmgf(digest);
    coder::ByteArray dbMask;
    try {
        dbMask = dbmgf.generateMask(H, emLen - hLen - 1);
    }
    catch (BadParameterException& e) {
        // Fail silently
        return false;
    }

    //std:: cout << "emsaPSSVerify dbMask = " << dbMask << std::endl;

    // 8.  Let DB = maskedDB \xor dbMask.
    coder::ByteArray DB;
    try {
        //DB = rsaXor(maskedDB, dbMask);
        DB = maskedDB ^ dbMask;
    }
    catch (BadParameterException& e) {
        // Fail silently
        return false;
    }

    //std:: cout << std::endl << "emsaPSSVerify DB = " << DB << std::endl;

    // 9.  Set the leftmost 8emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    bitmask = 0xff;
    bitmask = bitmask >> ((8 * emLen) - emBits);
    //int ibit = bitmask;
    //std::cout << std::endl << "emsaPSSVerify bitmask = " << ibit << std::endl << std::endl;
    DB[0] = DB[0] & bitmask;

    // 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
    //     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
    //     position is "position 1") does not have hexadecimal value 0x01,
    //     output "inconsistent" and stop.
    //
    for (int i = 0; i < emLen - hLen - saltLength - 2; ++i) {
        if (DB[i] != 0) {
            return false;
            //std::cout << "Zero check failed" << std::endl;
        }
    }
    // Subtract 2 at the end because it is relative to element 1of the array.
    if (DB[emLen - hLen - saltLength - 2] != 0x01) {
        //int idb = DB[emLen - hLen - saltLength - 1];
        //std::cout << "0x01 check failed. emLen - hLen - saltLength - 1 = " 
        //        << emLen - hLen - saltLength - 1 
        //        << " byte = " << idb << std::endl;
        return false;
    }

    // 11.  Let salt be the last sLen octets of DB.
    coder::ByteArray salt(DB.range(DB.getLength() - saltLength, saltLength));

    //std::cout << "emsaPSSVerify salt = " << salt << std::endl << std::endl;

    // 12.  Let
    //        M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //
    // M' is an octet string of length 8 + hLen + sLen with eight
    // initial zero octets.
    coder::ByteArray mPrime(8, 0);
    mPrime.append(mHash);
    mPrime.append(salt);

    // 13. Let H' = Hash(M'), an octet string of length hLen.
    // hash.reset(); Not needed. CK digests don't retail state.
    coder::ByteArray hPrime(digest->digest(mPrime));

    //std::cout << std::endl << "emsa PSSVerify hPrime = " << hPrime << std::endl;

    // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    return H == hPrime;

}

coder::ByteArray
PSSrsassa::encrypt(const RSAPublicKey& K, const coder::ByteArray& C) {
    throw IllegalOperationException("Unsupported signature operation");
}

/**
 * Sign a message.
 * 
 * K is the private key. M is the message octet string to be signed
 * 
 * Returns signature octet string.
 */
coder::ByteArray PSSrsassa::sign(const RSAPrivateKey& K, const coder::ByteArray& M) {

    // 1. EMSA-PSS encoding: Apply the EMSA-PSS encoding operation to
    // the message M to produce an encoded message EM of length
    // \ceil ((modBits - 1)/8) octets such that the bit length of the
    // integer OS2IP (EM) is at most modBits - 1, where modBits is the
    // length in bits of the RSA modulus n:
    //
    //    EM = EMSA-PSS-ENCODE (M, modBits - 1).
    //
    // Note that the octet length of EM will be one less than k if
    // modBits - 1 is divisible by 8 and equal to k otherwise.  If the
    // encoding operation outputs "message too long," output "message too
    // long" and stop.  If the encoding operation outputs "encoding
    // error," output "encoding error" and stop.
    //
    // The encoding operation won't output "message too long" since the
    // message would have to be ~= 2 exabytes long.
    coder::ByteArray EM(emsaPSSEncode(M, K.getBitLength() - 1));

    // RSA signature
    //
    // a. Convert the encoded message EM to an integer message
    //    representative m (see Section 4.2):
    //
    //      m = OS2IP (EM).
    BigInteger m(os2ip(EM));

    // b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
    //    private key K and the message representative m to produce an
    //    integer signature representative s:
    //
    //       s = RSASP1 (K, m).
    BigInteger s(K.rsasp1(m));

    // c. Convert the signature representative s to a signature S of
    //    length k octets (see Section 4.1):
    //
    //      S = I2OSP (s, k).
    unsigned k = K.getBitLength() / 8;
    return i2osp(s, k);

}

/**
 *
 * Verify an EMSA-PSS encoded signature.
 * 
 * K is the he public key in the form of (n,e). M is the signed message
 * octet string. S is the signature octet string.
 * 
 * Returns true if the signature is valid, otherwise false.
 * 
 */
bool PSSrsassa::verify(const RSAPublicKey& K, const coder::ByteArray& M,
                                                    const coder::ByteArray& S) {

    // Length check.
    unsigned k = K.getBitLength() / 8;
    if (S.getLength() != k) {
        // Fail silently
        return false;
    }

    // a. Convert the signature S to an integer signature representative s
    //
    //      s = OS2IP (S).
    //
    // b. Apply the RSAVP1 verification primitive (Section 5.2.2) to the
    //    RSA public key (n, e) and the signature representative s to
    //    produce an integer message representative m:
    //
    //       m = RSAVP1 ((n, e), s).
    //
    // If RSAVP1 output "signature representative out of range,"
    // output "invalid signature" and stop.
    BigInteger m(rsavp1(K, os2ip(S)));

    // c. Convert the message representative m to an encoded message EM
    //    of length emLen = \ceil ((modBits - 1)/8) octets, where modBits
    //    is the length in bits of the RSA modulus n:
    //
    //      EM = I2OSP (m, emLen).
    //
    // Note that emLen will be one less than k if modBits - 1 is
    // divisible by 8 and equal to k otherwise.  If I2OSP outputs
    // "integer too large," output "invalid signature" and stop.
    double doubleBitSize = K.getBitLength();
    int emLen = std::ceil((doubleBitSize - 1) / 8);
    coder::ByteArray EM(i2osp(m, emLen));

    return emsaPSSVerify(M, EM, K.getBitLength() - 1);

}

}
