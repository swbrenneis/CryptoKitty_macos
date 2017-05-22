#include "ciphermodes/MtE.h"
#include "mac/HMAC.h"

namespace CK {

MtE::MtE(BlockCipherMode *c, HMAC* h)
: cipher(c),
  hmac(h),
  authenticated(false) {
}

MtE::~MtE() {

    delete hmac;
    delete cipher;

}

coder::ByteArray MtE::decrypt(const coder::ByteArray& ciphertext,
                                    const coder::ByteArray& key) {

    coder::ByteArray ptm(cipher->decrypt(ciphertext, key));
    unsigned digestLength = hmac->getDigestLength();
    unsigned hmacOffset = ptm.getLength() - digestLength;
    coder::ByteArray mac(ptm.range(hmacOffset, digestLength));
    coder::ByteArray message(ptm.range(0, hmacOffset));
    hmac->setKey(key);
    hmac->setMessage(message);
    authenticated = hmac->authenticate(mac);
    return message;

}

coder::ByteArray MtE::encrypt(const coder::ByteArray& plaintext,
                                    const coder::ByteArray& key) {

    hmac->setKey(key);
    hmac->setMessage(plaintext);
    coder::ByteArray ptm(plaintext);
    ptm.append(hmac->getHMAC());
    return cipher->encrypt(ptm, key);

}

}
