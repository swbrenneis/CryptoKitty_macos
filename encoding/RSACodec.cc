#include "encoding/RSACodec.h"
#include "keys/RSAPrivateKey.h"
#include "keys/RSAPublicKey.h"
#include "cipher/OAEPrsaes.h"
#include "exceptions/DecryptionException.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/EncodingException.h"
#include "random/FortunaSecureRandom.h"

namespace CK {

RSACodec::RSACodec() {

}

RSACodec::RSACodec(const coder::ByteArray& txt)
: text(txt) {

}

RSACodec::~RSACodec() {

}

void RSACodec::decrypt(const RSAPrivateKey& privateKey) {

    if (text.getLength() == 0) {
        throw EncodingException("Cannot decrypt empty stream");
    }

    try {
        OAEPrsaes cipher(OAEPrsaes::sha256);
        stream = cipher.decrypt(privateKey, text);
        if (stream.getLength() == 0) {
            throw EncodingException("Decryption failed");
        }
    }
    catch (DecryptionException& e) {
        throw EncodingException(e);
    }

}

void RSACodec::encrypt(const RSAPublicKey& publicKey) {

    try {
        OAEPrsaes cipher(OAEPrsaes::sha256);
        coder::ByteArray seed(32, 0);
        FortunaSecureRandom rnd;
        rnd.nextBytes(seed);
        cipher.setSeed(seed);
        text = cipher.encrypt(publicKey, stream);
    }
    catch (BadParameterException& e) {
        throw EncodingException(e);
    }

}

}
