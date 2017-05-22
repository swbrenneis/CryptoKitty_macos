#include "encoding/GCMCodec.h"
#include "ciphermodes/GCM.h"
#include "cipher/AES.h"
#include "random/FortunaSecureRandom.h"
#include "exceptions/EncodingException.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/AuthenticationException.h"

namespace CK {

GCMCodec::GCMCodec() {
    
}

GCMCodec::GCMCodec(const coder::ByteArray& ciphertext)
: text(ciphertext) {
    
}

GCMCodec::~GCMCodec() {
    
}

void GCMCodec::decrypt(const coder::ByteArray& key, const coder::ByteArray& ad) {

    // The IV is the last 12 bytes of the provided text.
    coder::ByteArray ciphertext(text.range(0, text.getLength() - 12));
    coder::ByteArray iv(text.range(text.getLength() - 12));

    try {
        GCM gcm(new AES(AES::AES256), true);    // Auth tag is appended
        gcm.setIV(iv);
        gcm.setAuthenticationData(ad);
        stream = gcm.decrypt(ciphertext, key);
    }
    catch (BadParameterException& e) {
        throw EncodingException(e);
    }
    catch (AuthenticationException& e) {
        throw EncodingException(e);
    }
    
}

void GCMCodec::encrypt(const coder::ByteArray& key, const coder::ByteArray& ad) {

    coder::ByteArray iv(12, 0);
    FortunaSecureRandom rnd;
    rnd.nextBytes(iv);

    try {
        GCM gcm(new AES(AES::AES256), true);    // Append the auth tag.
        gcm.setIV(iv);
        gcm.setAuthenticationData(ad);
        text = gcm.encrypt(stream, key);
        text.append(iv);                        // Append the IV
    }
    catch (BadParameterException& e) {
        throw EncodingException(e);
    }
    catch (AuthenticationException& e) {
        throw EncodingException("Authentication failer");
    }

}

}
