#include "encoding/GCMCodec.h"
#include "ciphermodes/GCM.h"
#include "cipher/AES.h"
#include "random/FortunaSecureRandom.h"
#include "exceptions/EncodingException.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/AuthenticationException.h"

namespace CK {

GCMCodec::GCMCodec()
: ivSet(false) {
    
}

GCMCodec::GCMCodec(const coder::ByteArray& ciphertext)
: ivSet(false),
  text(ciphertext) {
    
}

GCMCodec::~GCMCodec() {
    
}

void GCMCodec::decrypt(const coder::ByteArray& key, const coder::ByteArray& ad) {

    // If not provided, the IV is the last 12 bytes of the provided text.
    coder::ByteArray ciphertext;
    if (!ivSet) {
        ciphertext = text.range(0, text.getLength() - 12);
        iv = text.range(text.getLength() - 12);
    }
    else {
        ciphertext = text;
    }

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

    if (!ivSet) {
        iv.setLength(12);
        FortunaSecureRandom rnd;
        rnd.nextBytes(iv);
    }

    try {
        GCM gcm(new AES(AES::AES256), true);    // Append the auth tag.
        gcm.setIV(iv);
        gcm.setAuthenticationData(ad);
        text = gcm.encrypt(stream, key);
        if (!ivSet) {
            text.append(iv);                    // Append the IV
        }
    }
    catch (BadParameterException& e) {
        throw EncodingException(e);
    }
    catch (AuthenticationException& e) {
        throw EncodingException("Authentication failer");
    }

}

void GCMCodec::setIV(const coder::ByteArray& i) {

    iv = i;
    ivSet = true;

}

}
