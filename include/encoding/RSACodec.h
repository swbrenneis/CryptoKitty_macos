#ifndef RSACODEC_H_INCLUDED
#define RSACODEC_H_INCLUDED

#include <coder/ByteStreamCodec.h>

namespace CK {

class RSAPrivateKey;
class RSAPublicKey;

class RSACodec : public coder::ByteStreamCodec {

    public:
        RSACodec();
        RSACodec(const coder::ByteArray& text);
        RSACodec(const RSACodec& other);
        ~RSACodec();

    public:
        void decrypt(const RSAPrivateKey& privateKey);
        void encrypt(const RSAPublicKey& publicKey);
        const coder::ByteArray& toArray() const { return text; }


    private:
        coder::ByteArray text;

};

}

#endif /* RSACODEC_H_INCLUDED */
