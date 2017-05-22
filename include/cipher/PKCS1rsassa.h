#ifndef PKCS1RSASSA_H_INCLUDED
#define PKCS1RSASSA_H_INCLUDED

#include "RSA.h"

namespace CK {

class Digest;

class PKCS1rsassa : public RSA {

    public:
        PKCS1rsassa(Digest *digest);
        PKCS1rsassa(Digest *digest, int saltLength);
        ~PKCS1rsassa();

    private:
        PKCS1rsassa();
        PKCS1rsassa(const PKCS1rsassa& other);
        PKCS1rsassa& operator= (const PKCS1rsassa& other);

    public:
        coder::ByteArray decrypt(const RSAPrivateKey& K, const coder::ByteArray& C);
        coder::ByteArray encrypt(const RSAPublicKey& K,
                                const coder::ByteArray& C);
        coder::ByteArray sign(const RSAPrivateKey& K, const coder::ByteArray& M);
        bool verify(const RSAPublicKey& K, const coder::ByteArray& M,
                                const coder::ByteArray& S);

    private:
        coder::ByteArray emsaPKCS1Encode(const coder::ByteArray&  M, int emLen);

    private:
        Digest *digest;
        coder::ByteArray algorithmOID;

};

}
#endif  // PKCS1RSASSA_H_INCLUDED
