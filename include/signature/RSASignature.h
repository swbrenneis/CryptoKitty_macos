#ifndef RSASIGNATURE_H_INCLUDED
#define RSASIGNATURE_H_INCLUDED

#include <coder/ByteArray.h>
#include "../keys/RSAPublicKey.h"
#include "../keys/RSAPrivateKey.h"

namespace CK {

class RSA;

/*
 * Signature class. The template parameter, C, refers to the RSA
 * padded cipher type, and parameter D refers to the digest type.
 `*/
template<class C, class D> class RSASignature {

    public:
        RSASignature();
        RSASignature(int saltLength);
        ~RSASignature();

    public:
        virtual void initVerify(RSAPublicKey* publicKey);
        virtual void initSign(RSAPrivateKey* privateKey);
        virtual coder::ByteArray sign();
        virtual void update(unsigned char b);
        virtual void update(const coder::ByteArray& bytes);
        virtual void update(const coder::ByteArray& bytes, int offset, int length);
        virtual bool verify(const coder::ByteArray& sig);

    private:
        RSAPublicKey* publicKey;
        RSAPrivateKey* privateKey;
        bool signInit;
        bool verifyInit;
        coder::ByteArray accumulator;
        RSA *cipher;

};

}

#endif  // RSASIGNATURE_H_INCLUDED
