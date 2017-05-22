#ifndef PSSRSASSA_H_INCLUDED
#define PSSRSASSA_H_INCLUDED

#include "../cipher/RSA.h"
#include <coder/ByteArray.h>

namespace CK {

class Digest;

class PSSrsassa : public RSA {

    public:
        PSSrsassa(Digest *digest); // Default salt length 10.
        PSSrsassa(Digest *digest, int sLen);
        ~PSSrsassa();

    private:
        PSSrsassa();
        PSSrsassa(const PSSrsassa& other);
        PSSrsassa& operator= (const PSSrsassa& other);

    public:
        coder::ByteArray decrypt(const RSAPrivateKey& K, const coder::ByteArray& C);
        coder::ByteArray encrypt(const RSAPublicKey& K,
                                const coder::ByteArray& C);
        coder::ByteArray sign(const RSAPrivateKey& K, const coder::ByteArray& M);
        bool verify(const RSAPublicKey& K, const coder::ByteArray& M,
                                const coder::ByteArray& S);

    private:
        coder::ByteArray emsaPSSEncode(const coder::ByteArray&  M, int emLen);
        bool emsaPSSVerify(const coder::ByteArray& M, const coder::ByteArray& EM,
                                                            int emBits);

    private:
        Digest *digest;
        coder::ByteArray algorithmOID;
        int saltLength;

};

}
#endif  // PSSRSASSA_H_INCLUDED
