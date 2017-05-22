#ifndef GCM_H_INCLUDED
#define GCM_H_INCLUDED

#include "AEADCipherMode.h"
#include "../data/BigInteger.h"
#include <cstdint>

namespace CK {

class BlockCipher;

/*
 * Galois Counter Mode stream AEAD cipher mode.
 * See RFC-5288.
 */
class GCM : public AEADCipherMode {

    public:
        GCM(BlockCipher* c, bool appendTag);
        ~GCM();

    private:
        GCM(const GCM& other);
        GCM& operator= (const GCM& other);

    public:
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key);
        const coder::ByteArray& getAuthTag() const;
        void setAuthenticationData(const coder::ByteArray& ad);
        void setAuthTag(const coder::ByteArray& tag);
        void setIV(const coder::ByteArray& iv) { IV = iv; }

    private:
        coder::ByteArray GHASH(const coder::ByteArray& H, const coder::ByteArray& A,
                                                const coder::ByteArray& C) const;
        coder::ByteArray incr(const coder::ByteArray& X) const;
        coder::ByteArray multiply(const coder::ByteArray& X, const coder::ByteArray& Y) const;
        void setTagSize(uint8_t t) { tagSize = t; }
        void shiftBlock(coder::ByteArray& block) const;

    private:
        uint8_t tagSize;        // Authentication tag size
        bool appendTag;      // True = append tag to ciphertext
        struct GCMNonce {
            uint8_t salt[4];
            uint8_t nonce_explicit[8];
        };
        BlockCipher *cipher;
        coder::ByteArray T;    // Authentication tag
        coder::ByteArray IV;   // Initial value
        coder::ByteArray A;    // Authenticated data

};

}

#endif  // GCM_H_INCLUDED
