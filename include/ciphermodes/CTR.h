#ifndef CTR_H_INCLUDED
#define CTR_H_INCLUDED

#include "BlockCipherMode.h"

namespace CK {

class BlockCipher;

class CTR : public BlockCipherMode {

    public:
        CTR(BlockCipher *cipher);
        ~CTR();

    private:
        CTR(const CTR& other);
        CTR& operator= (const CTR& other);

    public:
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key);
        void setIV(const coder::ByteArray& iv);

    private:
        void incrementCounter();

    private:
        BlockCipher *cipher;
        coder::ByteArray counter;

};

}

#endif  // CTR_H_INCLUDED
