#ifndef MTE_H_INCLUDED
#define MTE_H_INCLUDED

#include "BlockCipherMode.h"

namespace CK {

class HMAC;

class MtE : public BlockCipherMode {

    public:
        MtE(BlockCipherMode *c, HMAC* h);
        ~MtE();

    private:
        MtE(const MtE& other);
        MtE& operator= (const MtE& other);

    public:
        bool authenticate() { return authenticated; }
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext,
                                            const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext,
                                            const coder::ByteArray& key);
        void setIV(const coder::ByteArray& iv) {}

    private:
        unsigned blockSize;
        BlockCipherMode *cipher;
        HMAC *hmac;
        bool authenticated;


};

}

#endif  // MTE_H_INCLUDED
