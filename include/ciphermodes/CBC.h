#ifndef CBC_H_INCLUDED
#define CBC_H_INCLUDED

#include "BlockCipherMode.h"

namespace CK {

class BlockCipher;

class CBC : public BlockCipherMode {

    public:
        CBC(BlockCipher *c);
        ~CBC();

    private:
        CBC(const CBC& other);
        CBC& operator= (const CBC& other);

    public:
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext,
                                            const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext,
                                            const coder::ByteArray& key);
        void setIV(const coder::ByteArray& iv);

    private:
        coder::ByteArray decrypt(const coder::ByteArray& iv, const coder::ByteArray& block,
                                            const coder::ByteArray& key) const;
        coder::ByteArray encrypt(const coder::ByteArray& iv, const coder::ByteArray& block,
                                            const coder::ByteArray& key) const;

    private:
        unsigned blockSize;
        BlockCipher *cipher;
        coder::ByteArray iv;

};

}

#endif  // CBC_H_INCLUDED
