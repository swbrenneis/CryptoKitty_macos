#include "ciphermodes/CTR.h"
#include "cipher/BlockCipher.h"
#include "exceptions/BadParameterException.h"
#include "coder/Unsigned64.h"
#include <cmath>

namespace CK {

CTR::CTR(BlockCipher *c)
: cipher(c) {
}

CTR::~CTR() {

    delete cipher;

}

coder::ByteArray CTR::decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key) {

    coder::ByteArray P;

    double cs = ciphertext.getLength();
    uint32_t blockSize = cipher->blockSize();
    uint32_t blockCount = ceil(cs / blockSize);

    for (unsigned i = 0; i < blockCount; ++i) {
        uint32_t index = i * blockSize;
        incrementCounter();
        coder::ByteArray pBlock(cipher->encrypt(counter, key));
        if (index + blockSize < ciphertext.getLength()) { // Whole block
            P.append(pBlock ^ ciphertext.range(index, blockSize));
        }
        else {          // Partial block, xor with encrypted counter LSB
            coder::ByteArray partial(ciphertext.range(index, ciphertext.getLength() - index));
            coder::ByteArray pctr(pBlock.range(0, partial.getLength()));
            P.append(partial ^ pctr);
        }
    }

    return P;

}

coder::ByteArray CTR::encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key) {

    coder::ByteArray C;

    double ps = plaintext.getLength();
    uint32_t blockSize = cipher->blockSize();
    uint32_t blockCount = ceil(ps / blockSize);

    for (unsigned i = 0; i < blockCount; ++i) {
        uint32_t index = i * blockSize;
        incrementCounter();
        coder::ByteArray cBlock(cipher->encrypt(counter, key));
        if (index + blockSize < plaintext.getLength()) { // Whole block
            C.append(cBlock ^ plaintext.range(index, blockSize));
        }
        else {          // Partial block, xor with encrypted counter LSB
            coder::ByteArray partial(plaintext.range(index, plaintext.getLength() - index));
            coder::ByteArray pctr(cBlock.range(0, partial.getLength()));
            C.append(partial ^ pctr);
        }
    }

    return C;

}

void CTR::incrementCounter() {

    coder::ByteArray nonce(counter.range(0, counter.getLength() - 4));
    coder::Unsigned64 ctr(counter.range(nonce.getLength(), 4));
    counter.clear();
    ctr.setValue(ctr.getValue() + 1);
    counter.append(nonce);
    counter.append(ctr.getEncoded(coder::bigendian));

}

void CTR::setIV(const coder::ByteArray& iv) {

    if (iv.getLength() != cipher->blockSize() - 8) {
        throw BadParameterException("Invalid nonce size");
    }

    counter = iv;
    coder::ByteArray ctr(8,0);
    ctr[7] = 1;
    counter.append(ctr);

}

}

