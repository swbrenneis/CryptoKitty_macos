#include "ciphermodes/CBC.h"
#include "cipher/BlockCipher.h"
#include "exceptions/BadParameterException.h"
#include <deque>

namespace CK {

CBC::CBC(BlockCipher *c)
: cipher(c) {

    blockSize = cipher->blockSize();

}

CBC::~CBC() {
        
    delete cipher;

}

coder::ByteArray CBC::decrypt(const coder::ByteArray& iv, const coder::ByteArray& block,
                                            const coder::ByteArray& key) const {

    coder::ByteArray textblock(cipher->decrypt(block, key));
    return textblock ^ iv;

}

coder::ByteArray CBC::encrypt(const coder::ByteArray& iv, const coder::ByteArray& block,
                                            const coder::ByteArray& key) const {

    return cipher->encrypt(iv ^ block, key);

}

coder::ByteArray CBC::decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key) {

    coder::ByteArray plaintext;
    coder::ByteArray padded;
    unsigned textSize = ciphertext.getLength();
    unsigned blockOffset = 0;
    coder::ByteArray cblock;
    if (textSize % blockSize != 0) {
        while (textSize > blockSize) {
            cblock = ciphertext.range(blockOffset, blockSize);
            textSize -= blockSize;
            blockOffset += blockSize;
        }
        // Decrypt second to last block.
        coder::ByteArray padBlock(cipher->decrypt(cblock, key));
        // Get padding bits.
        coder::ByteArray padBytes(padBlock.range(textSize, blockSize - textSize));
        padded = ciphertext;
        // Pad the original ciphertext.
        padded.append(padBytes);
        // Extract the last 2 blocks.
        coder::ByteArray b1(padded.range(padded.getLength()-(blockSize*2), blockSize));
        coder::ByteArray b2(padded.range(padded.getLength()-(blockSize), blockSize));
        // Swap blocks.
        padded = padded.range(0, padded.getLength()-(blockSize*2));
        padded.append(b2);
        padded.append(b1);
    }
    else {
        padded = ciphertext;
    }
    textSize = padded.getLength();
    blockOffset = 0;
    coder::ByteArray input(iv);
    while (textSize > 0) {
        coder::ByteArray cipherblock(padded.range(blockOffset, blockSize));
        coder::ByteArray plainblock(decrypt(input, cipherblock, key));
        plaintext.append(plainblock);
        input = cipherblock;
        blockOffset += blockSize;
        textSize -= blockSize;
    }
    return plaintext.range(0, ciphertext.getLength());

}

coder::ByteArray CBC::encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key) {

    coder::ByteArray ciphertext;
    coder::ByteArray padded(plaintext);
    // plaintext is padded. Need to steal cipherbits
    bool steal = padded.getLength() % blockSize != 0;
    while (padded.getLength() % blockSize != 0) {
        padded.append(0);
    }
    unsigned textLength = padded.getLength();
    coder::ByteArray input = iv;
    coder::ByteArray cipherblock;
    std::deque<coder::ByteArray> blocks;
    unsigned blockStart = 0;
    while (textLength > 0) {
        coder::ByteArray plainblock(padded.range(blockStart, blockSize));
        coder::ByteArray cipherblock(encrypt(input, plainblock, key));
        input = cipherblock;
        blocks.push_back(cipherblock);
        blockStart += blockSize;
        textLength -= blockSize;
    }

    if (steal) {
        // Swap last two blocks
        coder::ByteArray cn(blocks.back());
        blocks.pop_back();
        coder::ByteArray cn1(blocks.back());
        blocks.pop_back();
        blocks.push_back(cn);
        blocks.push_back(cn1);
    }

    while (blocks.size() > 0) {
        ciphertext.append(blocks.front());
        blocks.pop_front();
    }

    return ciphertext.range(0, plaintext.getLength());

}

void CBC::setIV(const coder::ByteArray& nonce) {

    iv = nonce;
    if (iv.getLength() != blockSize) {
        throw BadParameterException("CBC Invalid IV");
    }

}

}
