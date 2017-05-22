#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

#include "DigestBase.h"
#include <deque>

namespace CK {

/*
 * SHA-256 message digest implementation.
 */
class SHA256 : public DigestBase {

    public:
        SHA256();
        ~SHA256();

    private:
        SHA256(const SHA256& other);
        SHA256& operator= (const SHA256& other);

    public:
        uint32_t getBlockSize() const { return 64; }
        uint32_t getDigestLength() const { return 32; }

    protected:
        coder::ByteArray finalize(const coder::ByteArray& bytes) const;
        const coder::ByteArray& getDER() const;

    private:
        typedef std::deque<uint32_t> W;

    private:
        uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) const;
        W decompose(const coder::ByteArray& chunks) const;
        uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) const;
        coder::ByteArray pad(const coder::ByteArray& in) const;
        uint32_t ror(uint32_t reg, int count) const;
        uint32_t sigma0(uint32_t w) const;
        uint32_t sigma1(uint32_t w) const;
        uint32_t Sigma0(uint32_t w) const;
        uint32_t Sigma1(uint32_t w) const;

    private:
        typedef std::deque<coder::ByteArray> Chunks;

        // Hash constants
        static const uint32_t H1, H2, H3, H4,
                                H5, H6, H7, H8;
        // Round constants
        static const uint32_t K[];
        // ASN.1 identifier encoding.
        static const coder::ByteArray DER;

};

}

#endif  // SHA256_H_INCLUDED
