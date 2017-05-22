#ifndef SHA384_H_INCLUDED
#define SHA384_H_INCLUDED

#include "DigestBase.h"

#include <deque>

namespace CK {
        
/*
 * SHA-384 message digest implementation.
 */
class SHA384 : public DigestBase {

    public:
        SHA384();
        ~SHA384();

    private:
        SHA384(const SHA384& other);
        SHA384& operator= (const SHA384& other);

    public:
        uint32_t getBlockSize() const { return 64; }
        uint32_t getDigestLength() const { return 48; }

    protected:
        coder::ByteArray finalize(const coder::ByteArray& bytes) const;
        const coder::ByteArray& getDER() const;

    private:
        typedef std::deque<uint64_t> W;
        
    private:
        uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) const;
        W decompose(const coder::ByteArray& chunks) const;
        uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) const;
        coder::ByteArray pad(const coder::ByteArray& in) const;
        uint64_t ror(uint64_t reg, int count) const;
        uint64_t sigma0(uint64_t w) const;
        uint64_t sigma1(uint64_t w) const;
        uint64_t Sigma0(uint64_t w) const;
        uint64_t Sigma1(uint64_t w) const;

    private:
        typedef std::deque<coder::ByteArray> Chunks;

        // Hash constants
        static const uint64_t H1, H2, H3, H4,
                                H5, H6, H7, H8;
        // Round constants
        static const uint64_t K[];
        // ASN.1 identifier encoding.
        static const coder::ByteArray DER;

};

}

#endif  // SHA384_H_INCLUDED
