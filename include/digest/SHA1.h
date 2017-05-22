#ifndef SHA1_H_INCLUDED
#define SHA1_H_INCLUDED

#include "DigestBase.h"

namespace CK {

class SHA1 : public DigestBase {

    public:
        SHA1();
        ~SHA1();

    private:
        SHA1(const SHA1& other);
        SHA1& operator= (const SHA1& other);

    public:
        uint32_t getBlockSize() const { return 20; }
        uint32_t getDigestLength() const { return 20; }

    protected:
        coder::ByteArray finalize(const coder::ByteArray& bytes) const;
        const coder::ByteArray& getDER() const { return DER; }

    private:
        uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) const;
        uint32_t f(uint32_t x, uint32_t y, uint32_t z, uint32_t t) const;
        uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) const;
        coder::ByteArray pad(const coder::ByteArray& in) const;
        uint32_t Parity(uint32_t x, uint32_t y, uint32_t z) const;
        uint32_t rol(uint32_t x, int count) const;
        uint32_t *W(const coder::ByteArray& chunk) const;

    private:
        static const uint32_t H1;
        static const uint32_t H2;
        static const uint32_t H3;
        static const uint32_t H4;
        static const uint32_t H5;

        static const uint32_t K[];

        static const coder::ByteArray DER;

};

}
#endif  // SHA1_H_INCLUDED
