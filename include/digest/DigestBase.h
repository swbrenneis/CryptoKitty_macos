#ifndef DIGESTBASE_H_INCLUDED
#define DIGESTBASE_H_INCLUDED

#include "Digest.h"
#include <string>

namespace CK {

/*
 * Digest base implementation class.
 * The class is abstract. Also includes a convenience method
 * for creating instances by name.
 */
class DigestBase : public Digest {

    protected:
        DigestBase();

    private:
        DigestBase(const DigestBase& other);
        DigestBase& operator= (const DigestBase& other);

    public:
        virtual ~DigestBase();

    public:
        coder::ByteArray digest();
        coder::ByteArray digest(const coder::ByteArray& bytes);
        void reset();
        void update(uint8_t byte);
        void update(const coder::ByteArray& bytes);
        void update(const coder::ByteArray& bytes, uint32_t offset, uint32_t length);

    public:
        static Digest* getInstance(const std::string& algorithm);

    private:
        coder::ByteArray accumulator;

};

}

#endif  // DIGESTBASE_H_INCLUDED
