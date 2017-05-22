#ifndef RANDOM_H_INCLUDED
#define RANDOM_H_INCLUDED

#include <cstdint>

namespace coder {
    class ByteArray;
}

namespace CK {

/*
 * Random number generator.
 * This class is largely unimplemented. It is intended
 * that there will be a subclass that provides the
 * actual PRNG.
 */
class Random {

    protected:
        Random();

    public:
        virtual ~Random();

    private:
        Random(const Random& other);
        Random& operator= (const Random& other);

    public:
        virtual void nextBytes(coder::ByteArray& bytes);
        virtual uint32_t nextUnsignedInt();
        virtual uint64_t nextUnsignedLong();

    public:
        virtual void setSeed(uint64_t seedValue);

    protected:
        virtual uint64_t next(int bits);

};

}

#endif  // RANDOM_H_INCLUDED
