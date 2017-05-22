#include "random/Random.h"
#include "coder/ByteArray.h"
#include <climits>
#include <cmath>

namespace CK {

/*
 * This is mostly used as a base class. It provides
 * a value from the built-in OS RNG. It is not a secure
 * PRNG.
 */
Random::Random() {
}

Random::~Random() {
}

/*
 * Returns a value from the system PRNG. If bits is greater
 * than the long word size, the maximum available
 * bits will be returned.
 */
uint64_t Random::next(int bits) {

    uint64_t rnd = random();
    uint64_t mask = 1 << bits;
    return rnd & mask;
    
}

/*
 * Return a series of random bytes. The length of the series
 * is determined by the length of the coder::ByteArray object.
 */
void Random::nextBytes(coder::ByteArray& bytes) {

    // Bit length.
    int l = bytes.getLength() * 8;
    int lSize = sizeof(long) * 8;
    unsigned index = 0;
    while (l > 0) {
        int getBits = std::min(l, lSize);
        uint64_t rnd = next(getBits);
        int shifted = lSize;
        while (shifted > 0 && l > 0 && index < bytes.getLength()) {
            bytes[index++] = rnd & 0xff;
            rnd = rnd >> 8;
            shifted -= 8;
            l-= 8;
        }
    }
}

/*
 * Return a random unsigned integer;
 */
uint32_t Random::nextUnsignedInt() {

    return next(sizeof(uint32_t) * 8) & ULONG_MAX;

}

/*
 * Return a random signed long integer.
 */
uint64_t Random::nextUnsignedLong() {

    return next(sizeof(uint64_t) * 8);

}

/*
 * Does nothing.
 */
void Random::setSeed(uint64_t newSeed) {
}

}

