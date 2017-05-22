#ifndef CMWCRANDOM_H_INCLUDED
#define CMWCRANDOM_H_INCLUDED

#include "Random.h"
#include <deque>

namespace CK {
/*
 * Complimentary Multiply With Carry entropy generator
 * Geroge Marsaglia et al.
 */
class CMWCRandom : public Random {

    public:
        CMWCRandom();
        CMWCRandom(uint64_t seed);

    private:    // No copying or assignment allowed
        CMWCRandom(const CMWCRandom& other);
        CMWCRandom& operator= (const CMWCRandom& other);

    public:
        ~CMWCRandom();

    public:
        void setSeed(uint64_t seedValue);

    protected:
        virtual uint64_t next(int bits);

    private:
        long cmwc4096();
        void seedGenerator();

    private:
        uint64_t seed; // Seed generator nonce.
        uint64_t c; // Reset mask.
        typedef std::deque<uint64_t> Q;    // Seed
        Q q;

        static uint32_t i;  // Seed selector.
        static const uint64_t A;
        static const uint64_t R;

};

}

#endif // CMWCRANDOM_H_INCLUDED
