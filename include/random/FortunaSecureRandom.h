#ifndef FORTUNASECURERANDOM_H_INCLUDED
#define FORTUNASECURERANDOM_H_INCLUDED

#include "SecureRandom.h"
#include "../data/BigInteger.h"
#include "coder/ByteArray.h"

namespace CK {

class FortunaGenerator;

class FortunaSecureRandom : public SecureRandom {

    public:
        FortunaSecureRandom();
        ~FortunaSecureRandom();

    public:
        void nextBytes(coder::ByteArray& bytes);
        uint32_t nextUnsignedInt();
        uint64_t nextUnsignedLong();

    private:
        uint16_t readBytes(coder::ByteArray& bytes, uint16_t count) const;

};

}

#endif  // FORTUNASECURERANDOM_H_INCLUDED
