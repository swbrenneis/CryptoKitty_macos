#ifndef SECURERANDOM_H_INCLUDED
#define SECURERANDOM_H_INCLUDED

#include "Random.h"
#include <string>

namespace CK {

class SecureRandom : public Random {

    protected:
        SecureRandom() {}

    public:
        virtual ~SecureRandom() {}

};

}

#endif	// SECURERANDOM_H_INCLUDED
