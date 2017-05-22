#ifndef PKCS1RSAES_H_INCLUDED
#define PKCS1RSAES_H_INCLUDED

#include "cipher/RSA.h"

namespace CK {

class PKCS1rsaes : public RSA {

    public:
        PKCS1rsaes();
        ~PKCS1rsaes();

    private:
        PKCS1rsaes(const PKCS1rsaes& other);
        PKCS1rsaes& operator= (const PKCS1rsaes& other);

};

}

#endif  // PKCS1RSAES_H_INCLUDED
