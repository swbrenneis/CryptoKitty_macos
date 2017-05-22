#ifndef DECRYPTIONEXCEPTION_H_INCLUDED
#define DECRYPTIONEXCEPTION_H_INCLUDED

#include "Exception.h"

namespace CK {

class DecryptionException : public Exception {

    public:
        // No oracles please.
        DecryptionException() : Exception("Decryption failed") {}
        DecryptionException(const Exception& other)
                : Exception(other) {}

    private:
        DecryptionException& operator= (const DecryptionException& other);

    public:
        ~DecryptionException() {}

};

}

#endif // DECRYPTIONEXCEPTION_H_INCLUDED
