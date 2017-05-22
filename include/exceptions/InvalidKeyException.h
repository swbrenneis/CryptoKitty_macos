#ifndef INVALIDKEYEXCEPTION_H_INCLUDED
#define INVALIDKEYEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"

namespace CK {

class InvalidKeyException : public Exception {

    protected:
        InvalidKeyException() {}

    public:
        InvalidKeyException(const std::string& msg) : Exception(msg) {}

    private:
        InvalidKeyException(const InvalidKeyException& other);
        InvalidKeyException& operator= (const InvalidKeyException& other);

    public:
        ~InvalidKeyException() {}

};

}

#endif // INVALIDKEYEXCEPTION_H_INCLUDED
