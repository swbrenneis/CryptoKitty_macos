#ifndef SECURERANDOMEXCEPTION_H_INCLUDED
#define SECURERANDOMEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"

namespace CK {

class SecureRandomException : public Exception {

    protected:
        SecureRandomException() {}

    public:
        SecureRandomException(const std::string& msg) : Exception(msg) {}
        SecureRandomException(const SecureRandomException& other)
                : Exception(other) {}

    private:
        SecureRandomException& operator= (const SecureRandomException& other);

    public:
        ~SecureRandomException() {}

};

}

#endif // SECURERANDOMEXCEPTION_H_INCLUDED
