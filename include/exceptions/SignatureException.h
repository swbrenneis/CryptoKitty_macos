#ifndef SIGNATUREEXCEPTION_H_INCLUDED
#define SIGNATUREEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"

namespace CK {

class SignatureException : public Exception {

    protected:
        SignatureException() {}

    public:
        SignatureException(const std::string& msg) : Exception(msg) {}
        SignatureException(const SignatureException& other)
                : Exception(other) {}

    private:
        SignatureException& operator= (const SignatureException& other);

    public:
        ~SignatureException() {}

};

}

#endif // SIGNATUREEXCEPTION_H_INCLUDED
