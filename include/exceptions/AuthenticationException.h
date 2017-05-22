#ifndef AUTHENTICATIONEXCEPTION_H_INCLUDED
#define AUTHENTICATIONEXCEPTION_H_INCLUDED

#include "Exception.h"

namespace CK {

class AuthenticationException : public Exception {

    protected:
        AuthenticationException() {}

    public:
        AuthenticationException(const std::string& msg) : Exception(msg) {}
        AuthenticationException(const Exception& other)
                : Exception(other) {}

    private:
        AuthenticationException& operator= (const AuthenticationException& other);

    public:
        ~AuthenticationException() {}

};

}

#endif // AUTHENTICATIONEXCEPTION_H_INCLUDED
