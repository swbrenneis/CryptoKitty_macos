#ifndef NOSUCHALGORITHMEXCEPTION_H_INCLUDED
#define NOSUCHALGORITHMEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"
#include <string>

namespace CK {

class NoSuchAlgorithmException : public Exception {

    protected:
        NoSuchAlgorithmException() {}

    public:
        NoSuchAlgorithmException(const std::string& msg) : Exception(msg) {}
        NoSuchAlgorithmException(const NoSuchAlgorithmException& other)
                : Exception(other) {}

    private:
        NoSuchAlgorithmException& operator= (const NoSuchAlgorithmException& other);

    public:
        ~NoSuchAlgorithmException() {}

};

}

#endif // NOSUCHALGORITHMEXCEPTION_H_INCLUDED
