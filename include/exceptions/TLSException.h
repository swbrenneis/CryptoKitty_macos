#ifndef TLSEXCEPTION_H_INCLUDED
#define TLSEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"

namespace CK {

class TLSException : public Exception {

    protected:
        TLSException() {}

    public:
        TLSException(const std::string& msg) : Exception(msg) {}
        TLSException(const Exception& other)
                : Exception(other) {}

    private:
        TLSException& operator= (const TLSException& other);

    public:
        ~TLSException() {}

};

}

#endif // TLSEXCEPTION_H_INCLUDED
