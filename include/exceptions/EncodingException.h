#ifndef ENCODINGEXCEPTION_H_INCLUDED
#define ENCODINGEXCEPTION_H_INCLUDED

#include "Exception.h"

namespace CK {

class EncodingException : public Exception {

    protected:
        EncodingException() {}

    public:
        EncodingException(const std::string& msg) : Exception(msg) {}
        EncodingException(const Exception& other)
                : Exception(other) {}

    private:
        EncodingException& operator= (const EncodingException& other);

    public:
        ~EncodingException() {}

};

}

#endif // ENCODINGEXCEPTION_H_INCLUDED
