#ifndef OUTOFRANGEEXCEPTION_H_INCLUDED
#define OUTOFRANGEEXCEPTION_H_INCLUDED

#include "Exception.h"

namespace CK {

class OutOfRangeException : public Exception {

    protected:
        OutOfRangeException() {}

    public:
        OutOfRangeException(const std::string& msg) : Exception(msg) {}
        OutOfRangeException(const OutOfRangeException& other)
                : Exception(other) {}

    private:
        OutOfRangeException& operator= (const OutOfRangeException& other);

    public:
        ~OutOfRangeException() {}

};

}

#endif // OUTOFRANGEEXCEPTION_H_INCLUDED
