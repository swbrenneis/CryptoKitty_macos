#ifndef BADPARAMETEREXCEPTION_H_INCLUDED
#define BADPARAMETEREXCEPTION_H_INCLUDED

#include "Exception.h"

namespace CK {

class BadParameterException : public Exception {

    protected:
        BadParameterException() {}

    public:
        BadParameterException(const std::string& msg) : Exception(msg) {}
        BadParameterException(const BadParameterException& other)
                : Exception(other) {}

    private:
        BadParameterException& operator= (const BadParameterException& other);

    public:
        ~BadParameterException() {}

};

}

#endif // BADPARAMETEREXCEPTION_H_INCLUDED
