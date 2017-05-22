#ifndef DATAEXCEPTION_H_INCLUDED
#define DATAEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"

namespace CK {

class DataException : public Exception {

    protected:
        DataException() {}

    public:
        DataException(const std::string& msg) : Exception(msg) {}
        DataException(const Exception& other)
                : Exception(other) {}

    private:
        DataException& operator= (const DataException& other);

    public:
        ~DataException() {}

};

}

#endif // DATAEXCEPTION_H_INCLUDED
