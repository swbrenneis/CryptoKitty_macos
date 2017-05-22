#ifndef TCPEXCEPTION_H_INCLUDED
#define TCPEXCEPTION_H_INCLUDED

#include "exceptions/Exception.h"

namespace CK {

class TCPException : public Exception {

    protected:
        TCPException() {}

    public:
        TCPException(const std::string& msg) : Exception(msg) {}
        TCPException(const Exception& other)
                : Exception(other) {}

    private:
        TCPException& operator= (const TCPException& other);

    public:
        ~TCPException() {}

};

}

#endif // TCPEXCEPTION_H_INCLUDED
