#ifndef CKEXCEPTION_H_INCLUDED
#define CKEXCEPTION_H_INCLUDED

#include <exception>
#include <string>

#ifndef EXCEPTION_THROW_SPEC
#define EXCEPTION_THROW_SPEC throw()
#endif

namespace CK {

class Exception  : public std::exception {

    protected:
        Exception() {}
        Exception(const std::string& msg) : message(msg) {}
        Exception(const Exception& other)
                : message(other.message) {}

    private:
        Exception& operator= (const Exception& other);

    public:
        ~Exception() {}

    public:
        const char *what() const EXCEPTION_THROW_SPEC { return message.c_str(); }

    private:
        std::string message;

};

}

#endif // CKEXCEPTION_H_INCLUDED
