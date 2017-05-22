#ifndef BASE64_H_INCLUDED
#define BASE64_H_INCLUDED

#include <coder/ByteArray.h>
#include <string>
#include <iostream>

namespace CK {

class Base64 {

    public:
        Base64();
        Base64(const coder::ByteArray& data);
        ~Base64();

    private:
        Base64(const Base64& other);
        Base64& operator= (const Base64& other);

    public:
        void decode(std::istream& in);
        void encode(std::ostream& out);
        const coder::ByteArray& getData() const { return data; }
        const std::string& getLastLine() const { return lastLine; }

    private:
        int decodeQuartet(uint8_t *content, char *b64);
        void encodeTriplet(uint8_t *content, int tsize, char *b64);

    private:
        bool pem;
        coder::ByteArray data;
        std::string lastLine;

};

}

#endif // BASE64_H_INCLUDED

