#include "encoding/Base64.h"
#include "exceptions/EncodingException.h"
#include <algorithm>
#include <memory>
#include <cstring>

namespace CK {

static const std::string
    ALPHABET("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
static const int BUFSIZE = 100;

Base64::Base64()
: pem(false) {
}

Base64::Base64(const coder::ByteArray& d)
: pem(false),
  data(d) {
}

Base64::~Base64() {
}

void Base64::decode(std::istream& in) {

    data.clear();

    std::unique_ptr<char[]> buf(new char[BUFSIZE]);
    char quartet[4];
    uint8_t triplet[3];

    in.getline(buf.get(), BUFSIZE);
    if (*(buf.get()) == '-') {
        pem = true;
        in.getline(buf.get(), BUFSIZE);
    }
    while (!in.eof()) {
        if (*(buf.get()) == '-') {
            if (!pem) {
                throw EncodingException("Illegal base 64 value");
            }
            lastLine = std::string(buf.get());
        }
        else {
            int length = strlen(buf.get());
            int index = 0;
            while (index < length) {
                memset(quartet, 0, 4);
                // Get 4 character substrings.
                for (int n = 0; n < 4 && index < length; ++n) {
                    quartet[n] = *(buf.get() + index++);
                }
                memset(triplet, 0, 3);
                int tbytes = decodeQuartet(triplet, quartet);
                data.append(triplet, tbytes);
            }
        }
        in.getline(buf.get(), BUFSIZE);
    }

}

int Base64::decodeQuartet(uint8_t *content, char *b64) {

    uint8_t letter = ALPHABET.find(b64[0]);
    content[0] = letter << 2;

    letter = ALPHABET.find(b64[1]);
    content[0] |= (letter & 0x30) >> 4;

    content[1] = (letter & 0x0f) << 4;

    if (b64[2] == '=') {
        // There will be two padding characters, one decoded byte.
        return 1;
    }

    letter = ALPHABET.find(b64[2]);
    content[1] |= letter >> 2;
    content[2] = (letter & 0x03) << 6;

    if (b64[3] == '=') {
        return 2;
    }

    letter = ALPHABET.find(b64[3]);
    content[2] |= letter;

    return 3;

}

void Base64::encode(std::ostream& out) {

    char b64[5];
    uint8_t triplet[3];

    int index = 0;
    int column = 0;
    int length = data.getLength();
    while (index < length) {
        memset(b64, 0, 5);
        memset(triplet, 0, 3);
        int tsize = 0;
        for (int n = 0; n < 3 && index < length; ++n) {
            triplet[n] = data[index++];
            tsize++;
        }
        encodeTriplet(triplet, tsize, b64);
        out << b64;
        column += 4;
        if (column >= 64) {
            out << std::endl;
            column = 0;
        }
    }
    if (column != 0) {
        out << std::endl;
    }

}

void Base64::encodeTriplet(uint8_t *content, int tsize, char *b64) {

    int letter = content[0] >> 2;
    b64[0] = ALPHABET[letter];

    letter = (content[0] & 0x03) << 4;

    if (tsize > 1) {
        letter |= (content[1] >> 4);
        b64[1] = ALPHABET[letter];

        letter = (content[1] & 0x0f)  << 2;

        if (tsize > 2) {
            letter |= (content[2] & 0xc0) >> 6;
            b64[2] = ALPHABET[letter];

            letter = content[2] & 0x3F;
            b64[3] = ALPHABET[letter];
        }
        else {
            b64[2] = ALPHABET[letter];
            b64[3] = '=';
        }
    }
    else {
        b64[1] = ALPHABET[letter];
        b64[2] = '=';
        b64[3] = '=';
    }

}

}

