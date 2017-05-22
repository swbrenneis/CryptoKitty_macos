#ifndef GCMCODEC_H_INCLUDED
#define GCMCODEC_H_INCLUDED

#include <coder/ByteStreamCodec.h>

namespace CK {

class GCMCodec : public coder::ByteStreamCodec {

    public:
        GCMCodec();
        GCMCodec(const coder::ByteArray& ciphertext);
        ~GCMCodec();

    public:
        void decrypt(const coder::ByteArray& key, const coder::ByteArray& ad);
        void encrypt(const coder::ByteArray& key, const coder::ByteArray& ad);
        const coder::ByteArray& toArray() const { return text; }

    private:
        coder::ByteArray text;

};

}

#endif /* GCMCODEC_H_INCLUDED */
