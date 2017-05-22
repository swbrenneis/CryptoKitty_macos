#ifndef DERCODEC_H_INCLUDED
#define DERCODEC_H_INCLUDED

#include <coder/ByteArray.h>

namespace coder {
    class ByteArrayInputStream;
    class ByteArrayOutputStream;
}

namespace CK {

class RSAPublicKey;
class RSAPrivateCrtKey;

class DERCodec {

    public:
        DERCodec();
        ~DERCodec();

    private:
        DERCodec(const DERCodec& other);
        DERCodec& operator= (const DERCodec& other);

    public:
        void encodeAlgorithm(coder::ByteArrayOutputStream& algorithm);
        void encodeBitString(coder::ByteArrayOutputStream& out,
                                                        const coder::ByteArray& data);
        void encodeInteger(coder::ByteArrayOutputStream& out,
                                                        const coder::ByteArray& data);
        void encodeOctetString(coder::ByteArrayOutputStream& out,
                                                        const coder::ByteArray& data);
        void encodeSequence(coder::ByteArrayOutputStream& out,
                                                        const coder::ByteArray& data);
        void getBitString(coder::ByteArrayInputStream& source, 
                                                coder::ByteArrayOutputStream& bitstring);
        void getInteger(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& integer);
        void getOctetString(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& octetstring);
        void getSegment(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& segment);
        void getSequence(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& sequence);
        void parseAlgorithm(coder::ByteArrayInputStream& source);

    private:
        void setLength(coder::ByteArrayOutputStream& out, unsigned length);

    private:
        coder::ByteArray rsa_oid;
        coder::ByteArray der_null;

};

}

#endif // DERCODEC_H_INCLUDED

