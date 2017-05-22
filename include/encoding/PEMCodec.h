#ifndef PEMCODEC_H_INCLUDED
#define PEMCODEC_H_INCLUDED

#include <iostream>
#include <string>
#include <cstdint>

namespace coder {
    class ByteArray;
    class ByteArrayInputStream;
    class ByteArrayOutputStream;
}

namespace CK {

class RSAPublicKey;
class RSAPrivateCrtKey;
class RSAPrivateModKey;
class RSAPrivateKey;
class DERCodec;

class PEMCodec {

    public:
        PEMCodec();
        PEMCodec(bool x509Keys);
        ~PEMCodec();

    private:
        PEMCodec(const PEMCodec& other);
        PEMCodec& operator= (const PEMCodec& other);

    public:
        RSAPrivateKey *decodePrivateKey(const std::string& keyString);
        RSAPublicKey *decodePublicFromPrivate(const std::string& keyString);
        RSAPublicKey *decodePublicKey(const std::string& keyString);
        void encode(std::ostream& out, const RSAPublicKey& key);
        void encode(std::ostream& out, const RSAPrivateKey& privateKey,
                                        const RSAPublicKey& publicKey);

    private:
        void encodeMultiprimeKey(coder::ByteArrayOutputStream& out,
                                                    const RSAPrivateCrtKey& privateKey,
                                                    const RSAPublicKey& publicKey);
        void encodePrimes(coder::ByteArrayOutputStream& out,
                                                    const RSAPrivateModKey& privateKey);
        void encodePrimes(coder::ByteArrayOutputStream& out,
                                                    const RSAPrivateCrtKey& privateKey,
                                                    const RSAPublicKey& publicKey);
        void encodePublicKey(coder::ByteArrayOutputStream& out,
                                                    const RSAPublicKey& key);
        void encodeTwoPrimeKey(coder::ByteArrayOutputStream& out,
                                                    const RSAPrivateModKey& privateKey);
        RSAPrivateKey *getPrivateKey(coder::ByteArrayInputStream& key);
        RSAPublicKey *getPublicFromPrivate(coder::ByteArrayInputStream& key);
        RSAPublicKey *getPublicKey(coder::ByteArrayInputStream& key);
        RSAPrivateKey *parsePrivateKey(coder::ByteArrayInputStream& key);
        RSAPublicKey *parsePublicFromPrivate(coder::ByteArrayInputStream& key);
        RSAPublicKey *parsePublicKey(coder::ByteArrayInputStream& key);

    private:
        bool x509Keys;
        DERCodec *derCodec;

};

}

#endif // PEMCODEC_H_INCLUDED

