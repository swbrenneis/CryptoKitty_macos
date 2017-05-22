#include "encoding/PEMCodec.h"
#include "encoding/DERCodec.h"
#include "encoding/Base64.h"
#include "data/BigInteger.h"
#include "keys/RSAPublicKey.h"
#include "keys/RSAPrivateCrtKey.h"
#include "keys/RSAPrivateModKey.h"
#include "exceptions/EncodingException.h"
#include <coder/ByteArray.h>
#include <coder/ByteArrayInputStream.h>
#include <coder/ByteArrayOutputStream.h>
#include <coder/Unsigned16.h>
#include <coder/Unsigned32.h>
#include <sstream>

namespace CK {

static const std::string RSA_PUBLIC_PREAMBLE("-----BEGIN RSA PUBLIC KEY-----");
static const std::string RSA_PUBLIC_EPILOGUE("-----END RSA PUBLIC KEY-----");
static const std::string PUBLIC_PREAMBLE("-----BEGIN PUBLIC KEY-----");
static const std::string PUBLIC_EPILOGUE("-----END PUBLIC KEY-----");
static const std::string RSA_PRIVATE_PREAMBLE("-----BEGIN RSA PRIVATE KEY-----");
static const std::string RSA_PRIVATE_EPILOGUE("-----END RSA PRIVATE KEY-----");
static const std::string PRIVATE_PREAMBLE("-----BEGIN PRIVATE KEY-----");
static const std::string PRIVATE_EPILOGUE("-----END PRIVATE KEY-----");

static const coder::ByteArray TWO_PRIME_VERSION(1, 0);
static const coder::ByteArray MULTIPRIME_VERSION(1, 1);

PEMCodec::PEMCodec()
: x509Keys(false),
  derCodec(0) {
}

PEMCodec::PEMCodec(bool x509)
: x509Keys(x509),
  derCodec(0) {
}

PEMCodec::~PEMCodec() {

    delete derCodec;

}

RSAPrivateKey *PEMCodec::decodePrivateKey(const std::string& keyString) {

    if (keyString.find(RSA_PRIVATE_PREAMBLE) == 0) {
        x509Keys = false;
    }
    else if (keyString.find(PRIVATE_PREAMBLE) == 0) {
        x509Keys = true;
    }
    else {
        throw EncodingException("Not a PEM format private key");
    }

    std::istringstream in(keyString);
    Base64 base64;
    base64.decode(in);
    coder::ByteArrayInputStream encoded(base64.getData());

    derCodec = new DERCodec;
    coder::ByteArrayOutputStream sequence;
    derCodec->getSequence(encoded, sequence);
    // The sequence should include the whole array.
    if (encoded.available() > 0) {
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayInputStream seq(sequence.toByteArray());
    if (x509Keys) {
        return parsePrivateKey(seq);
    }
    else {
        // The RSA key is just a sequence of integers.
        return getPrivateKey(seq);
    }

}

RSAPublicKey *PEMCodec::decodePublicFromPrivate(const std::string& keyString) {

    if (keyString.find(RSA_PRIVATE_PREAMBLE) == 0) {
        x509Keys = false;
    }
    else if (keyString.find(PRIVATE_PREAMBLE) == 0) {
        x509Keys = true;
    }
    else {
        throw EncodingException("Not a PEM format private key");
    }

    std::istringstream in(keyString);
    Base64 base64;
    base64.decode(in);
    coder::ByteArrayInputStream encoded(base64.getData());

    derCodec = new DERCodec;
    coder::ByteArrayOutputStream sequence;
    derCodec->getSequence(encoded, sequence);
    // The sequence should include the whole array.
    if (encoded.available() > 0) {
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayInputStream seq(sequence.toByteArray());
    if (x509Keys) {
        return parsePublicFromPrivate(seq);
    }
    else {
        // The RSA key is just a sequence of integers.
        return getPublicFromPrivate(seq);
    }

}

RSAPublicKey *PEMCodec::decodePublicKey(const std::string& keyString) {

    if (keyString.find(RSA_PUBLIC_PREAMBLE) == 0) {
        x509Keys = false;
    }
    else if (keyString.find(PUBLIC_PREAMBLE) == 0) {
        x509Keys = true;
    }
    else {
        throw EncodingException("Not a PEM format public key");
    }

    std::istringstream in(keyString);
    Base64 base64;
    base64.decode(in);
    coder::ByteArrayInputStream encoded(base64.getData());

    derCodec = new DERCodec;
    coder::ByteArrayOutputStream sequence;
    derCodec->getSequence(encoded, sequence);
    // The sequence should include the whole array.
    if (encoded.available() > 0) {
        throw EncodingException("Invalid public key encoding");
    }

    coder::ByteArrayInputStream seq(sequence.toByteArray());
    if (x509Keys) {
        return parsePublicKey(seq);
    }
    else {
        // The RSA key is just a sequence of integers.
        return getPublicKey(seq);
    }

}

void PEMCodec::encode(std::ostream& out, const RSAPrivateKey& privateKey,
                                        const RSAPublicKey& publicKey) {

    if (x509Keys) {
        out << PRIVATE_PREAMBLE << std::endl;
    }
    else {
        out << RSA_PRIVATE_PREAMBLE << std::endl;
    }

    derCodec = new DERCodec;
    coder::ByteArrayOutputStream *keyBytes = new coder::ByteArrayOutputStream;
    if (privateKey.getKeyType() == RSAPrivateKey::mod) {
        encodeTwoPrimeKey(*keyBytes, *dynamic_cast<const RSAPrivateModKey*>(&privateKey));
    }
    else if (privateKey.getKeyType() == RSAPrivateKey::crt) {
        encodeMultiprimeKey(*keyBytes,
                        *dynamic_cast<const RSAPrivateCrtKey*>(&privateKey), publicKey);
    }
    else {
        throw EncodingException("Unknown private key type");
    }

    coder::ByteArrayOutputStream *sequence;
    if (x509Keys ) {
        sequence = new coder::ByteArrayOutputStream;
        derCodec->encodeSequence(*sequence, keyBytes->toByteArray());
        delete keyBytes;
    }
    else {
        sequence = keyBytes;
    }

    Base64 base64(sequence->toByteArray());
    delete sequence;
    base64.encode(out);

    if (x509Keys) {
        out << PRIVATE_EPILOGUE << std::endl;
    }
    else {
        out << RSA_PRIVATE_EPILOGUE << std::endl;
    }

}

void PEMCodec::encode(std::ostream& out, const RSAPublicKey& key) {

    if (x509Keys) {
        out << PUBLIC_PREAMBLE << std::endl;
    }
    else {
        out << RSA_PUBLIC_PREAMBLE << std::endl;
    }

    derCodec = new DERCodec;
    coder::ByteArrayOutputStream *keyBytes = new coder::ByteArrayOutputStream;
    encodePublicKey(*keyBytes, key);

    coder::ByteArrayOutputStream *sequence;
    if (x509Keys ) {
        sequence= new coder::ByteArrayOutputStream();
        derCodec->encodeSequence(*sequence, keyBytes->toByteArray());
        delete keyBytes;
    }
    else {
        sequence = keyBytes;
    }

    Base64 base64(sequence->toByteArray());
    delete sequence;
    base64.encode(out);

    if (x509Keys) {
        out << PUBLIC_EPILOGUE << std::endl;
    }
    else {
        out << RSA_PUBLIC_EPILOGUE << std::endl;
    }

}

void PEMCodec::encodeMultiprimeKey(coder::ByteArrayOutputStream& out,
                                                const RSAPrivateCrtKey& privateKey,
                                                const RSAPublicKey& publicKey) {

    coder::ByteArrayOutputStream primes;
    derCodec->encodeInteger(primes, MULTIPRIME_VERSION);
    encodePrimes(primes, privateKey, publicKey);

    if (x509Keys) {
        derCodec->encodeInteger(out, MULTIPRIME_VERSION);
        derCodec->encodeAlgorithm(out);
        coder::ByteArrayOutputStream primeSeq;
        derCodec->encodeSequence(primeSeq, primes.toByteArray());
        derCodec->encodeOctetString(out, primeSeq.toByteArray());
    }
    else {
        out.write(primes.toByteArray());
    }

}

void PEMCodec::encodePrimes(coder::ByteArrayOutputStream& out,
                                                const RSAPrivateCrtKey& privateKey,
                                                const RSAPublicKey& publicKey) {

    derCodec->encodeInteger(out, privateKey.getModulus().getEncoded());
    derCodec->encodeInteger(out, publicKey.getPublicExponent().getEncoded());
    derCodec->encodeInteger(out, privateKey.getPrivateExponent().getEncoded());
    derCodec->encodeInteger(out, privateKey.getPrimeP().getEncoded());
    derCodec->encodeInteger(out, privateKey.getPrimeQ().getEncoded());
    derCodec->encodeInteger(out, privateKey.getPrimeExponentP().getEncoded());
    derCodec->encodeInteger(out, privateKey.getPrimeExponentQ().getEncoded());
    derCodec->encodeInteger(out, privateKey.getInverse().getEncoded());

}

void PEMCodec::encodePrimes(coder::ByteArrayOutputStream& out,
                                                const RSAPrivateModKey& key) {

    derCodec->encodeInteger(out, key.getModulus().getEncoded());
    derCodec->encodeInteger(out, key.getPrivateExponent().getEncoded());

}

void PEMCodec::encodePublicKey(coder::ByteArrayOutputStream& out,
                                                const RSAPublicKey& key) {

    coder::ByteArrayOutputStream primes;
    derCodec->encodeInteger(primes, key.getModulus().getEncoded());
    derCodec->encodeInteger(primes, key.getPublicExponent().getEncoded());

    if (x509Keys) {
        derCodec->encodeAlgorithm(out);
        coder::ByteArrayOutputStream primeSeq;
        derCodec->encodeSequence(primeSeq, primes.toByteArray());
        coder::ByteArrayOutputStream bitstring;
        derCodec->encodeBitString(bitstring, primeSeq.toByteArray());
        out.write(bitstring.toByteArray());
    }
    else {
        out.write(primes.toByteArray());
    }

}

void PEMCodec::encodeTwoPrimeKey(coder::ByteArrayOutputStream& out,
                                                const RSAPrivateModKey& key) {

    coder::ByteArrayOutputStream primes;
    derCodec->encodeInteger(primes, TWO_PRIME_VERSION);
    encodePrimes(primes, key);

    if (x509Keys) {
        derCodec->encodeInteger(out, TWO_PRIME_VERSION);
        derCodec->encodeAlgorithm(out);
        coder::ByteArrayOutputStream primeSeq;
        derCodec->encodeSequence(primeSeq, primes.toByteArray());
        derCodec->encodeOctetString(out, primeSeq.toByteArray());
    }
    else {
        out.write(primes.toByteArray());
    }
}

RSAPrivateKey *PEMCodec::getPrivateKey(coder::ByteArrayInputStream& key) {

    coder::ByteArrayOutputStream version;
    derCodec->getInteger(key, version);        
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }
    coder::ByteArray vBytes(version.toByteArray());

    coder::ByteArrayOutputStream nBytes;
    derCodec->getInteger(key, nBytes);
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }
    BigInteger n(nBytes.toByteArray());

    if (vBytes[0] == TWO_PRIME_VERSION[0]) {
        coder::ByteArrayOutputStream dBytes;
        derCodec->getInteger(key, dBytes);
        if (key.available() != 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger d(dBytes.toByteArray());
        return new RSAPrivateModKey(n, d);
    }
    else if (vBytes[0] == MULTIPRIME_VERSION[0]) {
        coder::ByteArrayOutputStream eBytes;
        derCodec->getInteger(key, eBytes);
        if (key.available() == 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger e(eBytes.toByteArray());

        coder::ByteArrayOutputStream dBytes;
        derCodec->getInteger(key, dBytes);
        if (key.available() == 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger d(dBytes.toByteArray());

        coder::ByteArrayOutputStream pBytes;
        derCodec->getInteger(key, pBytes);
        if (key.available() == 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger p(pBytes.toByteArray());

        coder::ByteArrayOutputStream qBytes;
        derCodec->getInteger(key, qBytes);
        if (key.available() == 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger q(qBytes.toByteArray());

        coder::ByteArrayOutputStream ppBytes;
        derCodec->getInteger(key, ppBytes);
        if (key.available() == 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger expp(ppBytes.toByteArray());

        coder::ByteArrayOutputStream qqBytes;
        derCodec->getInteger(key, qqBytes);
        if (key.available() == 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger expq(qqBytes.toByteArray());

        coder::ByteArrayOutputStream cBytes;
        derCodec->getInteger(key, cBytes);
        if (key.available() != 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger coeff(cBytes.toByteArray());
        RSAPrivateCrtKey *k = new RSAPrivateCrtKey(p, q, expp, expq, coeff);
        k->setPrivateExponent(d);
        k->setModulus(n);
        return k;
    }
    else {
        throw EncodingException("Invalid private key encoding");
    }

}

RSAPublicKey *PEMCodec::getPublicFromPrivate(coder::ByteArrayInputStream& key) {

    coder::ByteArrayOutputStream version;
    derCodec->getInteger(key, version);        
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }
    coder::ByteArray vBytes(version.toByteArray());

    coder::ByteArrayOutputStream nBytes;
    derCodec->getInteger(key, nBytes);
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }
    BigInteger n(nBytes.toByteArray());

    if (vBytes[0] == TWO_PRIME_VERSION[0]) {
        throw EncodingException("Unable to extract a public key from this encoding");
    }
    else if (vBytes[0] == MULTIPRIME_VERSION[0]) {
        coder::ByteArrayOutputStream eBytes;
        derCodec->getInteger(key, eBytes);
        if (key.available() == 0) {
            throw EncodingException("Invalid private key encoding");
        }
        BigInteger e(eBytes.toByteArray());
        return new RSAPublicKey(n, e);
    }
    else {
        throw EncodingException("Invalid private key encoding");
    }

}

RSAPublicKey *PEMCodec::getPublicKey(coder::ByteArrayInputStream& key) {

    coder::ByteArrayOutputStream nBytes;
    derCodec->getInteger(key, nBytes);
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }
    BigInteger n(nBytes.toByteArray());

    coder::ByteArrayOutputStream eBytes;
    derCodec->getInteger(key, eBytes);
    if (key.available() != 0) {
        // Stuff after the integer encodings. Suspicious!
        throw EncodingException("Invalid private key encoding");
    }
    BigInteger e(eBytes.toByteArray());

    return new RSAPublicKey(n, e);

}

RSAPrivateKey *PEMCodec::parsePrivateKey(coder::ByteArrayInputStream& key) {

    coder::ByteArrayOutputStream version;
    derCodec->getInteger(key, version);        
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }

    // Nothing useful in this sequence. Parsing for errors only.
    derCodec->parseAlgorithm(key);
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayOutputStream octetString;
    derCodec->getOctetString(key, octetString);
    if (key.available() != 0) {
        // Stuff after the end of the string. Suspicious!
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayOutputStream sequence;
    coder::ByteArrayInputStream octets(octetString.toByteArray());
    derCodec->getSequence(octets, sequence);
    if (key.available() != 0) {
        // Stuff after the end of the sequence. Suspicious!
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayInputStream keyStream(sequence.toByteArray());
    return getPrivateKey(keyStream);

}

RSAPublicKey *PEMCodec::parsePublicFromPrivate(coder::ByteArrayInputStream& key) {

    coder::ByteArrayOutputStream version;
    derCodec->getInteger(key, version);        
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }

    // Nothing useful in this sequence. Parsing for errors only.
    derCodec->parseAlgorithm(key);
    if (key.available() == 0) {
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayOutputStream octetString;
    derCodec->getOctetString(key, octetString);
    if (key.available() != 0) {
        // Stuff after the end of the string. Suspicious!
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayOutputStream sequence;
    coder::ByteArrayInputStream octets(octetString.toByteArray());
    derCodec->getSequence(octets, sequence);
    if (key.available() != 0) {
        // Stuff after the end of the sequence. Suspicious!
        throw EncodingException("Invalid private key encoding");
    }

    coder::ByteArrayInputStream keyStream(sequence.toByteArray());
    return getPublicFromPrivate(keyStream);

}

RSAPublicKey *PEMCodec::parsePublicKey(coder::ByteArrayInputStream& key) {

    // Nothing useful in this sequence. Parsing for errors only.
    derCodec->parseAlgorithm(key);
    if (key.available() == 0) {
        throw EncodingException("Invalid public key encoding");
    }

    coder::ByteArrayOutputStream bitString;
    derCodec->getBitString(key, bitString);
    coder::ByteArray bitBytes(bitString.toByteArray());
    if (key.available() != 0 || bitBytes[0] != 0) {
        // The first byte in the bit string segment indicates an independent element.
        throw EncodingException("Invalid public key encoding");
    }

    coder::ByteArrayOutputStream sequence;
    coder::ByteArrayInputStream bits(bitBytes.range(1));
    derCodec->getSequence(bits, sequence);
    if (key.available() != 0) {
        // Stuff after the end of the sequence. Suspicious!
        throw EncodingException("Invalid public key encoding");
    }

    coder::ByteArrayInputStream keyStream(sequence.toByteArray());
    return getPublicKey(keyStream);

}

}

