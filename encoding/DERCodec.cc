#include "encoding/DERCodec.h"
#include "exceptions/EncodingException.h"
#include <coder/Unsigned16.h>
#include <coder/Unsigned32.h>
#include <coder/ByteArrayInputStream.h>
#include <coder/ByteArrayOutputStream.h>

namespace CK {

static const uint8_t INTEGER_TAG = 0x02;
static const uint8_t NULL_TAG = 0x05;
static const uint8_t BIT_STRING_TAG = 0x03;
static const uint8_t OCTET_STRING_TAG = 0x04;
static const uint8_t OID_TAG = 0x06;
static const uint8_t SEQUENCE_TAG = 0x30;

static const uint8_t DER_NULL[] = { 0x05, 0x00 };
static const uint8_t RSA_OID[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const int OID_LENGTH = 11;

DERCodec::DERCodec()
: rsa_oid(RSA_OID, OID_LENGTH),
  der_null(DER_NULL, 2) {
}

DERCodec::~DERCodec() {
}

void DERCodec::encodeAlgorithm(coder::ByteArrayOutputStream& out) {

    coder::ByteArrayOutputStream algorithm;
    algorithm.write(coder::ByteArray(RSA_OID, OID_LENGTH));
    algorithm.write(coder::ByteArray(DER_NULL, 2));
    encodeSequence(out, algorithm.toByteArray());

}

void DERCodec::encodeBitString(coder::ByteArrayOutputStream& out, const coder::ByteArray& bits) {

    out.write(BIT_STRING_TAG);
    setLength(out, bits.getLength() + 1);
    out.write(0);
    out.write(bits);

}

void DERCodec::encodeInteger(coder::ByteArrayOutputStream& out, const coder::ByteArray& integer) {

    out.write(INTEGER_TAG);
    setLength(out, integer.getLength());
    out.write(integer);

}

void DERCodec::encodeOctetString(coder::ByteArrayOutputStream& out, const coder::ByteArray& octetstring) {

    out.write(OCTET_STRING_TAG);
    setLength(out, octetstring.getLength());
    out.write(octetstring);

}

void DERCodec::encodeSequence(coder::ByteArrayOutputStream& out, const coder::ByteArray& sequence) {

    out.write(SEQUENCE_TAG);
    setLength(out, sequence.getLength());
    out.write(sequence);

}

void DERCodec::getBitString(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& bitstring) {

    if (source.read() != BIT_STRING_TAG) {
        throw EncodingException("Not a bit string");
    }

    getSegment(source, bitstring);

}

void DERCodec::getInteger(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& integer) {

    if (source.read() != INTEGER_TAG) {
        throw EncodingException("Not an integer");
    }

    getSegment(source, integer);

}

void DERCodec::getOctetString(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& octetstring) {

    if (source.read() != OCTET_STRING_TAG) {
        throw EncodingException("Not an octet string");
    }

    getSegment(source, octetstring);

}

void DERCodec::getSegment(coder::ByteArrayInputStream& source,
                                                coder::ByteArrayOutputStream& segment) {

    // The first byte is the tag.
    // BER/DER length encoding:
    // If MSB of first byte is not set, segment length is the first byte/
    // It MSB is set, lower 7 bits contant number of bytes containing the length.
    // Length is always expressed in the minimum number of bytes.
    uint32_t length;
    int indicator = source.read();
    if ((indicator & 0x80) != 0) {
        uint32_t lengthSize = indicator & 0x7f;
        coder::ByteArray lBytes(lengthSize, 0);
        source.read(lBytes);
        if (lengthSize == 2) {
            coder::Unsigned16 u16(lBytes, coder::bigendian);
            length = u16.getValue();
        }
        else {
            coder::Unsigned32 u32(lBytes, coder::bigendian);
            length = u32.getValue();
        }
    }
    else {
        length = indicator;
    }

    // Read the segment
    coder::ByteArray segBytes(length, 0);
    source.read(segBytes);
    segment.write(segBytes);

}

void DERCodec::getSequence(coder::ByteArrayInputStream& source,
                                            coder::ByteArrayOutputStream& sequence) {

    if (source.read() != SEQUENCE_TAG) {
        throw EncodingException("Not a sequence");
    }

    getSegment(source, sequence);

}

void DERCodec::parseAlgorithm(coder::ByteArrayInputStream& source) {

    coder::ByteArrayOutputStream sequence;
    getSequence(source, sequence);
    coder::ByteArrayInputStream algorithm(sequence.toByteArray());

    if (algorithm.read() != OID_TAG) {
        throw EncodingException("Invalid algorithm encoding");
    }

    coder::ByteArrayOutputStream oid;
    getSegment(algorithm, oid);
    coder::ByteArray rsa_oid(RSA_OID, OID_LENGTH);
    if (oid.toByteArray() != rsa_oid.range(2)) {
        throw EncodingException("Invalid RSA object ID");
    }
    if (algorithm.available() == 0) {
        throw EncodingException("Invalid algorithm encoding");
    }

    int nullTag = algorithm.read();
    int nullValue = algorithm.read();
    if (nullTag != NULL_TAG || nullValue != 0) {
        throw EncodingException("Invalid algorithm encoding");
    }

}

void DERCodec::setLength(coder::ByteArrayOutputStream& out, unsigned length) {

    if (length <= 127) {
        out.write(length);
    }
    else {      //  For now, there shouldn't be an integer length greater than 16 bits.
        out.write(0x82);
        coder::Unsigned16 u16(length);
        out.write(u16.getEncoded(coder::bigendian));
    }

}

}

