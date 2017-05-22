#include "digest/SHA1.h"
#include <coder/Unsigned64.h>
#include <coder/Unsigned32.h>
#include <deque>
#include <memory>

namespace CK {

const uint32_t SHA1::H1 = 0x67452301;
const uint32_t SHA1::H2 = 0xefcdab89;
const uint32_t SHA1::H3 = 0x98badcfe;
const uint32_t SHA1::H4 = 0x10325476;
const uint32_t SHA1::H5 = 0xc3d2e1f0;

const uint32_t SHA1::K[] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

const coder::ByteArray SHA1::DER;

SHA1::SHA1() {
}

SHA1::~SHA1() {
}

/*
 * Ch function.
 */
uint32_t SHA1::Ch (uint32_t x, uint32_t y, uint32_t z) const {

    uint32_t r = (x & y) ^ ((~x) & z);
    return r;

}

/*
 * Round function.
 */
uint32_t SHA1::f(uint32_t x, uint32_t y, uint32_t z, uint32_t t) const {

    if (t <= 19) {
        return Ch(x, y, z);
    }
    else if (t <= 39) {
        return Parity(x, y, z);
    }
    else if (t <= 59) {
        return Maj(x, y, z);
    }
    else {
        return Parity(x, y, z);
    }

}

coder::ByteArray SHA1::finalize(const coder::ByteArray& message) const {

    // Pad the message to an even multiple of 512 bits.
    coder::ByteArray context(pad(message));

    // Split the message up into 512 bit chunks.
    uint32_t N = context.getLength() / 64;
    // We need the chunk array to begin at index 1 so the indexing
    // works out below.
    std::deque<coder::ByteArray> chunks;
    chunks.resize(N + 1, coder::ByteArray(64));
    int ci = 0;
    for (unsigned i = 1; i <= N; i++) {
        for (int j = 0; j < 64; ++j) {
            chunks[i][j] = context[ci + j];
        }
        ci += 64;
    }

    // Set the initial hash seeds
    uint32_t *h1 = new uint32_t[N + 1];
    h1[0] = H1;
    uint32_t *h2 = new uint32_t[N + 1];
    h2[0] = H2;
    uint32_t *h3 = new uint32_t[N + 1];
    h3[0] = H3;
    uint32_t *h4 = new uint32_t[N + 1];
    h4[0] = H4;
    uint32_t *h5 = new uint32_t[N + 1];
    h5[0] = H5;

    uint32_t *w = 0;
    // Process the chunks.
    for (unsigned i = 1; i <= N; ++i) {

        delete[] w;
        w = W(chunks[i]);

        uint32_t a = h1[i-1];
        uint32_t b = h2[i-1];
        uint32_t c = h3[i-1];
        uint32_t d = h4[i-1];
        uint32_t e = h5[i-1];

        for (int t = 0; t < 80; ++t) {

            int k;
            if (t <= 19) {
                k = K[0];
            }
            else if (t <= 39) {
                k = K[1];
            }
            else if (t <= 59) {
                k = K[2];
            }
            else {
                k = K[3];
            }

            uint32_t T = rol(a, 5) + f(b, c, d, t) + e + k + w[t];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = T;

        }

        h1[i] = h1[i-1] + a;
        h2[i] = h2[i-1] + b;
        h3[i] = h3[i-1] + c;
        h4[i] = h4[i-1] + d;
        h5[i] = h5[i-1] + e;

    }

    coder::ByteArray d;
    coder::Unsigned32 u32(h1[N]);
    d.append(u32.getEncoded(coder::bigendian));
    u32.setValue(h2[N]);
    d.append(u32.getEncoded(coder::bigendian));
    u32.setValue(h3[N]);
    d.append(u32.getEncoded(coder::bigendian));
    u32.setValue(h4[N]);
    d.append(u32.getEncoded(coder::bigendian));
    u32.setValue(h5[N]);
    d.append(u32.getEncoded(coder::bigendian));

    delete[] h1;
    delete[] h2;
    delete[] h3;
    delete[] h4;
    delete[] h5;

    return d;

}


/*
 * Maj function.
 */
uint32_t SHA1::Maj(uint32_t x, uint32_t y, uint32_t z) const {

  	uint32_t r = (x & y) ^ (x & z) ^ (y & z);
    return r;

}

/*
 * Pad the input array to an even multiple of 512 bits.
 */
coder::ByteArray SHA1::pad(const coder::ByteArray& in) const {

    // Message size in bits - l
    long l = in.getLength() * 8;

    /*
     * Pad the message such that k + 1 + l is congruent to
     * 448 mod 512, where k + 1 is the padding length and l is the
     * message length. The message is always padded with a byte
     * value of 0x80, which is a single bit added to the end of
     * the message.
     */
    coder::ByteArray work = in;
    work.append(0x80);
    // 512 bits = 64 bytes. The padded message includes the 64 bit
    // big endian representation of the message length in bits, so
    // in order to make the message modulo 512, we add bytes until
    // the whole message, including the length encoding is an even
    // multiple of 64,
    coder::ByteArray pad(64 - ((work.getLength() + 8) % 64));
    work.append(pad);
    // Append the 64 bit encoded bit length
    coder::Unsigned64 l64(l);
    work.append(l64.getEncoded(coder::bigendian));
    return work;

}

/*
 * Parity function.
 */
uint32_t SHA1::Parity(uint32_t x, uint32_t y, uint32_t z) const {

    return x ^ y ^ z;

}

/*
 * Rotate left (shift left carry the msb).
 */
uint32_t SHA1::rol(uint32_t x, int count) const {

    uint32_t result = x;
    for (int i = 1; i <= count; ++i) {
        uint32_t carry = (result >> 31) & 0x01;
        result = (result << 1) | carry;
    }

    return result;

}

/*
 * W function. Compute expanded message blocks via the SHA-1
 * message schedule.
 */
uint32_t *SHA1::W(const coder::ByteArray& chunk) const {

    uint32_t *w = new uint32_t[80];

    coder::Unsigned32 u32;
    for (int t = 0; t < 16; ++t) {
        int i = t * 4;
        u32.decode(chunk.range(i, 4), coder::bigendian);
        w[t] = u32.getValue();
    }

    for (int t = 16; t < 80; ++t) {
        w[t] = rol((w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]), 1);
    }
		
    return w;

}

}
