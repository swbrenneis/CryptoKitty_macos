#include "digest/SHA384.h"
#include <data/BigInteger.h>
#include <coder/Unsigned64.h>
#include <string.h>
#include <climits>

namespace CK {

// Static initializers
const uint64_t SHA384::H1 = 0xcbbb9d5dc1059ed8;
const uint64_t SHA384::H2 = 0x629a292a367cd507;
const uint64_t SHA384::H3 = 0x9159015a3070dd17;
const uint64_t SHA384::H4 = 0x152fecd8f70e5939;
const uint64_t SHA384::H5 = 0x67332667ffc00b31;
const uint64_t SHA384::H6 = 0x8eb44a8768581511;
const uint64_t SHA384::H7 = 0xdb0c2e0d64f98fa7;
const uint64_t SHA384::H8 = 0x47b5481dbefa4fa4;
const uint64_t SHA384::K[] =
{ 0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
  0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
  0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
  0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
  0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
  0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
  0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
  0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
  0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
  0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
  0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
  0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
  0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
  0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
  0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
  0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
  0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
  0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
  0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
  0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L };

const uint8_t DERbytes[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                                    0x00, 0x04, 0x40 };

const coder::ByteArray SHA384::DER(DERbytes, sizeof(DERbytes));

SHA384::SHA384(){
}

SHA384::~SHA384() {
}

/*
 * Ch(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z)
 *                          (~X)
 *   No corresponding X bar character
 */
uint64_t SHA384::Ch(uint64_t x, uint64_t y, uint64_t z) const {

    return (x & y) ^ ((~x) & z);
            
}

/*
 * Decompose the message into 80 64 bit blocks.
 *
 * Split the message into 16 64 bit blocks by concatenating bytes.
 *
 * Generate 48 32 bit blocks with this formula.
 *
 * W(i) = σ1(W(i−2)) + W(i−7) + σ0(W(i−15)) + W(i−16), 17 ≤ i ≤ 64
 */
SHA384::W SHA384::decompose(const coder::ByteArray& chunks) const {

    W w(80);

    for (int j = 0; j < 16; ++j) {
        coder::Unsigned64 c(chunks.range(j * 8, 8), coder::bigendian);
        w[j] = c.getValue();
    }

    for (int j = 16; j < 80; ++j) {
        w[j] = sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16];
    }

    return w;

}

coder::ByteArray SHA384::finalize(const coder::ByteArray& in) const {

    // Pad the message to an even multiple of 1024 bits.
    coder::ByteArray context(pad(in));

    // Split the message up into 1024 bit chunks.
    long n = context.getLength() / 128;
    // We need the chunk array to begin at index 1 so the indexing
    // works out below.
    Chunks chunks;
    chunks.push_back(coder::ByteArray(0));
    for (long i = 1; i <= n; i++) {
        chunks.push_back(context.range((i-1)*128, 128));
    }

    // Set the initial hash seeds
    uint64_t h1[n + 1];
    h1[0] = H1;
    uint64_t h2[n + 1];
    h2[0] = H2;
    uint64_t h3[n + 1];
    h3[0] = H3;
    uint64_t h4[n + 1];
    h4[0] = H4;
    uint64_t h5[n + 1];
    h5[0] = H5;
    uint64_t h6[n + 1];
    h6[0] = H6;
    uint64_t h7[n + 1];
    h7[0] = H7;
    uint64_t h8[n + 1];
    h8[0] = H8;

    // Process chunks.
    for (long i = 1; i <= n; ++i) {
        uint64_t a = h1[i-1];
        uint64_t b = h2[i-1];
        uint64_t c = h3[i-1];
        uint64_t d = h4[i-1];
        uint64_t e = h5[i-1];
        uint64_t f = h6[i-1];
        uint64_t g = h7[i-1];
        uint64_t h = h8[i-1];

        W w(decompose(chunks[i]));

        for (int j = 0; j < 80; ++j) {

            uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + w[j];
            uint64_t T2 = Sigma0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;

        }

        h1[i] = h1[i-1] + a;
        h2[i] = h2[i-1] + b;
        h3[i] = h3[i-1] + c;
        h4[i] = h4[i-1] + d;
        h5[i] = h5[i-1] + e;
        h6[i] = h6[i-1] + f;
        h7[i] = h7[i-1] + g;
        h8[i] = h8[i-1] + h;

    }

    coder::ByteArray d(coder::Unsigned64(h1[n]).getEncoded(coder::bigendian));
    d.append(coder::Unsigned64(h2[n]).getEncoded(coder::bigendian));
    d.append(coder::Unsigned64(h3[n]).getEncoded(coder::bigendian));
    d.append(coder::Unsigned64(h4[n]).getEncoded(coder::bigendian));
    d.append(coder::Unsigned64(h5[n]).getEncoded(coder::bigendian));
    d.append(coder::Unsigned64(h6[n]).getEncoded(coder::bigendian));

    return d;

}

/*
 * Return the ASN.1 encoding identifier
 */
const coder::ByteArray& SHA384::getDER() const {

    return DER;

}

/*
 * Maj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)
 */
uint64_t SHA384::Maj(uint64_t x, uint64_t y, uint64_t z) const {

    return (x & y) ^ (x & z) ^ (y & z);

}

/*
 * Pad the input array to an even multiple of 384 bits.
 */
coder::ByteArray SHA384:: pad(const coder::ByteArray& in) const {

    // Message size in bits - l
    uint64_t l = in.getLength() * 8;

    /*
     * Pad the message such that k + 1 + l is congruent to
     * 960 mod 1024, where k + 1 is the padding length and l is the
     * message length. The message is always padded with a byte
     * value of 0x80, which is a single bit added to the end of
     * the message.
     */
    coder::ByteArray work = in;
    work.append(0x80);
    // 1024 bits = 128 bytes. The padded message includes the 128 bit
    // big endian representation of the message length in bits, so
    // in order to make the message modulo 1024, we add bytes until
    // the whole message, including the length encoding is an even
    // multiple of 128,
    coder::ByteArray pad(128 - ((work.getLength() + 16) % 128));
    work.append(pad);
    //while ((work.getLength() + 8)  % 64 != 0) {
    //    work.append(0); //pad with zeroes.
    //}
    // Append the 64 bit encoded bit length
    BigInteger l128(l);
    coder::ByteArray b128(l128.getEncoded());
    pad = coder::ByteArray(16 - b128.getLength());
    work.append(pad);
    work.append(b128);
    return work;

}

/*
 * Logical rotate right function.
 */
uint64_t SHA384::ror(uint64_t reg, int count) const {

    uint64_t msb = (UINT64_MAX >> 1) ^ UINT64_MAX;
    uint64_t result = reg;
    for (int i = 1; i <= count; ++i) {
        uint64_t carry = result & 1;
        result = (result >> 1) | (carry * msb);
    }
    return result;
    
}

/*
 * σ0(X) = RotR(X, 1) ⊕ RotR(X, 8) ⊕ ShR(X, 7)
 */
uint64_t SHA384::sigma0(uint64_t x) const {

    return ror(x, 1) ^ ror(x, 8) ^ (x >> 7);

}

/*
 * σ1(X) = RotR(X, 19) ⊕ RotR(X, 61) ⊕ ShR(X, 6),
 */
uint64_t SHA384::sigma1(uint64_t x) const {

    return ror(x, 19) ^ ror(x, 61) ^ (x >> 6);

}

/*
 * Σ0(X) = RotR(X, 28) ⊕ RotR(X, 34) ⊕ RotR(X, 39)
 */
uint64_t SHA384::Sigma0(uint64_t x) const {

    return ror(x, 28) ^ ror(x, 34) ^ ror(x, 39);

}

/*
 * Σ1(X) = RotR(X, 14) ⊕ RotR(X, 18) ⊕ RotR(X, 41)
 */
uint64_t SHA384::Sigma1(uint64_t x) const {

    return ror(x, 14) ^ ror(x, 18) ^ ror(x, 41);

}

}

