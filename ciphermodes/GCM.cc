#include "ciphermodes/GCM.h"
#include "cipher/BlockCipher.h"
#include "coder/Unsigned64.h"
#include "coder/Unsigned32.h"
#include "data/BigInteger.h"
#include "exceptions/BadParameterException.h"
#include "exceptions/AuthenticationException.h"
#include <deque>
#include <iostream>
#include <cmath>

namespace CK {

GCM::GCM(BlockCipher *c, bool append)
: tagSize(128),
  appendTag(append),
  cipher(c) {

    if (cipher->blockSize() != 16) {
        throw BadParameterException("Invalid cipher block size");
     }

}

GCM::~GCM() {

    if (!jni) {
        delete cipher;
    }

}

/*
 * Class decryption function.
 */
coder::ByteArray GCM::decrypt(const coder::ByteArray& C, const coder::ByteArray& K) {

    coder::ByteArray ciphertext(C);
    if (appendTag) {
        uint32_t tagLength = tagSize / 8;
        T = C.range(C.getLength() - tagLength, tagLength);
        ciphertext.truncate(tagLength);
    }
    int n = ciphertext.getLength() / 16;
    int u = ciphertext.getLength() % 16;
    if (u == 0) {
        u = 16;
        n--;
    }

    coder::ByteArray H(cipher->encrypt(coder::ByteArray(16, 0), K));

    coder::ByteArray Y0;
    if (IV.getLength() == 12) {
        coder::ByteArray ctr(4, 0);
        ctr[3] = 0x01;
        Y0.append(IV);
        Y0.append(ctr);
    }
    else {
        Y0 = GHASH(H, coder::ByteArray(0), IV);
    }

    coder::ByteArray Tp(GHASH(H, A, ciphertext));
    Tp = Tp ^ cipher->encrypt(Y0, K);
    if (T != Tp) {
        throw AuthenticationException("GCM AEAD failed authentication");
    }

    coder::ByteArray Yi;           // Y(i)
    coder::ByteArray Yi1(Y0);      // Y(i-1)
    coder::ByteArray Ci;           // C(i)
    coder::ByteArray Pi;           // C(i);
    coder::ByteArray P;

    if (ciphertext.getLength() > 0) {
        for (int i = 1; i <= n; ++i) {
            Yi = incr(Yi1);
            Ci = ciphertext.range((i-1)*16, 16);
            Pi = Ci ^ cipher->encrypt(Yi, K);
            P.append(Pi);
            Yi1 = Yi;
        }
        Yi = incr(Yi1);
        coder::ByteArray Cn(ciphertext.range(ciphertext.getLength()-u, u));
        P.append(Cn ^ (cipher->encrypt(Yi, K)).range(0, u));
    }

    return P;

}

/*
 * Class encryption function.
 */
coder::ByteArray GCM::encrypt(const coder::ByteArray& P, const coder::ByteArray& K) {

    //std::cout << "encrypt P = " << P << std::endl;
    // l = (n - 1)128 + u
    int n = P.getLength() / 16;
    int u = P.getLength() % 16;
    if (u == 0) {
        u = 16;
        n--;
    }

    coder::ByteArray H(cipher->encrypt(coder::ByteArray(16, 0), K));

    coder::ByteArray Y0;
    if (IV.getLength() == 12) {
        coder::ByteArray ctr(4, 0);
        ctr[3] = 0x01;
        Y0.append(IV);
        Y0.append(ctr);
    }
    else {
        Y0 = GHASH(H, coder::ByteArray(0), IV);
    }

    coder::ByteArray Yi;           // Y(i)
    coder::ByteArray Yi1(Y0);      // Y(i-1)
    coder::ByteArray Pi;           // P(i)
    coder::ByteArray Ci;           // C(i);
    coder::ByteArray C;

    if (P.getLength() > 0) {
        for (int i = 1; i <= n; ++i) {
            Yi = incr(Yi1);
            Pi = P.range((i-1)*16, 16);
            Ci = Pi ^ cipher->encrypt(Yi, K);
            C.append(Ci);
            Yi1 = Yi;
        }
        Yi = incr(Yi1);
        coder::ByteArray Pn(P.range(P.getLength()-u, u));
        C.append(Pn ^ (cipher->encrypt(Yi, K)).range(0, u));
    }

    T = GHASH(H, A, C);
    T = T ^ cipher->encrypt(Y0, K);

    if (appendTag) {
        C.append(T);
    }

    return C;

}

const coder::ByteArray& GCM::getAuthTag() const {

    return T;

}

/*
 * GHASH function. See NIST SP 800-38D, section 6.4.
 * X must be an even multiple of 16 bytes. H is the subhash
 * key. Yi is always 128 bits.
*/
coder::ByteArray GCM::GHASH(const coder::ByteArray& H, const coder::ByteArray& A,
                                            const coder::ByteArray& C) const {

    if (H.getLength() != 16) {
        throw BadParameterException("Invalid hash sub-key");
    }

    int m = A.getLength() / 16;
    int v = A.getLength() % 16;
    if (v == 0) {
        v = 16;
        m--;
    }
    int n = C.getLength() / 16;
    int u = C.getLength() % 16;
    if (u == 0) {
        u = 16;
        n--;
    }

    coder::ByteArray Xi1(16, 0);           // X(i-1)
    coder::ByteArray Xi;                   // X(i)
    coder::ByteArray Ai;                   // A(i)
    coder::ByteArray Ci;                   // C(i)

    int i = 1; // For tracking Xi index. Debug only.
    for (int j = 0; j < m; ++j) {
        Ai = A.range(j * 16, 16);
        Xi = multiply(Xi1 ^ Ai, H);
        i++;
        Xi1 = Xi;
    }

    if (A.getLength() > 0) {
        coder::ByteArray Am(A.range(A.getLength() - v, v));    // A(n)
        coder::ByteArray pad(16-v, 0);
        Am.append(pad);
        Xi = multiply(Xi1 ^ Am, H);
        i++;
        Xi1 = Xi;
    }

    for (int j = 0; j < n; ++j) {
        Ci = C.range(j * 16, 16);
        Xi = multiply(Xi1 ^ Ci, H);
        i++;
        Xi1 = Xi;
    }

    if (C.getLength() > 0) {
        coder::ByteArray Cn(C.range(C.getLength() - u, u));    // A(n)
        coder::ByteArray pad(16-u, 0);
        Cn.append(pad);
        Xi = multiply(Xi1 ^ Cn, H);
        i++;
        Xi1 = Xi;
    }

    coder::ByteArray ac;
    coder::Unsigned64 al(A.getLength() * 8);
    ac.append(al.getEncoded(coder::bigendian));
    coder::Unsigned64 cl(C.getLength() * 8);
    ac.append(cl.getEncoded(coder::bigendian));
    Xi = multiply(Xi1 ^ ac, H);

    return Xi;

}

/*
 * Galois incr function. See NIST SP 800-38D, section 6.2.
 * Increments the rightmost s bits of X leaving the leftmost in
 * the bit string unchanged.
 */
coder::ByteArray GCM::incr(const coder::ByteArray& X) const {

    if (X.getLength() != 16) {
        throw BadParameterException("Illegal block size");
    }

    coder::ByteArray fixed(X.range(0, 12));
    coder::Unsigned32 x(X.range(12, 4), coder::bigendian);
    coder::Unsigned32 inc(x.getValue() + 1);
    fixed.append(inc.getEncoded(coder::bigendian));

    return fixed;

}

/*
 * Galois multiplication function. See NIST SP 800-3D, Section 6.3.
 * X, Y, and Z are 128 bits.
 */
coder::ByteArray GCM::multiply(const coder::ByteArray& X, const coder::ByteArray& Y) const {

    if (X.getLength() != 16 || Y.getLength() != 16) {
        throw BadParameterException("Invalid multiplicand or multiplier size");
    }

    coder::ByteArray Z(16,0);
    coder::ByteArray V(Y);

    //std:: cout << "X = " << X << std::endl
    //        << "Y = " << Y << std::endl << std::endl;
    uint8_t bits[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 8; ++j) {
    //    std::cout << "i = " << i << ", j = " << j << std::endl
    //            << "V = " << V << std::endl
    //            << "Z = " << Z << std::endl << std::endl;
            if ((X[i] & bits[7-j]) != 0) {
                Z = Z ^ V;
            }
            if ((V[15] & 0x01) != 0) {
                shiftBlock(V);
                V[0] = V[0] ^ 0xe1;
            }
            else {
                shiftBlock(V);
            }
        }
    }

    return Z;

}

void GCM::shiftBlock(coder::ByteArray& block) const {

    coder::Unsigned32 be(block.range(12, 4), coder::bigendian);
    uint32_t value = be.getValue();
    value = value >> 1;
    if ((block[11] & 0x01) != 0) {
        value |= 0x80000000;
    }
    coder::Unsigned32 v(value);
    block.copy(12, v.getEncoded(coder::bigendian), 0, 4);

    be.decode(block.range(8, 4), coder::bigendian);
    value = be.getValue();
    value = value >> 1;
    if ((block[7] & 0x01) != 0) {
        value |= 0x80000000;
    }
    v.setValue(value);
    block.copy(8, v.getEncoded(coder::bigendian), 0, 4);

    be.decode(block.range(4, 4), coder::bigendian);
    value = be.getValue();
    value = value >> 1;
    if ((block[3] & 0x01) != 0) {
        value |= 0x80000000;
    }
    v.setValue(value);
    block.copy(4,v.getEncoded(coder::bigendian), 0, 4);

    be.decode(block.range(0, 4), coder::bigendian);
    value = be.getValue();
    value = value >> 1;
    v.setValue(value);
    block.copy(0, v.getEncoded(coder::bigendian), 0, 4);

}

void GCM::setAuthenticationData(const coder::ByteArray& ad) {

    /*if (ad.getLength() * 8 > A_MAX) {
        throw BadParameterException("GCM setAuthData: Invalid authentication data");
    }*/

    A = ad;

}

void GCM::setAuthTag(const coder::ByteArray& tag) {

    if (tag.getLength() * 8 != tagSize) {
        throw BadParameterException("GCM setAuthTag: Invalid authentication tag");
    }

    T = tag;

}

}

