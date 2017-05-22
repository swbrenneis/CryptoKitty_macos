#include "signature/RSASignature.h"
#include "exceptions/IllegalStateException.h"
#include "cipher/RSA.h"

namespace CK {

template<class C, class D>
RSASignature<C,D>::RSASignature()
: signInit(false),
  verifyInit(false),
  cipher(new C(new D)) {
}

template<class C, class D>
RSASignature<C,D>::RSASignature(int saltLength)
: signInit(false),
  verifyInit(false),
  cipher(new C(new D, saltLength)) {
}

template<class C, class D>
RSASignature<C,D>::~RSASignature() {

    delete cipher;
}

/*
 * Initialize the signing function.
 */
template<class C, class D>
void RSASignature<C,D>::initSign(RSAPrivateKey* prv) {

    privateKey = prv;
    signInit = true;

}

/*
 * Initialize the signature verification function.
 */
template<class C, class D>
void RSASignature<C,D>::initVerify(RSAPublicKey* pub) {

    publicKey = pub;
    verifyInit = true;

}

/*
 * Sign the accumulated message.
 */
template<class C, class D>
coder::ByteArray RSASignature<C,D>::sign() {

    if (!signInit) {
        throw IllegalStateException("Signature Not Initialized");
    }

    return cipher->sign(*privateKey, accumulator);

}

/*
 * Update the message accumulator with a byte.
 */
template<class C, class D>
void RSASignature<C,D>::update(unsigned char b) {

    accumulator.append(b);

}

/*
 * Update the message accumulator with a byte array.
 */
template<class C, class D>
void RSASignature<C,D>::update(const coder::ByteArray& bytes) {

    accumulator.append(bytes);

}

/*
 * Update the message accumulator with a byte array.
 */
template<class C, class D>
void RSASignature<C,D>::update(const coder::ByteArray& bytes,
                int offset, int length) {

    accumulator.append(bytes, offset, length);

}

/*
 * Verify the accumulated message.
 */
template<class C, class D>
bool RSASignature<C,D>::verify(const coder::ByteArray& sig) {

    if (!verifyInit) {
        throw IllegalStateException("Signature Not Initialized");
    }

    return cipher->verify(*publicKey, accumulator, sig);

}

}

// Template instantiations. We want to limit the possible combinations.
// PKCS1SHA256RSASignature with RSA CRT private key instantiation.
#include "digest/SHA256.h"
#include "cipher/PKCS1rsassa.h"
#include "cipher/PSSrsassa.h"

CK::RSASignature<CK::PKCS1rsassa, CK::SHA256> pkcs1sha256sig;
CK::RSASignature<CK::PSSrsassa, CK::SHA256> psssha256sig;
CK::RSASignature<CK::PKCS1rsassa, CK::SHA256> pkcs1sha256sigSalted(10);
CK::RSASignature<CK::PSSrsassa, CK::SHA256> psssha256sigSalted(10);

