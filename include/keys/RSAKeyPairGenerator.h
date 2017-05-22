#ifndef RSAKEYPAIRGENERATOR_H_INCLUDED
#define RSAKEYPAIRGENERATOR_H_INCLUDED

#include "../data/BigInteger.h"
#include "../jni/JNIReference.h"
#include "KeyPair.h"

namespace CK {

class SecureRandom;
class RSAPublicKey;
class RSAPrivateKey;

typedef KeyPair<RSAPublicKey, RSAPrivateKey> RSAKeyPair;

class RSAKeyPairGenerator : public JNIReference {

    public:
        RSAKeyPairGenerator();
        RSAKeyPairGenerator(SecureRandom *secure, int bits = 1024);
        ~RSAKeyPairGenerator();

    private:
        RSAKeyPairGenerator(const RSAKeyPairGenerator& other);
        RSAKeyPairGenerator&
                operator= (const RSAKeyPairGenerator& other);

    public:
        RSAKeyPair *generateKeyPair(bool crt = true);
        void initialize(int bits, SecureRandom* secure);

    private:
        int keySize;
        SecureRandom *random;

        static const BigInteger THREE;

};

}

#endif	// RSAKEYPAIRGENERATOR_H_INCLUDED
