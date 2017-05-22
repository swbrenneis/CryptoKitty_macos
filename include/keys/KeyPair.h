#ifndef KEYPAIR_H_INCLUDED
#define KEYPAIR_H_INCLUDED

/*
 * Key pair POD with copy protection.
 */
namespace CK {

template<class Pu, class Pr> class KeyPair {

    private:
        KeyPair();
        KeyPair(const KeyPair& other);
        KeyPair& operator= (const KeyPair& other);

    public:
        KeyPair(Pu* pub, Pr* prv)
                : pubKey(pub), prvKey(prv) {}
        ~KeyPair() { delete pubKey; delete prvKey; }

    public:
        Pu* publicKey() { return pubKey; }
        Pr* privateKey() { return prvKey; }
        void releaseKeys() { pubKey = 0; prvKey = 0; }

    private:
        Pu* pubKey;
        Pr* prvKey;

};

}

#endif  // KEYPAIR_H_INCLUDED
