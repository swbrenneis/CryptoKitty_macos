#ifndef CKPUBLICKEY_H_INCLUDED
#define CKPUBLICKEY_H_INCLUDED

#include <string>

namespace CK {

class PublicKey {

    private:
        PublicKey();    // Must always be constructed
                        // with an algorithm name.

    protected:
        PublicKey(const std::string& alg);

    private:
        PublicKey(const PublicKey& other);
        PublicKey& operator= (const PublicKey& other);

    public:
        virtual ~PublicKey();

    public:
        virtual const std::string& getAlgorithm() const;

    protected:
        std::string algorithm;

};

}

#endif  // CKPUBLICKEY_H_INCLUDED
