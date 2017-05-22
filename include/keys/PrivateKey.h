#ifndef PRIVATEKEY_H_INCLUDED
#define PRIVATEKEY_H_INCLUDED

#include <string>

namespace CK {

class PrivateKey {

    private:
        PrivateKey();   // Must always be constructed
                        // with an algorithm name.

    protected:
        PrivateKey(const std::string& alg);

    private:
        PrivateKey(const PrivateKey& other);
        PrivateKey& operator= (const PrivateKey& other);

    public:
        virtual ~PrivateKey();

    public:
        const std::string& getAlgorithm() const;

    protected:
        std::string algorithm;

};

}

#endif  // PRIVATEKEY_H_INCLUDED
