#include "keys/PublicKey.h"

namespace CK {

PublicKey::PublicKey(const std::string& alg)
: algorithm(alg) {
}

PublicKey::~PublicKey() {
}

const std::string& PublicKey::getAlgorithm() const {

    return algorithm;

}

}

