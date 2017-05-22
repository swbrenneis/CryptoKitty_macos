#include "keys/PrivateKey.h"

namespace CK {

PrivateKey::PrivateKey(const std::string& alg)
: algorithm(alg) {
}

PrivateKey::~PrivateKey() {
}

}
