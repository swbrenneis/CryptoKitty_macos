#include "keys/RSAPrivateKey.h"

namespace CK {

RSAPrivateKey::RSAPrivateKey(KeyType kt)
: PrivateKey("RSA"),
  keyType(kt) {
}

RSAPrivateKey::~RSAPrivateKey() {
}

}
