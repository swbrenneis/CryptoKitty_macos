#include "random/CMWCRandom.h"
#include "data/NanoTime.h"
#include "coder/ByteArray.h"
#include "data/BigInteger.h"
#include "coder/Unsigned64.h"
#include "digest/SHA256.h"
#include <time.h>
#include <climits>
#include <cmath>

namespace CK {

// Static initializations
unsigned CMWCRandom::i = 4095;
const uint64_t CMWCRandom::A(18782L);
const uint64_t CMWCRandom::R = 0xfffffffe;

CMWCRandom::CMWCRandom() {

    NanoTime time;
    seed = time.getFullTime();

}

CMWCRandom::CMWCRandom(uint64_t seedValue)
: seed(seedValue){
}

CMWCRandom::~CMWCRandom() {
}

/*
 * Generate the random number.
 */
long CMWCRandom::cmwc4096() {

    uint64_t t;
    uint64_t x;

    i = (i + 1) & 4095;
    t = (A * q[i]) + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (q[i] = R - x);

}

/*
 * Provide the next bits of entropy. If bits
 * exceeds ULONG_MAX, the output will be truncated
 * silently.
 */
uint64_t CMWCRandom::next(int bits) {

    if (q.size() == 0) {
        seedGenerator();
    }

    long rnd = cmwc4096();

    int ulSize = sizeof(uint64_t) * 8;
    bits = std::min(ulSize, bits);
    uint64_t result = 0;
    uint64_t msb = (ULONG_MAX >> 1) ^ ULONG_MAX;
    for (int n = 0; n < ulSize; ++n) {
        if (n < bits) {
            if ((rnd & 1) != 0) {
                result |= msb;
            }
            rnd = rnd >> 1;
        }
        result = result >> 1;
    }

    return result;

}

/*
 * See the generator.
 */
void CMWCRandom::seedGenerator() {

    coder::ByteArray fill(4096);
    SHA256 digest;
    NanoTime nt;
    uint64_t nonce = seed;
    coder::ByteArray context;
    int filled = 0;

    if (q.size() != 4096) {
        q.resize(4096, 0);
    }
    while (filled < 4096) {
        if (context.getLength() != 0) {
            digest.update(context);
        }
        coder::Unsigned64 u64(nonce);
        digest.update(u64.getEncoded());
        nonce++;
        u64.setValue(nt.getFullTime());
        digest.update(u64.getEncoded());
        context = digest.digest();
        fill.copy(filled, context, 0);
        filled += context.getLength();
    }
    coder::Unsigned64 u64;
    for (int qi = 0; qi < 4088; qi += 8) {
        u64.decode(fill.range(qi, 8));
        q[qi] = u64.getValue();
    }
    nt.newTime();
    c = nt.getFullTime() % 809430659;  // Reset the reseed counter.

}

void CMWCRandom::setSeed(uint64_t seedValue) {

    seed = seedValue;
    seedGenerator(); // Generate new Q

}

}

