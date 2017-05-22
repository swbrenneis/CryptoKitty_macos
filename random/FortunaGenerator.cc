#include "random/FortunaGenerator.h"
#include "exceptions/OutOfRangeException.h"
#include "cipher/AES.h"
#include "digest/SHA256.h"
#include "coder/Unsigned32.h"
#include "coder/Unsigned64.h"
#include "data/NanoTime.h"
#include <memory>
#include <fstream>
#include <cmath>
#include <chrono>

namespace CK {

FortunaGenerator::FortunaGenerator()
: runFlag(false),
  thread(0),
  cipher(new AES(AES::AES256)),
  counter(0L) {

      limit.setBit(128);    // Limits counter to 16 bytes

}

FortunaGenerator::~FortunaGenerator() {

    delete thread;

}

/*
 * Generate k * 16 bytes of random data.
 */
coder::ByteArray FortunaGenerator::generateBlocks(uint16_t k) {

    coder::ByteArray r;

    for (unsigned i = 0; i < k; ++i) {
        coder::ByteArray c(counter.getEncoded());
        c.flip();   // We want the counter in little-endian order.
        coder::ByteArray pad(16 - c.getLength(), 0);
        c.append(pad);
        if (key.getLength() > 32) {
            std::cerr << "Key overrun in " << __FILE__ << ", line " << __LINE__
                        << std::endl;
            key = key.range(0, 32);
        }
        r.append(cipher->encrypt(c, key));
        counter++;
        if (counter >= limit) {
            counter = 1L;
        }
    }
    // Is this even necessary?
    if (r.getLength() > k * 16) {
       std::cerr << "Fortuna block overrun." << std::endl;
       r = r.range(0, k * 16);
    }
    return r;

}

/*
 * Generate length bytes of random data. length will be adjusted to an even multiple
 * of 16.
 */
void FortunaGenerator::generateRandomData(coder::ByteArray& bytes, uint32_t length) {

    if (length > 0x100000) {    // 2**20
        throw OutOfRangeException("Requested byte count out of range");
    }

    double n = length;
    coder::ByteArray blocks(generateBlocks(ceil(n / 16)));
    bytes.append(blocks.range(0, length));

    key = generateBlocks(2);
    if (key.getLength() > 32) {
        std::cerr << "Key overrun in " << __FILE__ << ", line " << __LINE__
                        << std::endl;
        key = key.range(0, 32);
    }

}

void FortunaGenerator::reseed(const coder::ByteArray& seed) {

    SHA256 sha;
    coder::ByteArray newkey(key);
    newkey.append(seed);
    key = sha.digest(newkey);
    counter++;
    if (counter >= limit) {
        counter = 1L;
    }
    std::ofstream seedstr("fgseed", std::ios::trunc|std::ios::binary);
    std::unique_ptr<uint8_t[]> bytes(key.asArray());
    char *cbuf = reinterpret_cast<char*>(bytes.get());
    seedstr.write(cbuf, seed.getLength());
    seedstr.close();

}

void FortunaGenerator::run() {

    using namespace std::chrono_literals;

    char ebuf[32];
    uint8_t *ubuf = reinterpret_cast<uint8_t*>(ebuf);
    uint64_t reseedCounter = 0;

    while (runFlag) {
        coder::ByteArray rd;
        generateRandomData(rd, 4);
        coder::Unsigned32 nsec(rd, coder::littleendian);
        std::this_thread::sleep_for(2s);       // Reseeds about once per minute.

        // Add some timed entropy
        NanoTime tm;
        coder::Unsigned32 timed(tm.getNanoseconds());
        coder::ByteArray nano(timed.getEncoded(coder::littleendian));
        // Fill out to 32 bytes.
        for (int i = 1; i < 8; ++i) {
            timed.setValue((timed.getValue() * 2) + i);
            nano.append(timed.getEncoded(coder::littleendian));
        }
        for (int i = 0; i < 32; ++i) {
            pools[i].append(nano[i]);
        }

        // Hash the time value and distribute
        coder::Unsigned64 htimed(tm.getFullTime());
        SHA256 sha;
        coder::ByteArray hashed(sha.digest(htimed.getEncoded(coder::littleendian)));
        for (int i = 0; i < 32; ++i) {
            pools[i].append(hashed[i]);
        }

        // Add some system entropy
        std::ifstream rnd("/dev/urandom");
        rnd.read(ebuf, 32);
        for (int i = 0; i < 32; ++i) {
            pools[i].append(ubuf[i]);
        }

        // Hash the system entropy and distribute
        coder::ByteArray hrnd(ubuf, 32);
        sha.reset();
        hashed = sha.digest(hrnd);
        for (int i = 0; i < 32; ++i) {
            pools[i].append(hashed[i]);
        }

        // Hash the time and system hashes
        sha.reset();
        sha.update(hashed);
        sha.update(hrnd);
        hashed = sha.digest();
        for (int i = 0; i < 32; ++i) {
            pools[i].append(hashed[i]);
        }

        // Generate the seed. pool 0 is always used. Each of the other pools
        // are used when the reseed counter is a multiple of their index.
        if (pools[0].getLength() >= 32) {
            reseedCounter++;
            if (reseedCounter > 0x100000000) {
                reseedCounter = 1;
            }
            uint32_t modulus = 32;
            coder::ByteArray seed(pools[0]);
            pools[0].clear();
            for (int i = 1; i < 32; ++i) {
                if (reseedCounter % modulus == 0) {
                    seed.append(pools[i]);
                    pools[i].clear();
                    modulus = modulus << 2;
                }
                reseed(seed);
            }
        }

    }

    reseed(pools.front());

}

void FortunaGenerator::start() {

    if (!runFlag) {
        // Initialize pools
        for (int n = 0; n < 32; ++n) {
            coder::ByteArray pool;
            pools.push_back(pool);
        }

        // Get the seed
        char entr[32];
        uint8_t *ubuf = reinterpret_cast<uint8_t*>(entr);
        std::ifstream seedstr("fgseed", std::ios::binary);
        if (!seedstr.good()) {                  // Seed file doesn't exist
            std::ifstream rnd("/dev/urandom");    // Get some entropy from /dev/urandom
            rnd.get(entr, 32);
            rnd.close();
        }
        else {
            seedstr.get(entr, 32);
            seedstr.close();
        }
        coder::ByteArray seed(ubuf, 32);
        reseed(seed);

        // Start the accumulator.
        runFlag = true;
        thread = new std::thread([this]{ run(); });
    }

}

}

