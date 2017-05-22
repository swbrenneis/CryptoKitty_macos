#ifndef FORTUNAGENERATOR_H_INCLUDED
#define FORTUNAGENERATOR_H_INCLUDED

#include "../data/BigInteger.h"
#include <coder/ByteArray.h>
#include <deque>
#include <thread>

namespace CK {

class AES;

class FortunaGenerator {

    public:
        FortunaGenerator();
        ~FortunaGenerator();

    private:
        FortunaGenerator(const FortunaGenerator& other);
        FortunaGenerator& operator= (const FortunaGenerator& other);

    public:
        void generateRandomData(coder::ByteArray& bytes, uint32_t length);
        void start();

    private:
        coder::ByteArray generateBlocks(uint16_t k);
        void reseed(const coder::ByteArray& seed);
        void run();

    private:
        bool runFlag;
        std::thread *thread;
        typedef std::deque<coder::ByteArray> EntropyPools;
        EntropyPools pools;
        uint32_t poolCounter;
        AES *cipher;
        coder::ByteArray key;
        BigInteger counter;
        BigInteger limit;

};

}
#endif  // FORTUNAGENERATOR_H_INCLUDED
