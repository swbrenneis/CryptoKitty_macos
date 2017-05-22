#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include "BlockCipher.h"

namespace CK {

class AES : public BlockCipher {

   public:
       enum KeySize { AES128=16, AES192=24, AES256=32 };

    public:
        AES(KeySize ks);
        ~AES();

    private:
        AES(const AES& other);
        AES& operator= (const AES& other);

    public:
        unsigned blockSize() const { return 16; }
        coder::ByteArray
                decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key);
        coder::ByteArray
                encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key);
        void reset() {}

    private:
        typedef uint8_t Word[4];
        inline void copy(Word& a, const Word& b) const {
            a[0] = b[0]; a[1] = b[1]; a[2] = b[2]; a[3] = b[3];
        }
        void rol(int count, Word& a) const {
            uint8_t tmp;
            for (int n = 0; n < count; ++n) {
                tmp = a[3];
                a[3] = a[2];
                a[2] = a[1];
                a[1] = a[0];
                a[0] = tmp;
            }
        }
        void ror(int count, Word& a) const {
            uint8_t tmp;
            for (int n = 0; n < count; ++n) {
                tmp = a[0];
                a[0] = a[1];
                a[1] = a[2];
                a[2] = a[3];
                a[3] = tmp;
            }
        }
        struct StateArray {
            Word row0;
            Word row1;
            Word row2;
            Word row3;
        };

    private:
        void AddRoundKey(const Word *roundKey);
        void Cipher(const coder::ByteArray& plaintext, const Word *keySchedule);
        void InvCipher(const coder::ByteArray& ciphertext, const Word *KeySchedule);
        void InvMixColumns();
        void InvShiftRows();
        void InvSubBytes();
        void KeyExpansion(const coder::ByteArray& key, Word *keySchedule) const;
        void MixColumns();
        uint8_t RijndaelMult(uint8_t lhs, uint8_t rhs) const;
        void Rotate(coder::ByteArray& w) const;
        void ShiftRows();
        void SubBytes();

    private:
        KeySize keySize;
        unsigned keyScheduleSize;
        int Nk;
        int Nr;
        StateArray state;
    
        static const uint8_t Rcon[256];
        static const uint8_t Sbox[256];
        static const uint8_t InvSbox[256];
        static const int Nb;
        static const StateArray cx;
        static const StateArray invax;

};

}

#endif  // AES_H_INCLUDED
