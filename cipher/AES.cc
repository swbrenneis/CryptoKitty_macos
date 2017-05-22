#include "cipher/AES.h"
#include "exceptions/BadParameterException.h"

namespace CK {

// Static initialization
const uint8_t AES::Rcon[256] =
{   0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d };

const uint8_t AES::Sbox[256] = 
{   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

const uint8_t AES::InvSbox[256] = 
{   0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

const int AES::Nb = 4;

const AES::StateArray AES::cx =
{   .row0 = { 2, 3, 1, 1 },
    .row1 = { 1, 2, 3, 1 },
    .row2 = { 1, 1, 2, 3 },
    .row3 = { 3, 1, 1, 2 } };

const AES::StateArray AES::invax =
{   .row0 = { 0x0e, 0x0b, 0x0d, 0x09 },
    .row1 = { 0x09, 0x0e, 0x0b, 0x0d },
    .row2 = { 0x0d, 0x09, 0x0e, 0x0b },
    .row3 = { 0x0b, 0x0d, 0x09, 0x0e } };

AES::AES(KeySize ks)
: keySize(ks) {

    switch (keySize) {
        case AES128:
            Nk = 4;
            Nr = 10;
            break;
        case AES192:
            Nk = 6;
            Nr = 12;
            break;
        case AES256:
            Nk = 8;
            Nr = 14;
            break;
        default:
            throw BadParameterException("AES : Invalid key length");
    }
    keyScheduleSize = Nb * (Nr + 1);

}

AES::~AES() {
}

/*
 * Add (xor) the round key state.
 */
void AES::AddRoundKey(const Word *roundKey) {

    Word column;
    for (int col = 0; col < 4; ++col) {
        copy(column, roundKey[col]);
        state.row0[col] = state.row0[col] ^ column[0];
        state.row1[col] = state.row1[col] ^ column[1];
        state.row2[col] = state.row2[col] ^ column[2];
        state.row3[col] = state.row3[col] ^ column[3];
    }

}

/*
 * From FIPS 197
 *
 * Nb = 4 for this FIPS
 * Nr = 10, 12, 14 for 128, 192, 256 bit keys respectively
 * Nk = Number of 32 bit words in the cipher key. 4, 6, or 8.
 * 
 * Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
 *
 * begin
 *
 *  byte state[4,Nb]
 *
 *  state = in
 *
 *  AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4
 *
 *  for round = 1 step 1 to Nr–1
 *
 *      SubBytes(state) // See Sec. 5.1.1
 *
 *      ShiftRows(state) // See Sec. 5.1.2
 *
 *      MixColumns(state) // See Sec. 5.1.3
 *
 *      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
 *
 *  end for
 *
 *  SubBytes(state)
 *
 *  ShiftRows(state)
 *
 *  AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
 *
 *  out = state
 *
 * end
 *  
 */
void AES::Cipher(const coder::ByteArray& plaintext, const Word *keySchedule) {

    if (plaintext.getLength() != Nb * 4) {
        throw BadParameterException("AES Cipher: Invalid block size.");
    }

    // Load the state
    for (int n = 0; n < 4; ++n) {
        state.row0[n] = plaintext[n*4];
        state.row1[n] = plaintext[(n*4)+1];
        state.row2[n] = plaintext[(n*4)+2];
        state.row3[n] = plaintext[(n*4)+3];
    }

    Word roundKey[4];
    for (int n = 0; n < 4; ++n) {
        copy(roundKey[n], keySchedule[n]);
    }
    AddRoundKey(roundKey);

    // Process rounds
    for (int round = 1; round < Nr; ++round) {
        SubBytes();
        ShiftRows();
        MixColumns();
        for (int n = 0; n < 4; ++n) {
            copy(roundKey[n], keySchedule[(round * Nb)+n]);
        }
        AddRoundKey(roundKey);
    }

    // Finish up.
    SubBytes();
    ShiftRows();
    for (int n = 0; n < 4; ++n) {
        copy(roundKey[n], keySchedule[(Nr*Nb)+n]);
    }
    AddRoundKey(roundKey);

}

/*
 * Perform the block cipher on the plaintext using the
 * supplied key.
 */
coder::ByteArray AES::decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key) {

    if (ciphertext.getLength() != Nb * 4) {
        throw BadParameterException("AES decrypt: Illegal ciphertext size");
    }

    if (key.getLength() != keySize) {
        throw BadParameterException("AES decrypt: Invalid key");
    }

    Word *keySchedule = new Word[keyScheduleSize];
    KeyExpansion(key, keySchedule);
    InvCipher(ciphertext, keySchedule);
    coder::ByteArray plaintext;
    for (int col = 0; col < 4; ++col) {
        plaintext.append(state.row0[col]);
        plaintext.append(state.row1[col]);
        plaintext.append(state.row2[col]);
        plaintext.append(state.row3[col]);
    }

    delete[] keySchedule;
    return plaintext;

}

/*
 * Perform the block cipher on the plaintext using the
 * supplied key.
 */
coder::ByteArray AES::encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key) {

    if (plaintext.getLength() != Nb * 4) {
        throw BadParameterException("AES encrypt: Illegal plaintext size");
    }

    if (key.getLength() != keySize) {
        throw BadParameterException("AES encrypt: Invalid key");
    }

    Word *keySchedule = new Word[keyScheduleSize];
    KeyExpansion(key, keySchedule);
    Cipher(plaintext, keySchedule);
    coder::ByteArray ciphertext;
    for (int col = 0; col < 4; ++col) {
        ciphertext.append(state.row0[col]);
        ciphertext.append(state.row1[col]);
        ciphertext.append(state.row2[col]);
        ciphertext.append(state.row3[col]);
    }

    delete[] keySchedule;
    return ciphertext;

}

/*
 * InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
 *
 * begin
 *
 *  byte state[4,Nb]
 *
 *  state = in
 *
 *  AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
 *
 *  for round = Nr-1 step -1 downto 1
 *
 *      InvShiftRows(state) // See Sec. 5.3.1
 *
 *      InvSubBytes(state) // See Sec. 5.3.2
 *
 *      AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
 *
 *      InvMixColumns(state) // See Sec. 5.3.3
 *
 *  end for
 *
 *  InvShiftRows(state)
 *
 *  InvSubBytes(state)
 *
 *  AddRoundKey(state, w[0, Nb-1])
 *
 *  out = state
 *
 * end
 */
void AES::InvCipher(const coder::ByteArray& ciphertext, const Word *keySchedule) {

    if (ciphertext.getLength() != Nb * 4) {
        throw BadParameterException("AES InvCipher: Invalid block size.");
    }

    // Load the state
    for (int n = 0; n < 4; ++n) {
        state.row0[n] = ciphertext[n*4];
        state.row1[n] = ciphertext[(n*4)+1];
        state.row2[n] = ciphertext[(n*4)+2];
        state.row3[n] = ciphertext[(n*4)+3];
    }

    Word roundKey[4];
    for (int n = 0; n < 4; ++n) {
        copy(roundKey[n], keySchedule[(Nr*Nb)+n]);
    }
    AddRoundKey(roundKey);

    for (int round = Nr - 1; round >= 1; --round) {
        InvShiftRows();
        InvSubBytes();
        for (int n = 0; n < 4; ++n) {
            copy(roundKey[n], keySchedule[(round*Nb)+n]);
        }
        AddRoundKey(roundKey);
        InvMixColumns();
    }

    InvShiftRows();
    InvSubBytes();
    for (int n = 0; n < 4; ++n) {
        copy(roundKey[n], keySchedule[n]);
    }
    AddRoundKey(roundKey);

}

/*
 * Matrix multiplication transformation.
 *
 * Each column in the state is multiplied and added as
 * a 4 byte polynomial against the inverse polynomial
 * function ax. The "multiplication" and "addition" are
 * as defined in Rijndael finite field operations.
 */
void AES::InvMixColumns() {

    StateArray m = state;

    for (int c = 0; c < 4; ++c) {
        state.row0[c] = RijndaelMult(invax.row0[0], m.row0[c])
                        ^ RijndaelMult(invax.row0[1], m.row1[c])
                        ^ RijndaelMult(invax.row0[2], m.row2[c])
                        ^ RijndaelMult(invax.row0[3], m.row3[c]);
        state.row1[c] = RijndaelMult(invax.row1[0], m.row0[c])
                        ^ RijndaelMult(invax.row1[1], m.row1[c])
                        ^ RijndaelMult(invax.row1[2], m.row2[c])
                        ^ RijndaelMult(invax.row1[3], m.row3[c]);
        state.row2[c] = RijndaelMult(invax.row2[0], m.row0[c])
                        ^ RijndaelMult(invax.row2[1], m.row1[c])
                        ^ RijndaelMult(invax.row2[2], m.row2[c])
                        ^ RijndaelMult(invax.row2[3], m.row3[c]);
        state.row3[c] = RijndaelMult(invax.row3[0], m.row0[c])
                        ^ RijndaelMult(invax.row3[1], m.row1[c])
                        ^ RijndaelMult(invax.row3[2], m.row2[c])
                        ^ RijndaelMult(invax.row3[3], m.row3[c]);
    }

}

/*
 * Columns are rotated as follows:
 *      row 0 rotated 0 left.
 *      row 1 rotated 1 left.
 *      row 2 rotated 2 left.
 *      row 3 rotated 3 left.
 */
void AES::InvShiftRows() {

    rol(1, state.row1);
    rol(2, state.row2);
    rol(3, state.row3);
}

/*
 * Perform the inverse S-Box transformation.
 * For each byte in the state s[r,c] substitute with
 * the byte at InvSbox[s[r,c]].
 */
void AES::InvSubBytes() {

    for (int col = 0; col < 4; ++col) {
        state.row0[col] = InvSbox[state.row0[col]];
        state.row1[col] = InvSbox[state.row1[col]];
        state.row2[col] = InvSbox[state.row2[col]];
        state.row3[col] = InvSbox[state.row3[col]];
    }

}

/*
 * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
 *
 *  begin
 *
 *      word temp
 *
 *      i = 0
 *
 *      while (i < Nk)
 *
 *          w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
 *
 *          i = i+1
 *
 *      end while
 *
 *      i = Nk
 *
 *      while (i < Nb * (Nr+1)]
 *
 *          temp = w[i-1]
 *
 *          if (i mod Nk = 0)
 *
 *              temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
 *
 *          else if (Nk > 6 and i mod Nk = 4)
 *
 *              temp = SubWord(temp)
 *
 *          end if
 *
 *          w[i] = w[i-Nk] xor temp
 *
 *          i = i + 1
 *
 *      end while
 *
 * end
 *  
 */
void AES::KeyExpansion(const coder::ByteArray& key, Word *keySchedule) const {

    // Key consistency check.
    if (key.getLength() != keySize) {
            throw BadParameterException("AES ExpandKey: Invalid key size");
    }

    Word temp;

    // Copy the key into the key schedule.
    //keySchedule.copy(0, key, 0);
    for (int i = 0; i < Nk; ++i) {
        for (int n = 0; n < 4; ++n) {
            keySchedule[i][n] = key[(i*4)+n];
        }
    }

    for (int i = Nk; i < Nb * (Nr + 1); ++i) {
        copy(temp, keySchedule[i-1]);
        if (i % Nk == 0) {
            // RotWord()
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // SubWord()
            for (int n = 0; n < 4; ++n) {
                temp[n] = Sbox[temp[n]];
            }
            // xor Rcon
            temp[0] = temp[0] ^ Rcon[i / Nk];
                
        }
        else if (Nk > 6 && i % Nk == 4) { // 256 bit keys
            // SubWord()
            for (int n = 0; n < 4; ++n) {
                temp[n] = Sbox[temp[n]];
            }
        }
        Word wink;
        copy(wink, keySchedule[i-Nk]);
        for (int n = 0; n < 4; ++n) {
            wink[n] = wink[n] ^ temp[n];
        }
        copy(keySchedule[i],wink);
    }

}

/*
 * Matrix multiplication transformation.
 *
 * Each column in the state is multiplied and added as
 * a 4 byte polynomial against the polynomial function cx.
 * The "multiplication" and "addition" are as defined in
 * Rijndael finite field operations.
 */
void AES::MixColumns() {

    StateArray m = state;

    for (int c = 0; c < 4; ++c) {
        state.row0[c] = RijndaelMult(cx.row0[0], m.row0[c])
                        ^ RijndaelMult(cx.row0[1], m.row1[c])
                        ^ RijndaelMult(cx.row0[2], m.row2[c])
                        ^ RijndaelMult(cx.row0[3], m.row3[c]);
        state.row1[c] = RijndaelMult(cx.row1[0], m.row0[c])
                        ^ RijndaelMult(cx.row1[1], m.row1[c])
                        ^ RijndaelMult(cx.row1[2], m.row2[c])
                        ^ RijndaelMult(cx.row1[3], m.row3[c]);
        state.row2[c] = RijndaelMult(cx.row2[0], m.row0[c])
                        ^ RijndaelMult(cx.row2[1], m.row1[c])
                        ^ RijndaelMult(cx.row2[2], m.row2[c])
                        ^ RijndaelMult(cx.row2[3], m.row3[c]);
        state.row3[c] = RijndaelMult(cx.row3[0], m.row0[c])
                        ^ RijndaelMult(cx.row3[1], m.row1[c])
                        ^ RijndaelMult(cx.row3[2], m.row2[c])
                        ^ RijndaelMult(cx.row3[3], m.row3[c]);
    }

}

/*
 * Run the following loop eight times (once per bit).
 * It is OK to stop when a or b are zero before an iteration:
 * 1. If the rightmost bit of b is set, exclusive OR the product
 *    by the value of a. This is polynomial addition.
 * 2. Shift b one bit to the right, discarding the rightmost bit,
 *    and making the leftmost bit have a value of zero. This divides
 *    the polynomial by x, discarding the x0 term.
 * 3. Keep track of whether the leftmost bit of a is set to one
 *    and call this value carry.
 * 4. Shift a one bit to the left, discarding the leftmost bit,
 *    and making the new rightmost bit zero. This multiplies the
 *    polynomial by x, but we still need to take account of carry
 *    which represented the coefficient of x7.
 * 5. If carry had a value of one, exclusive or a with the
 *    hexadecimal number 0x1b (00011011 in binary). 0x1b corresponds
 *    to the irreducible polynomial with the high term eliminated.
 *    Conceptually, the high term of the irreducible polynomial and
 *    carry add modulo 2 to 0.
 *
 */
uint8_t AES::RijndaelMult(uint8_t lhs, uint8_t rhs) const {

    if (lhs == 0 || rhs == 0) {
        return 0;
    }

    if (lhs == 1) {
        return rhs;
    }

    if (rhs == 1) {
        return lhs;
    }

    uint8_t a = lhs;
    uint8_t b = rhs;
    uint8_t product = 0;
    uint8_t carry;
    for (int l = 0; l < 8 && a > 0 && b > 0; ++l) {
        if ((b & 1) != 0) {
            product = product ^ a;
        }
        carry = a & 0x80;
        a = a << 1;
        if (carry != 0) {
            a = a ^ 0x1b;
        }
        b = b >> 1; 
    }
    return product;

}

/*
 * Rotate a word left one byte.
 */
void AES::Rotate(coder::ByteArray& w) const {

    unsigned char t = w[3];
    w[3] = w[2];
    w[2] = w[1];
    w[1] = w[0];
    w[0] = t;

}

/*
 * Columns are rotated as follows:
 *      row 0 rotated 0 left.
 *      row 1 rotated 1 left.
 *      row 2 rotated 2 left.
 *      row 3 rotated 3 left.
 */
void AES::ShiftRows() {

    /*StateArray temp = state;
    for (int col = 0; col < 4; ++col) {
        state.row0[col] = temp.row0[col];
        state.row1[col] = temp.row1[(col+1) % 4];
        state.row2[col] = temp.row2[(col+2) % 4];
        state.row3[col] = temp.row3[(col+3) % 4];
    }*/
    ror(1, state.row1);
    ror(2, state.row2);
    ror(3, state.row3);

}

/*
 * Perform the S-Box transformation.
 * For each byte in the state s[r,c] substitute with
 * the byte at Sbox[s[r,c]].
 */
void AES::SubBytes() {

    for (int col = 0; col < 4; ++col) {
        state.row0[col] = Sbox[state.row0[col]];
        state.row1[col] = Sbox[state.row1[col]];
        state.row2[col] = Sbox[state.row2[col]];
        state.row3[col] = Sbox[state.row3[col]];
    }

}

}
