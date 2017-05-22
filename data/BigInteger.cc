#include "data/BigInteger.h"
#include "random/Random.h"
#include "exceptions/BadParameterException.h"
#include <coder/ByteArray.h>
#include <algorithm>
#include <climits>
#include <cmath>
#include "NTL/ZZ.h"

namespace CK {

/*
 * Static initialization
 */
const BigInteger BigInteger::ZERO;
const BigInteger BigInteger::ONE(1);
const unsigned long long
    BigInteger::ULLONG_MSB = (ULLONG_MAX >> 1) ^ ULLONG_MAX;

/* Uses small coprime test, 64 rounds of Miller-Rabin, and
 * tests for Germain primality, if indicated.
 */ 
void makePrime(NTL::ZZ& n, bool sgPrime) {

    bool provisional = false;
    // Improve Miller-Rabin probability.
    long smallPrimes[] = { 3, 5, 7, 11, 13, 17, 19 };
    while (!provisional) {
        provisional = true;
        for (int i = 0; i < 7 && provisional; ++i) {
            provisional = NTL::GCD(n, NTL::ZZ(smallPrimes[i])) == 1;
        }
        if (!provisional) {
            n += 2;
        }
    }
    // Not sure why ProbPrime returns an integer.
    provisional = false;
    while (!provisional) {
        provisional = NTL::ProbPrime(n, 64) == 1;
        if (!provisional) {
            n += 2;
        }
    }

    // We'll just use Miller-Rabin for the Germain prime.
    if (sgPrime) {
        provisional = false;
        while (!provisional) {
            provisional = NTL::ProbPrime((n * 2) + 1, 64) == 1;
            if (!provisional) {
                n += 2;
                makePrime(n, true);
            }
        }
    }

}

/*
 * Default constructor
 * Sets value to 0
 */
BigInteger::BigInteger()
: number(new NTL::ZZ(0)){
}

/*
 * Copy constructor
 */
BigInteger::BigInteger(const BigInteger& other)
: number(new NTL::ZZ(*other.number)) {
}

/*
 * Constructor with initial long long value
 */
BigInteger::BigInteger(long initial)
: number(new NTL::ZZ(initial)) {
}

/*
 * Construct a BigInteger from a byte array
 */
BigInteger::BigInteger(const coder::ByteArray& bytes)
: number(0) {

    decode(bytes);

}

/*
 * Construct a BigInteger that is a probabilistic random prime, with the specified
 * length. The prime is tested with 64 Miller-Rabin rounds after some small prime
 * tests. The prime will also be a Sophie Germain prime if the boolean is true
 * (p and 2p+2 both prime). Selecting Germain primes is very time-consuming.
 */
BigInteger::BigInteger(int bits, bool sgPrime, Random& rnd) {

    if (bits == 0) {
        throw BadParameterException("Invalid bit length");
    }

    double dbits = bits;
    coder::ByteArray pBytes(ceil(dbits / 8));
    rnd.nextBytes(pBytes);

    // Load the big integer.
    NTL::ZZ work(pBytes[0]);
    for (unsigned n = 1; n < pBytes.getLength(); ++n) {
        work = (work * 256) + pBytes[n];
    }

    // Make sure it's positive.
    if (work < 0) {
        work = abs(work);
    }

    // Make sure it's odd.
    if (work % 2 == 0) {
        work++;
    }

    makePrime(work, sgPrime);
    number = new NTL::ZZ(work);

}

/*
 * Construct a BigInteger with a new NTL integer.
 */
BigInteger::BigInteger(NTL::ZZ *newNumber)
: number(newNumber) {
}

/*
 * Construct a BigInteger with a copy of an  NTL integer.
 */
BigInteger::BigInteger(const NTL::ZZ& otherNumber)
: number(new NTL::ZZ(otherNumber)) {
}

/*
 * Destructor
 */
BigInteger::~BigInteger() {

    delete number;

}

/*
 * Assignment operator
 */
BigInteger& BigInteger::operator= (const BigInteger& other) {

    delete number;
    number = new NTL::ZZ(*other.number);
    return *this;

}

/*
 * Assignment operator
 */
BigInteger& BigInteger::operator= (long value) {

    delete number;
    number = new NTL::ZZ(value);
    return *this;

}

/*
 * Prefix increment.
 */
BigInteger& BigInteger::operator++ () {

    ++(*number);
    return *this;

}

/*
 * Postfix increment.
 */
BigInteger BigInteger::operator++ (int) {

    BigInteger x = *this;
    ++(*this);
    return x;

}

/*
 * Returns a BigInteger equal to this plus addend.
 */
BigInteger BigInteger::add(const BigInteger& addend) const {

    return BigInteger(new NTL::ZZ(*number + *addend.number));

}

/*
 * Returns a BigInteger equal to bitwise and of this and logical.
 */
BigInteger BigInteger::And(const BigInteger& logical) const {

    return BigInteger(new NTL::ZZ(*number & *logical.number));

}

/*
 * Returns the number of bits in the binary representation of this integer.
 */
int BigInteger::bitLength() const {

    return NTL::NumBits(*number);

}

/*
 * Returns the number of bit in the encoded representation of this integer.
 */
int BigInteger::bitSize() const {

    coder::ByteArray enc(getEncoded());
    return enc.getLength() * 8;

}

/*
 * Decode a byte array with the indicated byte order.
 */
void BigInteger::decode(const coder::ByteArray& bytes) {

    delete number;
    number = new NTL::ZZ(0L);
    int bl = bytes.getLength(); // have to do this so the indexes
                                // don't wrap.

    for (int n = 0; n < bl; ++n) {
        *number = *number << 8;
        *number |= bytes[n];
    }

}

/*
 * returns a BigInteger that is eual to this divded by divisor.
 */
BigInteger BigInteger::divide(const BigInteger& divisor) const {

    return BigInteger(*number / *divisor.number);

}

/*
 * Returns true if this = other.
 */
bool BigInteger::equals(const BigInteger& other) const {

    return NTL::compare(*number, *other.number) == 0;

}

/*
 * Returns the greatest common denominator of this and a.
 */
BigInteger BigInteger::gcd(const BigInteger& a) const {

    return BigInteger(new NTL::ZZ(NTL::GCD(*number, *a.number)));

}

/*
 * Encodes the absolute value of the integer into an array
 * in the specified byte order.
 */
coder::ByteArray BigInteger::getEncoded() const {

    NTL::ZZ work(NTL::abs(*number));
    double bl = bitLength();
    int index = ceil(bl / 8);
    if (index == 0) {
        return coder::ByteArray(1,0);
    }
    coder::ByteArray result;
    while (index > 0) {
        long byte = work % 256;
        result.push(byte & 0xff);
        work = work / 256;
        index --;
    }
    // If the MSB is set in the lowest octet, we need to add
    // a sign byte so that the value is always positive.
    if ((result[0] & 0x80) != 0) {
        result.push(0);
    }
    return result;

}

/*
 * Returns a BigInteger that is the bitwise inversion of this.
 */
BigInteger BigInteger::invert() const {

    int bits = bitLength();
    NTL::ZZ mask;
    for (int i = 0; i < bits; ++i) {
        NTL::SetBit(mask, i);
    }
    return BigInteger(new NTL::ZZ(*number ^ mask));

}

/*
 * Returns true if the integer is probably prime.
 */
bool BigInteger::isProbablePrime() const {

    return NTL::ProbPrime(*number, 64) == 1;

}

/*
 * Returns a BigInteger that is this shifted left count times.
 */
BigInteger BigInteger::leftShift(long count) const {

    return BigInteger(new NTL::ZZ(*number << count));

}

/*
 * Returns true if this < other.
 */
bool BigInteger::lessThan(const BigInteger& other) const {

    return NTL::compare(*number, *other.number) < 0;

}

/*
 * Returns a BigInteger object that is the remainder of this divided by a.
 */
BigInteger BigInteger::mod(const BigInteger& a) const {

    return BigInteger(new NTL::ZZ(*number % *a.number));

}

/*
 * Returns a BigInteger that is equal to the modular inverse of this.
 * This and n must be coprime.
 */
BigInteger BigInteger::modInverse(const BigInteger& n) const {

    // Sadly, NTL has a bug that causes this to throw an exception when
    // the a >= n in a congruent to 1/x mod n.
    //try {
    //    return BigInteger(new NTL::ZZ(NTL::InvMod(*number, *n.number)));
    //}
    //catch (NTL::InvModErrorObject& e) {
    //    throw BadParameterException("Undefined inverse");
    //}

    if (gcd(n) != ONE) {
        throw BadParameterException("Modulus not coprime");
    }

    BigInteger t;
    BigInteger q;
    BigInteger x0(ZERO);
    BigInteger x1(ONE);
    BigInteger a(*number);
    BigInteger m(n);

    // Inverse modulus 1 is always 0. 
    if (n == ONE) {
        return BigInteger(ZERO);
    }

    while (a > ONE) {
        // q is quotient
        q = a / m;
        t = m;
        // m is remainder
        m = a % m;
        a = t;
        t = x0;
        // Extended Euclid substitution.
        x0 = x1 - q * x0;
        x1 = t;
    }

    // Make x1 positive
    if (x1 < ZERO) {
        x1 = x1 +  n;
    }

    return x1;

}

/*
 * Returns a BigInteger that is equal to (this**exp) % m.
 */
BigInteger BigInteger::modPow(const BigInteger& exp,
                const BigInteger& m) const {

    // This also appears to be bugged in NTL.
    //return BigInteger(new NTL::ZZ(
    //                    NTL::PowerMod(*number, *exp.number, *m.number)));

    // Solve for negative exponents using modular multiplicative
    // inverse.
    if (exp < ZERO) {
        return modInverse(m);
    }

    /*
     * Pseudocode from Schneier
    if modulus = 1 then return 0
    Assert :: (modulus - 1) * (modulus - 1) does not overflow base
    result := 1
    base := base mod modulus
    while exponent > 0
        if (exponent mod 2 == 1):
            result := (result * base) mod modulus
        exponent := exponent >> 1
        base := (base * base) mod modulus
    return result
    */

    if (m == ONE) {
        return BigInteger(ZERO);
    }

    BigInteger base(*this % m);
    BigInteger exponent(exp);
    BigInteger result(ONE);
    BigInteger TWO(2L);
    
    while (exponent > ZERO) {
        if (exponent % TWO == ONE) {
            result = (result * base) % m;
        }
        exponent = exponent >> 1;
        base = (base * base) % m;
    }
 
    return result;

}

/*
 * Returns a BigInteger that is the product of this and multiplier.
 */
BigInteger BigInteger::multiply(const BigInteger& multiplier) const {

    return BigInteger(new NTL::ZZ((*number) * (*multiplier.number)));

}

/*
 * Returns a BigInteger equal to bitwise or of this and logical.
 */
BigInteger BigInteger::Or(const BigInteger& logical) const {

    return BigInteger(new NTL::ZZ(*number | *logical.number));

}

/*
 * Send the value to a standard output stream.
 */
void BigInteger::out(std::ostream& o) const {

    o << *number;

}

/*
 * Returns a BigInteger equal to this**exp.
 */
BigInteger BigInteger::pow(long exp) const {

    return BigInteger(new NTL::ZZ(NTL::power(*number, exp)));

}

/*
 * Returns a BigInteger that is this shifted right count times.
 */
BigInteger BigInteger::rightShift(long count) const {

    return BigInteger(new NTL::ZZ(*number >> count));

}

/*
 * Sets the bit indicated by bitnum.
 */
void BigInteger::setBit(int bitnum) {

    NTL::SetBit(*number, bitnum);

}

/*
 * Returns a BigInteger equal to this minus subtractor.
 */
BigInteger BigInteger::subtract(const BigInteger& subtractor) const {

    return BigInteger(new NTL::ZZ(*number - *subtractor.number));

}

/*
 * Returns true if the specified bit is set.
 */
bool BigInteger::testBit(int bitnum) const {

    return NTL::bit(*number, bitnum) == 1;

}

/*
 * Returns a long (64 bit) representation of this integer.
 */
long BigInteger::toLong() {

    return NTL::to_long(*number);

}

/*
 * Returns a BigInteger equal to bitwise xor of this and logical.
 */
BigInteger BigInteger::Xor(const BigInteger& logical) const {

    return BigInteger(new NTL::ZZ(*number ^ *logical.number));

}

}

// Global operators
bool operator== (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.equals(rhs); }
bool operator!= (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return !lhs.equals(rhs); }
bool operator< (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.lessThan(rhs); }
bool operator<= (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.lessThan(rhs) || lhs.equals(rhs); }
bool operator> (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return !lhs.lessThan(rhs) && !lhs.equals(rhs); }
bool operator>= (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return !lhs.lessThan(rhs); }
CK::BigInteger operator- (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.subtract(rhs); }
CK::BigInteger operator- (const CK::BigInteger& lhs)
{ return CK::BigInteger::ZERO.subtract(lhs); }
CK::BigInteger operator+ (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.add(rhs); }
CK::BigInteger operator* (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.multiply(rhs); }
CK::BigInteger operator/ (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.divide(rhs); }
CK::BigInteger operator% (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.mod(rhs); }
CK::BigInteger operator^ (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.Xor(rhs); }
CK::BigInteger operator| (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.Or(rhs); }
CK::BigInteger operator& (const CK::BigInteger& lhs, const CK::BigInteger& rhs)
{ return lhs.And(rhs); }
CK::BigInteger operator~ (const CK::BigInteger& lhs)
{ return lhs.invert(); }
CK::BigInteger operator<< (const CK::BigInteger& lhs, long rhs)
{ return lhs.leftShift(rhs); }
CK::BigInteger operator>> (const CK::BigInteger& lhs, long rhs)
{ return lhs.rightShift(rhs); }
std::ostream& operator<< (std::ostream& out, const CK::BigInteger& bi)
{ bi.out(out); return out; }
