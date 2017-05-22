#ifndef NANOTIME_H_INCLUDED
#define NANOTIME_H_INCLUDED

namespace CK {

/*
 * Encapsulation of *nix clock_time function
 */
class NanoTime {

    public:
        NanoTime();
        ~NanoTime();

    private:
        NanoTime(const NanoTime& other);

    public:
        unsigned long getFullTime() const; // Time in nanoseconds.
        unsigned long getNanoseconds() const; // Returns just nanoseconds.
        unsigned long getSeconds() const; // Returns just seconds.
        void newTime(); // Get new time value.

    private:
        unsigned long time;
        unsigned long seconds;
        unsigned long nanoseconds;

};

}

#endif // NANOTIME_H_INCLUDED
