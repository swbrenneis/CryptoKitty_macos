#include "data/NanoTime.h"
#include "exceptions/DataException.h"
#include <time.h>
#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

namespace CK {

NanoTime::NanoTime() {

     newTime();

}

NanoTime::~NanoTime() {
}

unsigned long NanoTime::getFullTime() const {

    return time;

}

unsigned long NanoTime::getNanoseconds() const {

    return nanoseconds;

}

unsigned long NanoTime::getSeconds() const {

    return seconds;

}

void NanoTime::newTime() {

    timespec now;
#ifdef __MACH__ // OS X does not have clock_gettime, use clock_get_time
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    now.tv_sec = mts.tv_sec;
    now.tv_nsec = mts.tv_nsec;
#else
    // We use CLOCK_MONOTONIC_RAW because it can't be
    // manipulated by settime, NTP, or adjtime
    int ret = clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    if (ret != 0) {
        throw DataException("NanoTime clock retrieval failed.");
    }
#endif
    time = (now.tv_sec * 1000000000) + now.tv_nsec;
    seconds = now.tv_sec;
    nanoseconds = now.tv_nsec;

}

}

