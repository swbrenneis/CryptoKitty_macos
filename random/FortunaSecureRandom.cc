#include "random/FortunaSecureRandom.h"
#include "random/FortunaGenerator.h"
#include "exceptions/SecureRandomException.h"
#include <coder/Unsigned64.h>
#include <coder/Unsigned32.h>
#include <sstream>
#include <memory>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

namespace CK {

static const short FORTUNAPORT = 16574;
static const char *LOCALHOST = "127.0.0.1";

FortunaSecureRandom::FortunaSecureRandom() {
}

FortunaSecureRandom::~FortunaSecureRandom() {
}

void FortunaSecureRandom::nextBytes(coder::ByteArray& bytes) {

    if (bytes.getLength() > 0xffffffff) {
        throw SecureRandomException("Invalid request size");
    }
    uint16_t length = bytes.getLength();
    uint16_t offset = 0;
    coder::ByteArray rbytes;
    while (length > 0) {
        rbytes.clear();
        uint16_t read;
        read = readBytes(rbytes, length);
        bytes.copy(offset, rbytes, 0, read);
        length -= read;
        offset += read;
    }

}

/*
 * Returns the next 32 bits of entropy.
 */
uint32_t FortunaSecureRandom::nextUnsignedInt() {

    coder::ByteArray bytes(4, 0);
    nextBytes(bytes);
    coder::Unsigned32 u32(bytes);
    return u32.getValue();

}

/*
 * Returns the next 64 bits of entropy.
 */
uint64_t FortunaSecureRandom::nextUnsignedLong() {

    coder::ByteArray bytes(8, 0);
    nextBytes(bytes);
    coder::Unsigned64 u64(bytes);
    return u64.getValue();

}

uint16_t FortunaSecureRandom::readBytes(coder::ByteArray& bytes, uint16_t count) const {

    int socket = ::socket(PF_INET, SOCK_DGRAM, 0);
    if (socket < 0) {
        std::ostringstream str;
        str << "Socket creation error: " << strerror(errno) << std::endl;
        throw SecureRandomException(str.str());
    }

    int optval = 1;
    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &optval , sizeof(int));

    sockaddr_in name;
    name.sin_family = AF_INET;
    name.sin_port = htons(FORTUNAPORT);
    hostent *hostinfo = gethostbyname(LOCALHOST);
    name.sin_addr = *(reinterpret_cast<in_addr*>(hostinfo->h_addr));
    socklen_t saLength = sizeof(sockaddr_in);

    uint8_t countBytes[2];
    countBytes[1] = count & 0xff;
    countBytes[0] = count >> 8;
    int res = sendto(socket, static_cast<void*>(countBytes), 2, 0,
                                    reinterpret_cast<sockaddr*>(&name), saLength);
    if (res < 0) {
        std::ostringstream str;
        str << "Socket send error: " << strerror(errno) << std::endl;
        throw SecureRandomException(str.str());
    }
    std::unique_ptr<uint8_t[]> inBytes(new uint8_t[count]);
    res = recvfrom(socket, static_cast<void*>(inBytes.get()), count, 0,
                                    reinterpret_cast<sockaddr*>(&name), &saLength);
    if (res < 0) {
        std::ostringstream str;
        str << "Socket receive error: " << strerror(errno) << std::endl;
        throw SecureRandomException(str.str());
    }

    bytes.append(inBytes.get(), res);
    return res;

}

}

