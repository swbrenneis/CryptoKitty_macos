#ifndef AEADCIPHERMODE_H_INCLUDED
#define AEADCIPHERMODE_H_INCLUDED

#include "BlockCipherMode.h"

namespace CK {

class AEADCipherMode : public BlockCipherMode {

    protected:
        AEADCipherMode() {}
        
    public:
        virtual ~AEADCipherMode() {}

    private:
        AEADCipherMode(const AEADCipherMode& other);
        AEADCipherMode& operator= (const AEADCipherMode& other);

    public:
        virtual void setAuthenticationData(const coder::ByteArray& ad)=0;

};

}

#endif  // AEADCIPHERMODE_H_INCLUDED
