#ifndef JNIREFERENCE_H_INCLUDED
#define JNIREFERENCE_H_INCLUDED

namespace CK {

/**
 * This is an empty superclass to enable the dispose method for
 * JNI backing classes. See JNIReference.java in the CryptoKitty Java
 * tree.
 */
class JNIReference {

    public:
        JNIReference() : jni(false) {}
        virtual ~JNIReference() {}

    private:
        JNIReference(const JNIReference& other);
        JNIReference& operator= (const JNIReference& other);

    public:
        void setJni(bool j) { jni = j; }

    protected:
        bool jni;   // Indicates this is a JNI reference implementation.

};

}

#endif // JNIREFERENCE_H_INCLUDED

