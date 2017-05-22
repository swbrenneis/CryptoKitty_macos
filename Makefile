INSTALL_PATH= /usr/local
CHOWN_USER= root:wheel
CK_INCLUDE= $(INSTALL_PATH)/include/CryptoKitty-C

LD= g++
LDPATHS= -L/usr/local/lib
LDLIBS=  -lntl -lgmp -lcoder
LDFLAGS= -Wall -g -shared

CIPHER_OBJECT= cipher/AES.o cipher/OAEPrsaes.o cipher/PKCS1rsaes.o cipher/PKCS1rsassa.o \
			   cipher/PSSmgf1.o cipher/PSSrsassa.o cipher/RSA.o
CIPHER_HEADER= include/cipher/AES.h include/cipher/OAEPrsaes.h include/cipher/PKCS1rsaes.h \
			   include/cipher/PKCS1rsassa.h include/cipher/PSSmgf1.h \
			   include/cipher/PSSrsassa.h include/cipher/RSA.h
CIPHER_SOURCE= $(CIPHER_OBJECT:.o=.cc)
CIPHERMODES_OBJECT= ciphermodes/CBC.o ciphermodes/CTR.o ciphermodes/GCM.o \
					ciphermodes/MtE.o
CIPHERMODES_HEADER= include/ciphermodes/CBC.h include/ciphermodes/CTR.h \
					include/ciphermodes/GCM.h include/ciphermodes/MtE.h
CIPHERMODES_SOURCE= $(CIPHERMODES_OBJECT:.o=.cc)
DATA_OBJECT= data/BigInteger.o data/NanoTime.o
DATA_HEADER= include/data/BigInteger.h include/data/NanoTime.h
DATA_SOURCE= $(DATA_OBJECT:.o=.cc)
DIGEST_OBJECT= digest/SHA1.o digest/SHA256.o digest/SHA384.o digest/SHA512.o digest/DigestBase.o
DIGEST_HEADER= include/digest/SHA1.h include/digest/SHA256.h include/digest/SHA384.h \
			   include/digest/SHA512.h include/digest/DigestBase.h
DIGEST_SOURCE= $(DIGEST_OBJECT:.o=.cc)
ENCODING_OBJECT= encoding/Base64.o encoding/DERCodec.o encoding/GCMCodec.o encoding/PEMCodec.o \
				 encoding/RSACodec.o
ENCODING_HEADER= include/encoding/Base64.h include/encoding/DERCodec.h include/encoding/GCMCodec.h \
				 include/encoding/PEMCodec.h include/encoding/RSACodec.h
ENCODING_SOURCE= $(ENCODING_OBJECT:.o=.cc)
KEYS_OBJECT= keys/DHKeyExchange.o keys/ECDHKeyExchange.o keys/PrivateKey.o \
			 keys/PublicKey.o keys/RSAKeyPairGenerator.o keys/RSAPrivateKey.o \
			 keys/RSAPrivateCrtKey.o keys/RSAPrivateModKey.o \
			 keys/RSAPublicKey.o
KEYS_HEADER= include/keys/DHKeyExchange.h include/keys/ECDHKeyExchange.h \
			 include/keys/PrivateKey.h include/keys/PublicKey.h \
			 include/keys/RSAKeyPairGenerator.h include/keys/RSAPrivateKey.h \
			 include/keys/RSAPrivateCrtKey.h include/keys/RSAPrivateModKey.h \
			 include/keys/RSAPublicKey.h
KEYS_SOURCE= $(KEYS_OBJECT:.o=.cc)
MAC_OBJECT= mac/HMAC.o
MAC_HEADER= include/mac/HMAC.h
MAC_SOURCE= $(MAC_OBJECT:.o=.cc)
RANDOM_OBJECT= random/BBSSecureRandom.o random/CMWCRandom.o random/FortunaSecureRandom.o \
			   random/FortunaGenerator.o random/Random.o
RANDOM_HEADER= include/random/BBSSecureRandom.h include/random/CMWCRandom.h \
			   include/random/FortunaSecureRandom.h include/random/FortunaGenerator.h \
			   include/random/Random.h include/random/SecureRandom.h
RANDOM_SOURCE= $(RANDOM_OBJECT:.o=.cc)
SIGNATURE_OBJECT= signature/RSASignature.o
SIGNATURE_HEADER= include/signature/RSASignature.h
SIGNATURE_SOURCE= $(SIGNATURE_OBJECT:.o=.cc)

CKOBJECT= $(CIPHER_OBJECT) $(CIPHERMODES_OBJECT) $(DATA_OBJECT) $(ENCODING_OBJECT) \
		  $(DIGEST_OBJECT) $(KEYS_OBJECT) $(MAC_OBJECT) $(RANDOM_OBJECT) \
		  $(SIGNATURE_OBJECT)

LIBRARY= libcryptokitty.dylib

.SUFFIXES:

.PHONY: clean install

all: $(LIBRARY)

$(CIPHER_OBJECT): $(CIPHER_SOURCE) $(CIPHER_HEADER)
	$(MAKE) -C cipher

$(CIPHERMODES_OBJECT): $(CIPHERMODES_SOURCE) $(CIPHERMODES_HEADER)
	$(MAKE) -C ciphermodes

$(DATA_OBJECT): $(DATA_SOURCE) $(DATA_HEADER)
	$(MAKE) -C data

$(ENCODING_OBJECT): $(ENCODING_SOURCE) $(ENCODING_HEADER)
	$(MAKE) -C encoding 

$(DIGEST_OBJECT): $(DIGEST_SOURCE) $(DIGEST_HEADER)
	$(MAKE) -C digest

$(KEYS_OBJECT): $(KEYS_SOURCE) $(KEYS_HEADER)
	$(MAKE) -C keys

$(MAC_OBJECT): $(MAC_SOURCE) $(MAC_HEADER)
	$(MAKE) -C mac

$(RANDOM_OBJECT): $(RANDOM_SOURCE) $(RANDOM_HEADER)
	$(MAKE) -C random

$(SIGNATURE_OBJECT): $(SIGNATURE_SOURCE) $(SIGNATURE_HEADER)
	$(MAKE) -C signature

$(LIBRARY): $(CKOBJECT)
	    $(LD) -o $@ $(CKOBJECT) $(LDFLAGS) $(LDPATHS) $(LDLIBS)

install: $(LIBRRY)
	rm -rf $(CK_INCLUDE)
	mkdir -p $(CK_INCLUDE)
	cp -R -p include/* $(CK_INCLUDE)
	chmod 755 $(CK_INCLUDE)
	chmod 755 $(CK_INCLUDE)/
	chown -R $(CHOWN_USER) $(CK_INCLUDE)
	mkdir -p $(INSTALL_PATH)/lib
	cp -p $(LIBRARY) $(INSTALL_PATH)/lib
	chmod 755 $(INSTALL_PATH)/lib/$(LIBRARY)
	chown $(CHOWN_USER) $(INSTALL_PATH)/lib/$(LIBRARY)

clean:
	rm -f $(LIBRARY)
	cd cipher && $(MAKE) clean
	cd ciphermodes && $(MAKE) clean
	cd data && $(MAKE) clean
	cd digest && $(MAKE) clean
	cd encoding && $(MAKE) clean
	cd keys && $(MAKE) clean
	cd mac && $(MAKE) clean
	cd random && $(MAKE) clean
	cd signature && $(MAKE) clean

