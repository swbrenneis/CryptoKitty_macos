DEV_HOME=$(HOME)/dev

CPP= g++
CPPDEFINES= -D_GNU_SOURCE -D_REENTRANT
CPPINCLUDES= -I../include $(TAILS_INCLUDE)
CPPFLAGS= -Wall -g -MMD -std=c++11 -fPIC $(CPPDEFINES) $(CPPINCLUDES)

CPP_SOURCES= AES.cc OAEPrsaes.cc PKCS1rsaes.cc PKCS1rsassa.cc PSSmgf1.cc PSSrsassa.cc RSA.cc
CPP_OBJECT= $(CPP_SOURCES:.cc=.o)
DEPEND= $(CPP_OBJECT:.o=.d)

.PHONY: clean

all: $(CPP_OBJECT)

$(CPP_OBJECT): %.o: %.cc
	$(CPP) -c $(CPPFLAGS) -o $@ $<

clean:
	-rm -f $(CPP_OBJECT) $(DEPEND) $(PROGRAM)

-include $(DEPEND)
