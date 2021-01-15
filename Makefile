# PSC Makefile

KEY1=\"secret1\"
KEY2=\"secret2\"

CXX=c++
DEFS=-DPSC_READ_KEY=$(KEY1) -DPSC_WRITE_KEY=$(KEY2)
CXXFLAGS=-c -Wall -O2 -std=c++11 -pedantic
LIBS=-lcrypto

# If you have a custom openssl or libressl or run on OSX:
#SSL_PATH=/opt/ssl/openssl-1.1.1
#DEFS+=-I$(SSL_PATH)/include
#LIBS+=-L$(SSL_PATH)/lib

# Not necessary for OSX
#LIBS+=-Wl,--rpath=$(SSL_PATH)/lib


.PHONY: all clean

ifeq ($(shell uname), Linux)
DEFS+=-DHAVE_UNIX98
endif

all: pscl pscr

clean:
	rm -f *.o

pscl: misc.o client.o pcwrap.o pty.o pty98.o net.o
	$(CXX) $^ -o $@ $(LIBS)

pscr: misc.o server.o pty.o pty98.o pcwrap.o net.o
	$(CXX) $^ -o $@ $(LIBS)

pcwrap.o: pcwrap.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

client.o: client.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

server.o: server.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

misc.o: misc.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

pty.o: pty.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

pty98.o: pty98.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

net.o: net.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

