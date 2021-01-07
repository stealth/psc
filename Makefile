#

KEY1=\"secret1\"
KEY2=\"secret2\"

CXX=c++
DEFS=
CXXFLAGS=-c -Wall -O2 -DPSC_READ_KEY=$(KEY1) -DPSC_WRITE_KEY=$(KEY2) -std=c++11 -pedantic $(DEFS)
CXXFLAGS+=-DHAVE_UNIX98

all: pscl pscr

clean:
	rm -f *.o

pscl: misc.o client.o pcwrap.o pty.o pty98.o net.o
	$(CXX) misc.o pcwrap.o client.o pty.o pty98.o net.o -o pscl -lcrypto

pscr: misc.o server.o pty.o pty98.o pcwrap.o net.o
	$(CXX) misc.o server.o pty.o pty98.o pcwrap.o net.o -o pscr -lcrypto

pcwrap.o: pcwrap.cc pcwrap.h
	$(CXX) $(CXXFLAGS) pcwrap.cc

client.o: client.cc
	$(CXX) $(CXXFLAGS) client.cc

server.o: server.cc
	$(CXX) $(CXXFLAGS) server.cc

misc.o: misc.cc misc.h
	$(CXX) $(CXXFLAGS) misc.cc

pty.o: pty.cc pty.h
	$(CXX) $(CXXFLAGS) pty.cc

pty98.o: pty98.cc pty.h
	$(CXX) $(CXXFLAGS) pty98.cc

net.o: net.cc net.h
	$(CXX) $(CXXFLAGS) net.cc

