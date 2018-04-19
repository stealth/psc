#

DEFS=
CC=cc
CXX=c++
CXXFLAGS=-std=c++11 -Wall -O2 -DSTARTTLS=\"psc-2018-STARTTLS\" -pedantic $(DEFS)
CXXFLAGS+=-DHAVE_UNIX98
LIBS=-lssl -lcrypto

all: psc-local psc-remote

clean:
	rm -f *.o

psc-local: misc.o local.o pcwrap.o pty.o pty98.o base64.o bio.o
	$(CXX) misc.o pcwrap.o local.o pty.o pty98.o base64.o bio.o -o psc-local $(LIBS)

psc-remote: misc.o remote.o pty.o pty98.o pcwrap.o base64.o bio.o
	$(CXX) misc.o remote.o pty.o pty98.o pcwrap.o base64.o bio.o -o psc-remote $(LIBS)

pcwrap.o: pcwrap.cc
	$(CXX) -c $(CXXFLAGS) $<

local.o: local.cc
	$(CXX) -c $(CXXFLAGS) $<

remote.o: remote.cc
	$(CXX) -c $(CXXFLAGS) $<

misc.o: misc.cc
	$(CXX) -c $(CXXFLAGS) $<

pty.o: pty.cc
	$(CXX) -c $(CXXFLAGS) $<

pty98.o: pty98.cc
	$(CXX) -c $(CXXFLAGS) $<

base64.o: base64.cc
	$(CXX) -c $(CXXFLAGS) $<

bio.o: bio.cc
	$(CXX) -c $(CXXFLAGS) $<


