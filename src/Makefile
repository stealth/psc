# PSC Makefile

# MUST use different keys for KEY1 and KEY2
KEY1=\"secret1\"
KEY2=\"secret2\"

BANNER=\"psc-2022-STARTTLS-\"

CXX=c++
DEFS=-DPSC_READ_KEY=$(KEY1) -DPSC_WRITE_KEY=$(KEY2) -DSTART_BANNER=$(BANNER)
CXXFLAGS=-c -Wall -O2 -std=c++11 -pedantic

.PHONY: all clean

ifeq ($(shell uname), Linux)
DEFS+=-DHAVE_UNIX98
endif

all: warn pscl pscr pscsh

warn:
	@echo "Hint: Do not 'make' inside pscl session, as it echos PSC STARTTLS sequence." || true

clean:
	rm -f *.o

pscl: misc.o client.o pcwrap.o pty.o pty98.o net.o sha512.o aes.o
	$(CXX) $^ -o $@

pscr: misc.o server.o pty.o pty98.o pcwrap.o net.o sha512.o aes.o
	$(CXX) $^ -o $@

pscsh: pscsh.o
	$(CXX) $^ -o $@

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

aes.o: external/aes.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

sha512.o: external/sha512.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

pscsh.o: pscsh.cc
	$(CXX) $(DEFS) $(CXXFLAGS) $^ -o $@

