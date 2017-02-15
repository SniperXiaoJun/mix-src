LIBDIR = ./lib
SRCDIR = .
VPATH  = $(SRCDIR)

PROJ  = iccp
OPT   =
DEFS  =
#LIST  = >> cc.lst 2>&1

CC = gcc

LIBRARY = $(LIBDIR)/lib$(PROJ).so

OBJECTS = $(LIBDIR)/libcrypto.a   

all: $(LIBRARY)

$(LIBRARY): $(OBJECTS)
	rm -f $(LIBRARY)
	$(CC) -shared -fPIC -Wl,--whole-archive $(OBJECTS) -Wl,--no-whole-archive  -Wl,-soname -Wl,$@ -o $@ -lc $(LIST)

$(LIBDIR)/libcrypto.a: 

.PHONY:clean
clean:
	rm -f $(LIBRARY)
