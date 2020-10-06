# Makefile stun
#

prefix=/usr/local
exec_prefix=${prefix}/bin 

CFLAGS=-g -Wall  -I/usr/local/include
LDFLAGS=-g -Wall  -L/usr/local/lib

LIBS= -lnice

INSTALL=/usr/bin/install -c
INSTALL_DATA=${INSTALL} -m 644

CFILES = ice.c main.c
OFILES = $(CFILES:.c=.o)

all: stuncheck

stuncheck: $(OFILES)
	$(CC) $(LDFLAGS) -o $@ $(OFILES) $(LIBS)

clean:
	rm -f *.o *~ stuncheck

.c.o:
	$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<
