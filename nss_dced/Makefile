# 
# DCE Naming Services for Solaris/Linux
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 1997-2002 Paul Henson -- see COPYRIGHT file for details
#

all: nss_dced

nss_dced: nss_dced.o
	$(CC) -o nss_dced nss_dced.o -ldce $(LIBS)

nss_dced.o: nss_dced.c nss_dced.h nss_dced_protocol.h
	$(CC) -I/usr/include/dce -D_REENTRANT $(DEBUG) $(SOCKETPATH) -c nss_dced.c

clean:
	@rm -f nss_dced nss_dced.o *~
