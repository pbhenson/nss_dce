# 
# DCE Naming Services for Solaris
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
#

OBJECTS = nss_dce_passwd.o nss_dce_group.o

CFLAGS = -fpic $(DEBUG) $(SOCKETPATH) -D_REENTRANT -DPIC -D_TS_ERRNO -I../nss_dced

LIBS = -lsocket -lnsl -lc

all:	nss_dce.so.1

.c.o:
	$(CC) $(CFLAGS) -c $<

nss_dce.so.1:	$(OBJECTS)
	$(CC) -o nss_dce.so.1 -G $(OBJECTS) $(LIBS)

clean:
	@rm -f *.o *~ nss_dce.so.1
