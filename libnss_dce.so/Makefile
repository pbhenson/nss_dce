# 
# DCE Naming Services for Linux
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
#

OBJECTS = nss_dce_passwd.o nss_dce_shadow.o nss_dce_group.o nss_dce_common.o

CFLAGS = -fpic $(DEBUG) $(SOCKETPATH) $(SEQUENTIAL_DISABLE) -D_REENTRANT -DPIC -D_TS_ERRNO -I../nss_dced

LIBS =

all:	libnss_dce.so.2

.c.o:
	$(CC) $(CFLAGS) -c $<

libnss_dce.so.2:	$(OBJECTS)
	$(CC) -shared -o libnss_dce.so.2 -Wl,-soname,libnss_dce.so.2 $(OBJECTS) $(LIBS)

clean:
	@rm -f *.o *~ libnss_dce.so.2
