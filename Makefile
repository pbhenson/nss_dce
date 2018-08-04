# 
# DCE Naming Services for Solaris
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
#

# Choose your C compiler
CC = gcc

# Uncomment to enable the -d option for daemon debugging
#DEBUG_DAEMON = -DDEBUG

# Uncomment to turn on debugging output from shared library
#DEBUG_LIB = -DDEBUG

all:
	@cd nss_dce.so; make CC=$(CC) DEBUG=$(DEBUG_DAEMON) all
	@cd nss_dced; make CC=$(CC) DEBUG=$(DEBUG_LIB) all
	@cd tests; make CC=$(CC) all

install:
	@echo "Installing nss_dced into /usr/sbin"
	@cp nss_dced/nss_dced /usr/sbin/nss_dced
	@chown root /usr/sbin/nss_dced
	@chgrp bin /usr/sbin/nss_dced
	@chmod 700 /usr/sbin/nss_dced
	@echo "Installing nss_dce.so into /usr/lib"
	@cp nss_dce.so/nss_dce.so.1 /usr/lib/nss_dce.so.1
	@chown bin /usr/lib/nss_dce.so.1
	@chgrp bin /usr/lib/nss_dce.so.1
	@chmod 755 /usr/lib/nss_dce.so.1
	@echo "Now you need to configure nss_dced to start at boot."
	@echo "Please see README for details"

clean:
	@cd nss_dce.so; make clean
	@cd nss_dced; make clean
	@cd tests; make clean
	@rm -f *~
