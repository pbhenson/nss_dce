# 
# DCE Naming Services for Solaris
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 1997-2000 Paul Henson -- see COPYRIGHT file for details
#

# Choose your C compiler
CC = gcc

# Comment out to disable passwd_override feature
OVERRIDE = -DOVERRIDE

# Comment out to enable sequential password lookups (getpwent)
GETPWENT_DISABLE = -DNO_GETPWENT

# Comment out to enable sequential shadow lookups (getspent)
GETSPENT_DISABLE = -DNO_GETSPENT

# Comment out to enable sequential group lookups (getgrent)
GETGRENT_DISABLE = -DNO_GETGRENT

SEQUENTIAL_DISABLE = $(GETPWENT_DISABLE) $(GETGRENT_DISABLE)

# Uncomment to turn on syslog debugging in the daemon
#
#DEBUG_DAEMON = -DDEBUG

# Uncomment to turn on debugging output from shared library
#
#DEBUG_LIB = -DDEBUG

# Uncomment to use a different socket location for testing a new version
# while still running a previous version. Pretty funky syntax to get this
# define to propagate correctly to the lower level makefiles, eh?
#
#SOCKETPATH = -DNSS_DCED_SOCKETPATH="\\\"\"/var/tmp/.nss_dced\"\\\" "

# Uncomment to use a different location for the .nss_dced.pid file
#PIDFILE = -DNSS_DCED_PIDFILE="\\\"\"/var/tmp/.nss_dced.pid\"\\\" "

all:
	@cd nss_dce.so; make CC=$(CC) DEBUG=$(DEBUG_LIB) SOCKETPATH=$(SOCKETPATH) SEQUENTIAL_DISABLE="$(SEQUENTIAL_DISABLE)" all
	@cd nss_dced; make CC=$(CC) DEBUG=$(DEBUG_DAEMON) SOCKETPATH=$(SOCKETPATH) PIDFILE=$(PIDFILE) OVERRIDE="$(OVERRIDE)" all
	@cd tests; make CC=$(CC) all

install:
	@echo "Installing nss_dced into /usr/sbin"
	@cp nss_dced/nss_dced /usr/sbin/nss_dced
	@chown root /usr/sbin/nss_dced
	@chgrp bin /usr/sbin/nss_dced
	@chmod 700 /usr/sbin/nss_dced
	@echo "Installing nss_dce.so into /usr/lib"
	@rm -f /usr/lib/nss_dce.so.1
	@cp nss_dce.so/nss_dce.so.1 /usr/lib/nss_dce.so.1
	@chown bin /usr/lib/nss_dce.so.1
	@chgrp bin /usr/lib/nss_dce.so.1
	@chmod 755 /usr/lib/nss_dce.so.1
	@echo "Installing S15-80nss_dced into /etc/rc3.d"
	@cp S15-80nss_dced /etc/rc3.d/S15-80nss_dced
	@chown root /etc/rc3.d/S15-80nss_dced
	@chgrp sys /etc/rc3.d/S15-80nss_dced
	@chmod 744 /etc/rc3.d/S15-80nss_dced

clean:
	@cd nss_dce.so; make clean
	@cd nss_dced; make clean
	@cd tests; make clean
	@rm -f *~
