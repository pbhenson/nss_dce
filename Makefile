# 
# DCE Naming Services for Solaris/Linux
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 1997-2002 Paul Henson -- see COPYRIGHT file for details
#

# Choose your C compiler
CC = gcc

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

all:
	@case "`uname`" in \
		'SunOS') echo "Compiling for Solaris"; make solaris \
			;; \
		'Linux') echo "Compiling for Linux"; make linux \
			;; \
		*) echo "Unsupported platform" \
			;; \
	esac

install: all
	@case "`uname`" in \
		'SunOS') echo "Installing for Solaris"; make install-solaris \
			;; \
		'Linux') echo "Installing for Linux"; make install-linux \
			;; \
		*) echo "Unsupported platform" \
			;; \
	esac

solaris:
	@cd nss_dce.so; make CC=$(CC) DEBUG=$(DEBUG_LIB) SOCKETPATH=$(SOCKETPATH) all
	@cd nss_dced; make CC=$(CC) LIBS="-lsocket -lnsl" DEBUG=$(DEBUG_DAEMON) SOCKETPATH=$(SOCKETPATH) all
	@cd tests; make CC=$(CC) all

linux:
	@cd libnss_dce.so; make CC=$(CC) DEBUG=$(DEBUG_LIB) SOCKETPATH=$(SOCKETPATH) all
	@cd nss_dced; make CC=$(CC) DEBUG=$(DEBUG_DAEMON) SOCKETPATH=$(SOCKETPATH) all
	@cd tests; make CC=$(CC) all

install-solaris:
	@echo "Installing nss_dced into /usr/sbin"
	@rm -f /usr/sbin/nss_dced
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
	@echo "Installing nss_dced.8 into /usr/man/man8"
	@cp nss_dced/nss_dced.8 /usr/man/man8
	@chown root /usr/man/man8/nss_dced.8
	@chgrp sys /usr/man/man8/nss_dced.8
	@chmod 644 /usr/man/man8/nss_dced.8
	@echo "Installing nss_dced.rc-solaris as /etc/init.d/nss_dced"
	@cp nss_dced/nss_dced.rc-solaris /etc/init.d/nss_dced
	@chown root /etc/init.d/nss_dced
	@chgrp sys /etc/init.d/nss_dced
	@chmod 744 /etc/init.d/nss_dced
	@echo "Creating S15-80nss_dced symlink in /etc/rc3.d"
	@ln -s /etc/init.d/nss_dced /etc/rc3.d/S15-80nss_dced

install-linux:
	@echo "Installing nss_dced into /usr/sbin"
	@rm -f /usr/sbin/nss_dced
	@cp nss_dced/nss_dced /usr/sbin/nss_dced
	@chown root /usr/sbin/nss_dced
	@chgrp bin /usr/sbin/nss_dced
	@chmod 700 /usr/sbin/nss_dced
	@echo "Installing libnss_dce.so.2 into /lib"
	@rm -f /lib/libnss_dce.so.2
	@cp libnss_dce.so/libnss_dce.so.2 /lib/libnss_dce.so.2
	@chown root /lib/libnss_dce.so.2
	@chgrp root /lib/libnss_dce.so.2
	@chmod 755 /lib/libnss_dce.so.2
	@echo "Creating libnss_dce.so.2 symlink in /usr/lib"
	@rm -f /usr/lib/libnss_dce.so.2
	@ln -s /lib/libnss_dce.so.2 /usr/lib/libnss_dce.so.2
	@echo "Installing nss_dced.8 into /usr/share/man/man8"
	@cp nss_dced/nss_dced.8 /usr/share/man/man8
	@chown root /usr/share/man/man8/nss_dced.8
	@chgrp sys /usr/share/man/man8/nss_dced.8
	@chmod 644 /usr/share/man/man8/nss_dced.8
	@echo "Installing nss_dced.rc-linux as /etc/init.d/nss_dced"
	@cp nss_dced/nss_dced.rc-linux /etc/init.d/nss_dced
	@chown root /etc/init.d/nss_dced
	@chgrp sys /etc/init.d/nss_dced
	@chmod 744 /etc/init.d/nss_dced
	@chkconfig --add nss_dced
	@chkconfig nss_dced on

clean:
	@cd libnss_dce.so; make clean
	@cd nss_dce.so; make clean
	@cd nss_dced; make clean
	@cd tests; make clean
	@rm -f *~
