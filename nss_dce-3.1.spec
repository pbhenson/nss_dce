Summary       : DCE Naming Services for Linux
Name          : nss_dce
Version       : 3.1
Release       : 1
License       : GPL
Group         : Network
Packager      : Paul B. Henson <henson@acm.org>
Source        : nss_dce-3.1.tar.gz
URL           : http://www.csupomona.edu/~henson/www/projects/nss_dce/
Prereq        : dcerts
BuildArch     : i386
BuildRoot     : %{_builddir}/%{name}-%{version}

%description

nss_dce is a package that integrates DCE into the naming services switch
architecture under Linux. It allows you to specify "dce" as a
source in the /etc/nsswitch.conf file for passwd, shadow and group
lookups, removing the need to duplicate your security registry in local
passwd and group files.

%prep
rm -rf %{buildroot}
mkdir -p %{buildroot}
tar xzf %{_sourcedir}/nss_dce-3.1.tar.gz -C %{buildroot}

%build
cd %{buildroot}/nss_dce-3.1
make

mkdir -p %{buildroot}/usr/sbin
cp %{buildroot}/nss_dce-3.1/nss_dced/nss_dced %{buildroot}/usr/sbin/nss_dced
chown root.bin %{buildroot}/usr/sbin/nss_dced
chmod 700 %{buildroot}/usr/sbin/nss_dced

mkdir -p %{buildroot}/lib
cp %{buildroot}/nss_dce-3.1/libnss_dce.so/libnss_dce.so.2 %{buildroot}/lib/libnss_dce.so.2
chown root.root %{buildroot}/lib/libnss_dce.so.2
chmod 755 %{buildroot}/lib/libnss_dce.so.2

mkdir -p %{buildroot}/usr/share/man/man8
cp %{buildroot}/nss_dce-3.1/nss_dced/nss_dced.8 %{buildroot}/usr/share/man/man8/nss_dced.8
chown root.sys %{buildroot}/usr/share/man/man8/nss_dced.8
chmod 644 %{buildroot}/usr/share/man/man8/nss_dced.8

mkdir -p %{buildroot}/etc/init.d
cp %{buildroot}/nss_dce-3.1/nss_dced/nss_dced.rc-linux %{buildroot}/etc/init.d/nss_dced
chown root.sys %{buildroot}/etc/init.d/nss_dced
chmod 744 %{buildroot}/etc/init.d/nss_dced

%post
ln -s /lib/libnss_dce.so.2 /usr/lib/libnss_dce.so.2

(echo '/^passwd:/ s/files/files dce/'; \
 echo '/^shadow:/ s/files/files dce/'; \
 echo '/^group:/ s/files/files dce/'; \
 echo 'w'; echo 'q') | ed /etc/nsswitch.conf > /dev/null 2>&1

chkconfig --add nss_dced
chkconfig nss_dced on
service nss_dced start

%preun
service nss_dced stop
chkconfig nss_dced off
chkconfig --del nss_dced

(echo '1,$ s/files dce/files/'; echo 'w'; echo 'q') | ed /etc/nsswitch.conf > /dev/null 2>&1

rm -f /usr/lib/libnss_dce.so.2

%files
/usr/sbin/nss_dced
/lib/libnss_dce.so.2
/usr/share/man/man8/nss_dced.8
/etc/init.d/nss_dced

%changelog
* Fri Feb 22 2002 Paul B. Henson <henson@acm.org>
- Added spec to source distribution with minor tweaks.

* Wed Feb 20 2002 Eric J Barkie/Poughkeepsie/IBM@IBMUS <ebarkie@us.ibm.com>
- Initial release of spec.
