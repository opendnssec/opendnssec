#global prever rcX
%global _hardened_build 1

# If you want unstripped binaries, uncomment in '# define __spec_install_post #{nil}'
# with percent signs
%global _enable_debug_package 0
# global debug_package #{nil}
# define __spec_install_post #{nil}

Summary: DNSSEC key and zone management software
Name: opendnssec
Version: 2.1.13
Release: 1%{?dist}
License: BSD
Url: https://www.opendnssec.org/
Packager: Mikko 'dogo' Rantanen / Oivan Group Oy <https://oivan.com/>
Source0: https://www.opendnssec.org/files/source/%{?prever:testing/}%{name}-%{version}%{?prever}.tar.gz
Source1: ods-enforcerd.service
Source2: ods-signerd.service
Source3: ods.sysconfig
Source4: tmpfiles-opendnssec.conf
Source5: opendnssec.cron
# Source6: conf.xml
# Source7: opendnssec-2.1.sqlite_convert.sql
# Source8: opendnssec-2.1.sqlite_rpmversion.sql

# Patch1: patch-signer-hsm-c-20230105.patch
# Patch2: patch-signer-ods-signer-c-20230106.patch
# Patch3: patch-signer-zone-error-message-disambiguation-20230108.patch
# Patch4: patch-keystate-import-cmd-20231021.patch
# Patch5: patch-1.4-2.0-mysql-convert-sql-20231025.patch

Requires: opencryptoki, softhsm >= 2.6.1, systemd-units, libxml2, libxslt, sqlite, libunwind, ldns, policycoreutils-python-utils
BuildRequires: make
BuildRequires: gcc
BuildRequires: ldns-devel >= 1.7.1, ldns >= 1.7.1, sqlite-devel >= 3.0.0, openssl-devel, libunwind, libunwind-devel, mariadb-devel
BuildRequires: libxml2-devel
# It tests for pkill/killall and would use /bin/false if not found
BuildRequires: procps-ng
BuildRequires: perl-interpreter

BuildRequires: systemd-units
Requires(pre): shadow-utils
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
# #if 0#{?prever:1}
# For building development snapshots
# Buildrequires: autoconf, automake, libtool, java
Buildrequires: autoconf, automake, libtool
# #endif

%description
OpenDNSSEC was created as an open-source turn-key solution for DNSSEC.
It secures zone data just before it is published in an authoritative
name server. It requires a PKCS#11 crypto module library, such as SoftHSM

%prep
%setup -q -n %{name}-%{version}%{?prever}
# bump default policy ZSK keysize to 2048
sed -i "s/1024/2048/" conf/kasp.xml.in
# We want MariaDB/MySQL backend, so use correct config template
cp conf/conf-mysql.xml.in conf/conf.xml.in
# patch1 -p2
# patch2 -p2
# patch3 -p2
# patch4 -p2
# patch5 -p2

%build
export LDFLAGS="-Wl,-z,relro,-z,now -pie -specs=/usr/lib/rpm/redhat/redhat-hardened-ld"
export CFLAGS="$RPM_OPT_FLAGS -fPIE -pie -Wextra -Wformat -Wformat-nonliteral -Wformat-security -std=gnu11"
export CXXFLAGS="$RPM_OPT_FLAGS -fPIE -pie -Wformat-nonliteral -Wformat-security"
# #if 0#{?prever:1}
# for development snapshots
sh ./autogen.sh
# #endif
# This is either-or: default is SQLite, need --with-enforcer-database=mysql for MySQL/MariaDB
%configure --with-ldns=%{_libdir} --with-pkcs11-softhsm=/usr/lib64/pkcs11/libsofthsm2.so \
 --with-enforcer-database=mysql --with-mysql=yes --with-libunwind
%make_build

%check
# Requires many dependencies and specific system set-up.
# make check
# Note: in RH 2.1.8 .spec, there's 'tmp' instead of 'signer'.
# Keep both.
#
%install
# export DONT_STRIP=1
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
mkdir -p %{buildroot}%{_localstatedir}/opendnssec/{tmp,signer,signed,signconf,enforcer}
install -d -m 0755 %{buildroot}%{_initrddir} %{buildroot}%{_sysconfdir}/cron.d/
install -m 0644 %{SOURCE5} %{buildroot}/%{_sysconfdir}/cron.d/opendnssec
rm -f %{buildroot}/%{_sysconfdir}/opendnssec/*.sample
install -d -m 0755 %{buildroot}/%{_sysconfdir}/sysconfig
install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/
install -m 0644 %{SOURCE2} %{buildroot}%{_unitdir}/
install -m 0644 %{SOURCE3} %{buildroot}/%{_sysconfdir}/sysconfig/ods
# install -m 0644 %{SOURCE4} %{buildroot}/%{_sysconfdir}/opendnssec/
mkdir -p %{buildroot}%{_tmpfilesdir}/
install -m 0644 %{SOURCE4} %{buildroot}%{_tmpfilesdir}/opendnssec.conf
mkdir -p %{buildroot}%{_localstatedir}/run/opendnssec
mkdir -p %{buildroot}%{_datadir}/opendnssec/

cp -a enforcer/utils %{buildroot}%{_datadir}/opendnssec/migration
cp -a enforcer/src/db/schema.* %{buildroot}%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/
#
# From vanilla 2.1.12 .spec, there's commenting out 'exit 2:'
# in sqlite conversion script but such line does not exist, so
# might be dev/test remnant
sed -i "s:^SCHEMA=.*schema:SCHEMA=%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/schema:" \
 %{buildroot}%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/convert_sqlite
sed -i "s:exit 2:# exit 2:" %{buildroot}%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/convert_sqlite
sed -i "s:find_problematic_zones.sql:%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/find_problematic_zones.sql:g" \
 %{buildroot}%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/convert_sqlite
sed -i "s:^SCHEMA=.*schema:SCHEMA=%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/schema:" \
 %{buildroot}%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/convert_mysql
sed -i "s:find_problematic_zones.sql:%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/find_problematic_zones.sql:g" \
 %{buildroot}%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/convert_mysql
sed -i "s:sqlite_convert.sql:%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/sqlite_convert.sql:g" \
 %{buildroot}%{_datadir}/opendnssec/migration/1.4-2.0_db_convert/convert_sqlite

%files
%{_unitdir}/ods-enforcerd.service
%{_unitdir}/ods-signerd.service
%config(noreplace) %{_tmpfilesdir}/opendnssec.conf
%attr(0770,root,ods) %dir %{_sysconfdir}/opendnssec
%attr(0770,root,ods) %dir %{_localstatedir}/opendnssec
%attr(0770,ods,ods) %dir %{_localstatedir}/opendnssec/tmp
%attr(0770,root,ods) %dir %{_localstatedir}/opendnssec/signer
%attr(0775,root,ods) %dir %{_localstatedir}/opendnssec/signed
%attr(0770,root,ods) %dir %{_localstatedir}/opendnssec/signconf
%attr(0770,ods,ods) %dir %{_localstatedir}/opendnssec/enforcer
%attr(0660,root,ods) %config(noreplace) %{_sysconfdir}/opendnssec/*.xml
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysconfig/ods
%attr(0770,root,ods) %dir %{_localstatedir}/run/opendnssec
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/cron.d/opendnssec
%doc NEWS README.md
%license LICENSE
%{_mandir}/*/*
%{_sbindir}/*
%{_bindir}/*
%attr(0755,root,root) %dir %{_datadir}/opendnssec
%{_datadir}/opendnssec/*

%pre
getent group ods >/dev/null || groupadd -r ods
getent passwd ods >/dev/null || \
useradd -r -g ods -d /etc/opendnssec -s /sbin/nologin \
-c "OpenDNSSEC daemon account" ods
exit 0

%post
#
# Initialize a slot on the softhsm on first install
#

if [ "$1" -eq 1 ]; then
   if [ -z "$(find /var/lib/softhsm/tokens -mindepth 1)" ]; then
     %{_sbindir}/runuser -u ods -- %{_bindir}/softhsm2-util --init-token \
                  --free --label "OpenDNSSEC_KSK" --pin 1234 --so-pin 1234
     %{_sbindir}/runuser -u ods -- %{_bindir}/softhsm2-util --init-token \
                  --free --label "OpenDNSSEC_ZSK" --pin 1234 --so-pin 1234
   fi

   printf "\n***\n  If this is your first-time install with MariaDB/MySQL backend:\n"
   printf "  Please edit your '/etc/opendnssec/conf.xml',\n"
   printf "  configure GRANTs in your MariaDB/MySQL and run\n\n"
   printf "  ods-enforcer-db-setup -f\n\n"
   printf "  to create initial OpenDNSSEC database.\n\n"
   printf "  Example GRANTs:\n"
   printf "  GRANT USAGE ON *.* TO 'kasp_user'@'127.0.0.1' IDENTIFIED BY PASSWORD '....'\n"
   printf "  GRANT ALL PRIVILEGES ON 'kasp26'.* TO 'kasp_user'@'127.0.0.1'\n\n"
   printf "  For 1.4->2.x migration and SQLite -> MariaDB conversion details, please see\n"
   printf "  https://wiki.opendnssec.org/pages/viewpage.action?pageId=10125376\n"
   printf "***\n\n"

fi

# Do this here - it is needed anyway
#
printf "Configuring SELinux, please wait for about 30 seconds..."
semanage permissive -a opendnssec_t >/dev/null 2>&1
semanage permissive -a named_t >/dev/null 2>&1
printf "done.\n\n"

printf "If you have a previous 1.4 installation, please note that\n"
printf "MariaDB/MySQL users have to do manual migration. See directory\n"
printf "/usr/share/opendnssec/migration/1.4-2.0_db_convert/ and the\n"
printf "file README.md there if you're upgrading from 1.4-release.\n\n"

%systemd_post ods-enforcerd.service
%systemd_post ods-signerd.service

%preun
%systemd_preun ods-enforcerd.service
%systemd_preun ods-signerd.service

%postun
%systemd_postun_with_restart ods-enforcerd.service
%systemd_postun_with_restart ods-signerd.service

%changelog
* Fri Dec 08 2023 Mikko 'dogo' Rantanen <dogo@nxme.net> - 2.1.13-1
- Upstream release 2.1.13
- .spec file change to allow for MariaDB/MySQL specific conf.xml
- Provide 1.4->2.x migration and SQLite->MariaDB conversion help text

* Sun Jan 29 2023 Mikko 'dogo' Rantanen <dogo@nxme.net> - 2.1.12-3
- Upstream release 2.1.12
- SUPPORT-278, SUPPORT-289, SUPPORT-291 locally included
- SUPPORT-283 resolved locally
- .spec-file adapted to RHEL9, 'rpm_migration' table removed, post-script enhancements

* Fri Nov 04 2022 Berry A.W. van Halderen <berry@halderen.net> - 2.1.12-1
- Upstream release 2.1.12
- Produce non-stripped binaries with symbols and include libunwind

* Mon Sep 06 2021 Berry A.W. van Halderen <berry@halderen.net> - 2.1.10-1
- Upstream release 2.1.10

* Thu Jul 22 2021 Fedora Release Engineering <releng@fedoraproject.org> - 2.1.9-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

* Tue Jul 06 2021 Francois Cami <fcami@redhat.com> - 2.1.9-1
- Update to 2.1.9 (rhbz#1956561). Solves OPENDNSSEC-955 and OPENDNSSEC-956.
- Known issue: OPENDNSSEC-957: Signer daemon stops with failure exit code even when no error occured.

* Tue Mar 02 2021 Zbigniew J?drzejewski-Szmek <zbyszek@in.waw.pl> - 2.1.8-2
- Rebuilt for updated systemd-rpm-macros
  See https://pagure.io/fesco/issue/2583.

* Sat Feb 20 2021 Fedora Release Monitoring <release-monitoring@fedoraproject.org> - 2.1.8-1
- Update to 2.1.8 (#1931143)

* Tue Jan 26 2021 Fedora Release Engineering <releng@fedoraproject.org> - 2.1.7-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Sat Dec 19 2020 <awilliam@redhat.com> - 2.1.7-3
- Rebuild for libldns soname bump

* Tue Dec  8 2020 Paul Wouters <pwouters@redhat.com> - 2.1.7-2
- Resolves rhbz#1826233 ods-enforcerd.service should wait until socket is ready

* Fri Dec 04 2020 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.7-1
- Upstream release 2.1.7
- Resolves: rhbz#1904484

* Tue Jul 28 2020 Fedora Release Engineering <releng@fedoraproject.org> - 2.1.6-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Tue Jul 14 2020 Tom Stellard <tstellar@redhat.com> - 2.1.6-7
- Use make macros
- https://fedoraproject.org/wiki/Changes/UseMakeBuildInstallMacro

* Thu May 28 2020 Paul Wouters <pwouters@redhat.com> - 2.1.6-6
- Resolves: rhbz#1833718 ods-signerd.service missing .service

* Mon Apr 20 2020 Paul Wouters <pwouters@redhat.com> - 2.1.6-5
- Resolves: rhbz#1825812 AVC avc: denied { dac_override } for comm="ods-enforcerd

* Wed Mar 11 2020 Paul Wouters <pwouters@redhat.com> - 2.1.6-4
- Fix migration check to not attempt to check on first install with no db

* Tue Mar 03 2020 Alexander Bokovoy <abokovoy@redhat.com> - 2.1.6-3
- Create and manage /var/opendnssec/enforcer directory
- Resolves rhbz#1809492

* Wed Feb 19 2020 Paul Wouters <pwouters@redhat.com> - 2.1.6-2
- Update to 2.1.6 (major upgrade, supports migration from 1.4.x)
- gcc10 compile fixups
- Fix trying to use unversioned libsqlite3.so file

* Wed Jan 29 2020 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.14-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Thu Jul 25 2019 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.14-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Fri Feb 01 2019 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.14-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Fri Jul 13 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.14-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Thu Feb 08 2018 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.14-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Tue Dec 12 2017 Paul Wouters <pwouters@redhat.com> - 1.4.14-1
- Update to 1.4.14 as first steop to migrating to 2.x
- Resolves: rhbz#1413254 Move tmpfiles.d config to %%{_tmpfilesdir}, install LICENSE as %%license

* Thu Aug 03 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.9-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.9-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Wed Mar 08 2017 Tomas Hozza <thozza@redhat.com> - 1.4.9-5
- Fix FTBFS (#1424019) in order to rebuild against new ldns

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.9-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Thu Feb 18 2016 Paul Wouters <pwouters@redhat.com> - 1.4.9-3
- Resolves: rbz#1303965 upgrade to opendnssec-1.4.9-1.fc23 breaks old installations
- On initial install, after token init, also run ods-ksmutil setup

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 1.4.9-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Mon Feb 01 2016 Paul Wouters <pwouters@redhat.com> - 1.4.9-1
- Updated to 1.4.9
- Removed merged in patch

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.7-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Tue Jun 09 2015 Paul Wouters <pwouters@redhat.com> - 1.4.7-2
- Resolves rhbz#1219746 ods-signerd.service misplaced After= in section Service
- Resolves rhbz#1220443 OpenDNSSEC fails to initialise a slot in softhsm on first install

* Tue Dec 09 2014 Paul Wouters <pwouters@redhat.com> - 1.4.7-1
- Updated to 1.4.7 (fix zone update can get stuck, crash on retransfer cmd)

* Wed Oct 15 2014 Paul Wouters <pwouters@redhat.com> - 1.4.6-4
- Change /etc/opendnssec to be ods group writable

* Wed Oct 08 2014 Paul Wouters <pwouters@redhat.com> - 1.4.6-3
- Added Petr Spacek's patch that adds the config option <AllowExtraction/> (rhbz#1123354)

* Sun Aug 17 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Mon Jul 28 2014 Paul Wouters <pwouters@redhat.com> - 1.4.6-1
- Updated to 1.4.6
- Removed incorporated patch upstream
- Remove Wants= from ods-signerd.service (rhbz#1098205)

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.5-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Apr 18 2014 Paul Wouters <pwouters@redhat.com> - 1.4.5-2
- Updated to 1.4.5
- Added patch for serial 0 bug in XFR adapter

* Tue Apr 01 2014 Paul Wouters <pwouters@redhat.com> - 1.4.4-3
- Add buildrequires for ods-kasp2html (rhbz#1073313)

* Sat Mar 29 2014 Paul Wouters <pwouters@redhat.com> - 1.4.4-2
- Add requires for ods-kasp2html (rhbz#1073313)

* Thu Mar 27 2014 Paul Wouters <pwouters@redhat.com> - 1.4.4-1
- Updated to 1.4.4 (compatibility with non RFC 5155 errata 3441)
- Change the default ZSK policy from 1024 to 2048 bit RSA keys
- Fix post to be quiet when upgrading opendnssec

* Thu Jan 09 2014 Paul Wouters <pwouters@redhat.com> - 1.4.3-1
- Updated to 1.4.3 (rhel#1048449) - minor bugfixes, minor feature enhancements
- rhel#1025985 OpenDNSSEC signer cannot be started due to a typo in service file

* Wed Sep 11 2013 Paul Wouters <pwouters@redhat.com> - 1.4.2-1
- Updated to 1.4.2, bugfix release

* Sat Aug 03 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Fri Jun 28 2013 Paul Wouters <pwouters@redhat.com> - 1.4.1-1
- Updated to 1.4.1. NSEC3 handling and serial number handling fixes
- Add BuildRequire for systemd-units

* Sat May 11 2013 Paul Wouters <pwouters@redhat.com> - 1.4.0-1
- Updated to 1.4.0

* Fri Apr 12 2013 Paul Wouters <pwouters@redhat.com> - 1.4.20-0.8.rc3
- Updated to 1.4.0rc3
- Enabled hardened compile, full relzo/pie

* Fri Jan 25 2013 Patrick Uiterwijk <puiterwijk@gmail.com> - 1.4.0-0.7.rc2
- Updated to 1.4.0rc2, which includes svn r6952

* Fri Jan 18 2013 Patrick Uiterwijk <puiterwijk@gmail.com> - 1.4.0-0.6.rc1
- Updated to 1.4.0rc1
- Applied opendnssec-ksk-premature-retirement.patch (svn r6952)

* Tue Dec 18 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.5.b2
- Updated to 1.4.0b2
- All patches have been merged upstream
- cron job should be marked as config file

* Tue Oct 30 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.4.b1
- Added BuildRequires: procps-ng for bug OPENDNSSEC-345
- Change RRSIG inception offset to -2h to avoid possible
  daylight saving issues on resolvers
- Patch to prevent removal of occluded data

* Wed Sep 26 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.3.b1
- Just an EVR fix to the proper standard
- Cleanup of spec file
- Introduce new systemd-rpm macros (rhbz#850242)

* Wed Sep 12 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.b1.1
- Updated to 1.4.0b1
- Patch for NSEC3PARAM TTL
- Cron job to assist narrowing ods-enforcerd timing differences

* Wed Aug 29 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.a3.1
- Updated to 1.4.0a3
- Patch to more aggressively try to resign
- Patch to fix locking issue eating up cpu

* Fri Jul 20 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.0-0.a2.2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Tue Jun 12 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.a2.1
- Updated to 1.4.0a2
- ksm-utils patch for ods-ksmutil to die sooner when it can't lock
  the HSM.

* Wed May 16 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.a1.3
- Patch for crasher with deleted RRsets and NSEC3/OPTOUT chains

* Mon Mar 26 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.a1.2
- Added opendnssec LICENSE file from trunk (Thanks Jakob!)

* Mon Mar 26 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.a1.1
- Fix macros in comment
- Added missing -m to install target

* Sun Mar 25 2012 Paul Wouters <pwouters@redhat.com> - 1.4.0-0.a1
- The 1.4.x branch no longer needs ruby, as the auditor has been removed
- Added missing openssl-devel BuildRequire
- Comment out <SkipPublicKey/> so keys generated by ods can be used by bind

* Fri Feb 24 2012 Paul Wouters <pwouters@redhat.com> - 1.3.6-3
- Requires rubygem-soap4r when using ruby-1.9
- Don't ghost /var/run/opendnssec
- Converted initd to systemd

* Thu Nov 24 2011 root - 1.3.2-6
- Added rubygem-dnsruby requires as rpm does not pick it up automatically

* Tue Nov 22 2011 root - 1.3.2-5
- Added /var/opendnssec/signconf/ /as this temp dir is needed

* Mon Nov 21 2011 Paul Wouters <paul@xelerance.com> - 1.3.2-4
- Added /var/opendnssec/signed/ as this is the default output dir

* Sun Nov 20 2011 Paul Wouters <paul@xelerance.com> - 1.3.2-3
- Add ods user for opendnssec tasks
- Added initscripts and services for ods-signerd and ods-enforcerd
- Initialise OpenDNSSEC softhsm token on first install

* Wed Oct 05 2011 Paul Wouters <paul@xelerance.com> - 1.3.2-1
- Updated to 1.3.2
- Added dependancies on opencryptoki and softhsm
- Don't install duplicate unreadable .sample files
- Fix upstream conf.xml to point to actually used library paths

* Thu Mar  3 2011 Paul Wouters <paul@xelerance.com> - 1.2.0-1
- Initial package for Fedora
