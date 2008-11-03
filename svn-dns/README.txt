$Id$


This is my collection of scripts for integrating DNS zone file management with
Subversion and ZKT. A brief introduction to how this is supposed to work can
be found below and in the file 'dataflow.pdf'.

Enjoy,

	Jakob Schlyter, jakob@kirei.se



0. All zone files are stored in a subversion repository.

1. a subversion pre-commit hook (called svn-checkzone) checks that
   the unsigned zone is syntactically valid by calling named-checkzone.

2. a subversion post-commit hook (called svn-installzone) installs
   the unsigned zone file into a spool directory (e.g. /var/spool/named).

3. a cron job (zkt-batch) moves any pending zone files from the spool
   directory into ZKT (for signed zones) or directly into the BIND master
   directory (for unsigned zones). unsigned zones are updated with a new
   SOA serial when copied, while the SOA serial for signed zones are handled
   by ZKT.

   zkt-batch then executes ZKT to do the signing and installs any updated
   zone file into the BIND master directory.

   finally, named is notified of any changes zones using rndc.

