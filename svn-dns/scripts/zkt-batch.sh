#!/bin/sh
#
# $Id$
#
# Copyright (c) 2008 Kirei AB. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
######################################################################

ZKT_SIGNER=/usr/local/sbin/dnssec-signer
ZKT_ZONEDIR=/var/dnssec/zkt
DNS_INSTALLZONE=/usr/local/sbin/dns-installzone
RNDC=/usr/sbin/rndc

INBOX=/var/spool/named
OUTBOX=/var/named/master

CLASS=IN
VIEW=aaonly

PROCESSED=0

# process files in INBOX
# - signed zones are moved to its corresponding ZKT directory for
#   further processing by ZKT
# - unsigned zones are moved directly to OUTBOX
#
process_inbox()
{
	if [ `ls -1 ${INBOX} | wc -l` -gt 0 ]; then
		for file in ${INBOX}/*; do
			zone=`basename $file`
	
			PROCESSED=1

			if [ -d ${ZKT_ZONEDIR}/${zone}. ]; then
				prepare_signed $zone $file
			else
				install_unsigned $zone $file
			fi
		done
	fi
}

# prepare signed zones for ZKT processing
#
prepare_signed()
{
	zone=$1
	file=$2

	tmp=${ZKT_ZONEDIR}/${zone}./zone.db.$$
	dst=${ZKT_ZONEDIR}/${zone}./zone.db

	# if this is a new zone, create empty signed zone
	if [ ! -f ${dst}.signed ]; then
		touch ${dst}.signed
		sleep 1
	fi

	# append $INCLUDE for keys
	install -m 600 $file $tmp
	rm -f $file
	echo "\$INCLUDE dnskey.db" >> $tmp

	# move zone into ZKT directory
	install -m 444 $tmp $dst
	rm -f $tmp
}

# copy signed zones from ZKT in OUTBOX
#
install_signed()
{
	for dir in ${ZKT_ZONEDIR}/*; do
		file=${dir}/zone.db.signed
		
		if [ -d $dir -a -f $file ]; then	
			zone=`basename $dir .`

			if [ $file -nt ${OUTBOX}/${zone} ]; then
    				install -m 444 $file ${OUTBOX}/${zone}

				echo "Requesting reload of $zone (signed)"
				$RNDC reload $zone $CLASS $VIEW >/dev/null
			fi
		fi
	done
}

# move unsigned zones to OUTBOX
#
install_unsigned()
{
	zone=$1
	file=$2
	
	if [ $file -nt ${OUTBOX}/${zone} ]; then
		${DNS_INSTALLZONE} --zone=${zone} --destdir=${OUTBOX} $file
		rm -f $file

		echo "Requesting reload of $zone (unsigned)"
		$RNDC reload $zone $CLASS $VIEW >/dev/null
	fi
}

# launch DNSSEC signer (ZKT)
#
launch_signer()
{
    # if any updated zones where installed, use verbose mode
	if [ ${PROCESSED} -gt 0 ]; then
		${ZKT_SIGNER} -v
	else
		${ZKT_SIGNER} $@
	fi
}


process_inbox
launch_signer $@
install_signed 
