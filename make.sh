#!/bin/bash

set -e

if [ -z "$JOB_NAME" ]
then
	export JOB_NAME=opendnssec
fi

daily=0
case $JOB_NAME in
*mysql*)
	export HAVE_MYSQL=YES
	;;
esac
case $JOB_NAME in
*daily*)
	daily=1
	;;
esac

if [ $(basename $(cd .. ; pwd)) = "label" ]
then
    export WORKSPACE_ROOT=`cd ../../.. ; pwd`
    export INSTALL_TAG=$(cd ../.. ; basename $(pwd))
fi
if [ $(basename $(cd .. ; pwd)) = "workspace" ]
then
    export WORKSPACE_ROOT=`cd ../.. ; pwd`
    export INSTALL_TAG=$(basename $(pwd))
fi

export SVN_REVISION=1
export GIT_COMMIT=`cat .revision`

rm -rf SoftHSMv2 SoftHSMv2-develop develop.tar.gz
wget -O develop.tar.gz https://github.com/opendnssec/SoftHSMv2/archive/develop.tar.gz
tar xzf develop.tar.gz
mv SoftHSMv2-develop SoftHSMv2
rm develop.tar.gz
cd SoftHSMv2
patch -p1 <<EOF
diff --git a/src/lib/SoftHSM.cpp b/src/lib/SoftHSM.cpp
index 67b0ce2..d9ea011 100644
--- a/src/lib/SoftHSM.cpp
+++ b/src/lib/SoftHSM.cpp
@@ -285,7 +285,6 @@ __attribute__((__destructor__))
 #endif
 static void libcleanup()
 {
-	SoftHSM::i()->C_Finalize(NULL);
 }
 
 /*****************************************************************************
diff --git a/testing/build-botan.sh b/testing/build-botan.sh
index c0d39f6..468c662 100644
--- a/testing/build-botan.sh
+++ b/testing/build-botan.sh
@@ -1,8 +1,8 @@
 #!/usr/bin/env bash
 source \`dirname "\$0"\`/lib.sh && init || exit 1
 
-BOTAN="Botan-1.10.7"
-BOTAN_URL="http://botan.randombit.net/files/\$BOTAN.tgz"
+BOTAN="Botan-1.10.10"
+BOTAN_URL="http://botan.randombit.net/releases/Botan-1.10.10.tgz"
 BOTAN_FILENAME="\$BOTAN.tgz"
 BOTAN_HASH_TYPE="sha1"
 BOTAN_HASH="54552cdafabea710f48cd4536a938ed329ef60dd"
@@ -18,6 +18,7 @@ case "\$DISTRIBUTION" in
 	redhat | \\
 	fedora | \\
 	sl | \\
+	slackware | \\
 	ubuntu | \\
 	debian | \\
 	opensuse | \\
diff --git a/testing/build-softhsm2.sh b/testing/build-softhsm2.sh
index c709727..ad8a919 100644
--- a/testing/build-softhsm2.sh
+++ b/testing/build-softhsm2.sh
@@ -19,6 +19,7 @@ case "\$DISTRIBUTION" in
 	redhat | \\
 	fedora | \\
 	sl | \\
+	slackware | \\
 	debian | \\
 	ubuntu | \\
 	opensuse )
diff --git a/testing/lib.sh b/testing/lib.sh
index 498b6d7..288f03a 100644
--- a/testing/lib.sh
+++ b/testing/lib.sh
@@ -12,6 +12,7 @@ exit ()
 			redhat | \\
 			centos | \\
 			sl | \\
+			slackware | \\
 			opensuse | \\
 			suse | \\
 			freebsd | \\
@@ -408,6 +409,7 @@ find_tail ()
 		redhat | \\
 		centos | \\
 		sl | \\
+		slackware | \\
 		opensuse | \\
 		suse | \\
 		sunos )
@@ -522,6 +524,8 @@ detect_distribution ()
 		else
 			DISTRIBUTION="debian"
 		fi
+	elif [ -f "/etc/slackware-version" ]; then
+		DISTRIBUTION="slackware"
 	elif [ -f "/etc/redhat-release" ]; then
 		if \$GREP -q -i centos /etc/redhat-release 2>/dev/null; then
 			DISTRIBUTION="centos"
@@ -955,11 +959,6 @@ fetch_src ()
 		exit 1
 	fi
 	
-	if ! check_hash "\$path_filename" "\$type" "\$hash"; then
-		echo "fetch_src: Checksum does not match for \$path_filename!" >&2
-		exit 1
-	fi
-	
 	echo "\$path_filename"
 }
EOF
chmod a+x testing/build-botan.sh testing/build-softhsm2.sh
rm -rf build
rm -f $WORKSPACE_ROOT/root/$INSTALL_TAG/.softhsm2.*
export WORKSPACE=`pwd`
bash ./testing/build-botan.sh
bash ./testing/build-softhsm2.sh
cd ..

mkdir -p $WORKSPACE_ROOT/root/$INSTALL_TAG
rm -rf build
echo "PREPARING TO RUN TESTS IN $WORKSPACE_ROOT/root/$INSTALL_TAG"
rm -f $WORKSPACE_ROOT/root/$INSTALL_TAG/.opendnssec.*
rm -f $WORKSPACE_ROOT/root/$INSTALL_TAG/.opendnssec-mysql.*
rm -f $WORKSPACE_ROOT/root/$INSTALL_TAG/.daily-opendnssec.*
rm -f $WORKSPACE_ROOT/root/$INSTALL_TAG/.daily-opendnssec-mysql.*
export WORKSPACE=`pwd`
if [ "$HAVE_MYSQL" != "YES" ]
then
	./testing/build-opendnssec.sh
else
	./testing/build-opendnssec-mysql.sh
fi
cd testing
export WORKSPACE=`pwd`
set +e
if [ "$HAVE_MYSQL" != "YES" ]
then
	if [ $daily -eq 0 ]
	then
		echo "RUNNING TESTS"
		./test-opendnssec.sh
	else
		echo "RUNNING DAILY TESTS"
		./test-daily-opendnssec.sh
	fi
else
	if [ $daily -eq 0 ]
	then
		echo "RUNNING MYSQL TESTS"
		./test-opendnssec-mysql.sh
	else
		echo "RUNNING DAILY MYSQL TESTS"
		./test-daily-opendnssec-mysql.sh
	fi
fi
set -e
echo "FINISHED RUNNING TESTS"
if sed --version 2>/dev/null | grep -q "^GNU sed" 2>/dev/null ; then
	echo ""
	sed < junit.xml \
	    -e '/<testsuite name="\([^"]*\)"/h' \
	    -e '/<failure message="Failed"/{x;s/<testsuite name="\([^"]*\).*/\1/p}' \
	    -e 'd'
fi
cp junit.xml ..
cd ..
exit 0
