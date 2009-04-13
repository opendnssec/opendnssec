#!/bin/sh
#
# database.sh - Set Up/Tear Down Test Database
#
# Description:
#		This script is run from within the test program to set up a test
#		database before the the database test module is run and to tear it
#		down afterwards.
#
#		The following environment variables should be set before running the
#		test program to control access to the database:
#
#			DB_USERNAME		username to access the database
#			DB_PASSWORD		asssociated password
#			DB_HOST			host on which the database resides
#			DB_NAME			name of the database
#
# Invocation:
#		The script can also be run manually to set up and tear down the
#		database:
#
#			sh database.sh setup
#			sh database.sh teardown
#-

USERNAME=
if [ -n $DB_USERNAME ]; then
	USERNAME=--user=$DB_USERNAME
fi

PASSWORD=
if [ -n $DB_PASSWORD ]; then
	PASSWORD=--password=$DB_PASSWORD
fi

HOST=
if [ -n $DB_HOST ]; then
	HOST=--host=$DB_HOST
fi

NAME=
if [ -n $DB_NAME ]; then
	NAME=--database=$DB_NAME
fi

case $1 in
	setup)
		mysql $USERNAME $PASSWORD $HOST $NAME < '../database/database_create.mysql';
		mysql $USERNAME $PASSWORD $HOST $NAME << EOF
DROP TABLE IF EXISTS TEST_BASIC;
CREATE TABLE TEST_BASIC (
   ID           INT NOT NULL AUTO_INCREMENT,
   IVALUE       INT,
   SVALUE       VARCHAR(64),
   TVALUE       TIMESTAMP,
   CONSTRAINT PRIMARY KEY (ID)
) ENGINE=InnoDB;
INSERT INTO TEST_BASIC VALUES(0, 100, NULL,  '20080101');
INSERT INTO TEST_BASIC VALUES(0, 200, 'ABC', '20080102');
INSERT INTO TEST_BASIC VALUES(0, 300, 'DEF', '20080103');

-- A couple of Zones:
INSERT INTO zones VALUES (1,'opendnssec.org',1,1,2);
INSERT INTO zones VALUES (2,'opendnssec.se',1,1,2);

-- Create a dead key which we can purge out of the database
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 6, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
-- With 2 zones using it:
INSERT INTO dnsseckeys VALUES (NULL, 1, 1, 257, 1, 1, NULL, NULL);
INSERT INTO dnsseckeys VALUES (NULL, 1, 2, 257, 1, 1, NULL, NULL);

-- parameters for KsmParameter tests
INSERT INTO categories VALUES (NULL,		"Test");
INSERT INTO parameters VALUES (NULL, "Blah", "Used in unit test", (select id from categories where name = "Test")	);

INSERT INTO parameters VALUES (NULL, "Blah2", "Used in unit test", (select id from categories where name = "Test")	);
INSERT INTO parameters_policies VALUES (NULL, (select id from parameters where name = "Blah2"), 2, 1	);

-- Create a key which we can request from the database
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO dnsseckeys VALUES (NULL, 2, 1, 257, 1, 1, NULL, NULL);

-- Create a set of keys which we can delete from the database
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
INSERT INTO keypairs VALUES(NULL, "0x1", 5, 1024, 1, 1, "2001-01-01 01:00:00", NULL, NULL, NULL, NULL, "2002-01-01 01:00:00", 2, NULL, "");
EOF
		;;

	teardown)
		mysql $USERNAME $PASSWORD $HOST $NAME << EOF
DROP TABLE IF EXISTS TEST_BASIC;
EOF
		;;

	*)
		echo "Usage: $0 [setup | teardown]"
		;;
esac
