#!/bin/sh
#
# $Id$

LOGFILE=hudson.log

nohup java -jar hudson.war > $LOGFILE 2>&1
