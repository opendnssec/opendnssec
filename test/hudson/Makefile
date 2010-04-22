# $Id$

HUDSON_WAR=	hudson.war
JOB_NAME=	OpenDNSSEC

DESTDIR=	$(HOME)/.hudson/jobs/$(JOB_NAME)


all::

fetch:: $(HUDSON_WAR)

install::
	install -d $(DESTDIR)
	install config.xml $(DESTDIR)/config.xml

run:: $(HUDSON_WAR)
	java -jar $(HUDSON_WAR)

$(HUDSON_WAR):
	wget http://hudson-ci.org/latest/hudson.war
