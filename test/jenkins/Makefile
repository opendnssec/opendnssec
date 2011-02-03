# $Id$

HUDSON_URL=	http://mirrors.jenkins-ci.org/war/latest/jenkins.war
HUDSON_WAR=	jenkins.war
JOB_NAME=	OpenDNSSEC

DESTDIR=	$(HOME)/.jenkins/jobs/$(JOB_NAME)

JAVA=		java
INSTALL=	install


all::

fetch:: $(HUDSON_WAR)

install::
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) config.xml $(DESTDIR)/config.xml

run:: $(HUDSON_WAR)
	$(JAVA) -jar $(HUDSON_WAR)

$(HUDSON_WAR):
	wget $(HUDSON_URL)
