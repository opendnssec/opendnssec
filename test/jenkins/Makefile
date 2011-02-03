# $Id$

JENKINS_URL=	http://mirrors.jenkins-ci.org/war/latest/jenkins.war
JENKINS_WAR=	jenkins.war
JOB_NAME=	OpenDNSSEC

DESTDIR=	$(HOME)/.jenkins/jobs/$(JOB_NAME)

JAVA=		java
INSTALL=	install


all::

fetch:: $(JENKINS_WAR)

install::
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) config.xml $(DESTDIR)/config.xml

run:: $(JENKINS_WAR)
	$(JAVA) -jar $(JENKINS_WAR)

$(JENKINS_WAR):
	wget $(JENKINS_URL)
