# $Id$

DESTDIRS = enforcer libhsm libksm signer softHSM auditor xml

all:

autogen:
	@for dir in $(DESTDIRS); do \
		target=../$$dir ;\
		echo "running autogen.sh in $$target" ;\
		(cd $$target; sh autogen.sh) ;\
		echo "" ;\
	done
