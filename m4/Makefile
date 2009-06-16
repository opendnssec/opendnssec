# $Id$

DESTDIRS = enforcer libhsm libksm signer softHSM

all:

install: copy autogen

copy:
	@for dir in $(DESTDIRS); do \
		target=../$$dir ;\
		echo "copying acinclude.m4 to $$target" ;\
		cp acinclude.m4 $$target ;\
	done
	@echo "don't forget to commit installed copies of acinclude.m4"

autogen:
	@for dir in $(DESTDIRS); do \
		target=../$$dir ;\
		echo "running autogen.sh in $$target" ;\
		(cd $$target; sh autogen.sh) ;\
		echo "" ;\
	done
