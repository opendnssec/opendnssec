AC_DEFUN([ACX_BROKEN_SETRES],[

	AC_CHECK_FUNCS(setresuid, [
		AC_MSG_CHECKING(if setresuid seems to work)
		AC_RUN_IFELSE(
			[AC_LANG_SOURCE([[
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
int main(){errno=0; setresuid(0,0,0); if (errno==ENOSYS) exit(1); else exit(0);}
			]])],
			[AC_MSG_RESULT(yes)],
			[AC_DEFINE(BROKEN_SETRESUID, 1,
				[Define if your setresuid() is broken])
			 AC_MSG_RESULT(not implemented)],
			[AC_MSG_WARN([cross compiling: not checking setresuid])]
		)
	])
	
	AC_CHECK_FUNCS(setresgid, [
		AC_MSG_CHECKING(if setresgid seems to work)
		AC_RUN_IFELSE(
			[AC_LANG_SOURCE([[
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
int main(){errno=0; setresgid(0,0,0); if (errno==ENOSYS) exit(1); else exit(0);}
			]])],
			[AC_MSG_RESULT(yes)],
			[AC_DEFINE(BROKEN_SETRESGID, 1,
				[Define if your setresgid() is broken])
			 AC_MSG_RESULT(not implemented)],
			[AC_MSG_WARN([cross compiling: not checking setresuid])]
		)
	])

])
