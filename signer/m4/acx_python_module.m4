# $Id$

AC_DEFUN([ACX_PYTHON_MODULE],[

	for module in $1;
	do
		if ! $PYTHON -c 'import '$module'' > /dev/null 2>&1; then
			echo 'Checking for python module '$module'... not found'
			AC_MSG_ERROR([Python module '$module' not found])
		else
			echo 'Checking for python module '$module'... ok'
		fi
	done

])
