AC_DEFUN([ACX_ABS_SRCDIR], [
case "$srcdir" in
  .) # No --srcdir option.  We are building in place.
    ac_sub_srcdir=`pwd` ;;
  /*) # Absolute path.
    ac_sub_srcdir=$srcdir/$ac_config_dir ;;
  *) # Relative path.
    ac_sub_srcdir=`pwd`/$ac_dots$srcdir/$ac_config_dir ;;
esac
])
