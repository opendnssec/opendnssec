#include <getopt.h>

#ifndef HAVE_GETOPT_LONG
struct option
{
  const char* name;
  int has_arg;
  int *flag;
  int val;
};
# ifndef  no_argument
#  define no_argument 0
# endif
# ifndef  required_argument
#  define required_argument 1
# endif
# ifndef  optional_argument
#  define optional_argument 2
# endif
#endif

struct longgetopt {
    int optind;
    int optopt;
    char* optarg;

    const char* _optstring;
    const struct option* _optarray;
    int _optend;
    int _argc;
    char** _argv;
    int _optpos;
    int _permute;
};

extern int longgetopt(int argc, char** argv, const char* optstring, const struct option* longopts, int* longindex, struct longgetopt* context);

extern int strtoargs(const char* arg, int *argc, char*** argv);
