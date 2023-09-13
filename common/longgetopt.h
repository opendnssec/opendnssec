#include <getopt.h>

#ifndef HAVE_GETOPT_LONG
struct option
{
  const char* name;
  int has_arg;
  int *flag;
  int val;
};
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
