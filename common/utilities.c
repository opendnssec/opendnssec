#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "utilities.h"

functioncast_t
functioncast(void*generic) {
    functioncast_t* function = (functioncast_t*)&generic;
    return *function;
}

unsigned long long int
rnd(void)
{
  unsigned long long int foo;
  int cf_error_status;

  asm("rdrand %%rax; \
        mov $1,%%edx; \
        cmovae %%rax,%%rdx; \
        mov %%edx,%1; \
        mov %%rax, %0;":"=r"(foo),"=r"(cf_error_status)::"%rax","%rdx");
  return  (!cf_error_status ? 0 : foo);
}
