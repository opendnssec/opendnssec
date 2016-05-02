/* COPYRIGHT 2016 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include "debug.h"

int
main(int argc, char* argv[])
{
    installcrashhandler(argv[0]);
    return 0;
}
