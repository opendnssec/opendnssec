/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*+
 * test_routines.c - Unit Testing Routines
 *
 * Description:
 *      These are common routines used in various unit tests.
 *
 *      The unit testing routines made use of the CUint framework,
 *      available from http://cunit.sourcefourge.net.
-*/

#include <assert.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ksm/memory.h"
#include "test_routines.h"

static int m_automatic = 0;     /* Set 1 for automatic mode */
static int m_basic = 0;         /* Set 1 for basic mode */
static int m_console = 0;       /* Set 1 for console mode */
static int m_list = 0;          /* Set 1 for list mode */
static int m_curses= 0;         /* Set 1 for for curses mode */
static char* m_filename = NULL; /* If a filename is given */



/*
 * TestHelp - Print Help
 *
 * Description:
 *      Prints help for the test driver.  This just lists the most common
 *      options.
 *
 * Arguments:
 *      None.
 */

static void TestHelp(void)
{
    static const char* lines[] = {
        "The following switches are available:",
        "",
        "    -a        Automatic - run tests in automatic mode. If the -f switch is also",
        "              given, the output is set to a file whose root name is given here.",
        "              Two files are produced, <root>-Listing.xml, listing the tests,",
        "              and <root>-Results.xml listing the contents of the tests.  If not",
        "              specified, a default name (CUnitAutomated) is used instead.",
        "    -b        Basic - run tests in basic mode. (This is the default.)",
        "    -c        Console - run tests using console mode.",
        "    -f file   Name of the file for automatic or list mode.",
        "    -h        Print this message and exit.",
        "    -l        List tests to file.",
        "    -u        Curses - run tests using curses interface.",
        "",
        "    (The options 'a', 'b', 'c', 'l' and 'u' are mutually exclusive.)",
        NULL
    };
    int i;

    for (i = 0; lines[i]; ++i) {
        printf("%s\n", lines[i]);
    }
}



/*+
 * TestCommandLine - Process Command Line
 *
 * Description:
 *      Parses the command line and sets the flags.  (See TestHelp for a list
 *      of supported flags.)  If the help flag is encountered, prints the help
 *      and exits.
 *
 * Arguments:
 *      int argc, char **argv
 *          Standard command-line arguments.
-*/

static void TestCommandLine(int argc, char** argv)
{
    int c = 0;      /* Option found with getopt() */
    /* extern char* optarg      from getopt(3) */
    /* extern int   optind      from getopt(3) */
    /* extern int   optopt      from getopt(3) */

    while ((c = getopt(argc, argv, "abcf:hlu")) != -1) {
        switch (c) {
        case 'a':
            m_automatic = 1;
            break;

        case 'b':
            m_basic = 1;
            break;

        case 'c':
            m_console = 1;
            break;

        case 'f':
            m_filename = optarg;
            break;

        case 'h':
            TestHelp();
            exit(0);

        case 'l':
            m_list = 1;
            break;

        case 'u':
            m_curses = 1;
            break;

        default:
            fprintf(stderr, "Unrecognised switch: -%c\n", optopt);
            exit(1);
        }
    }
}


/*
 * TestInitialize - Initialize Tests
 *
 * Description:
 *      Processes options and initializes test registry.
 *
 * Arguments:
 *      int argc (input)
 *      char **argv (input)
 *          Arguments passed to main().
 */

void TestInitialize(int argc, char** argv)
{
    int     sum;        /* For checking options given */

    /* Process command-line options */

    TestCommandLine(argc, argv);

    /* Check for conflicting options */

    sum = TestGetAutomatic() + TestGetBasic() + TestGetConsole() +
        TestGetCurses() + TestGetList();
    if (sum == 0) {
        m_basic = 1;    /* Flag as the default option */
    }
    else if (sum > 1) {
        printf("Conflicting options given\n\n");
        TestHelp();
        exit(1);
    }

    return;
}


/*
 * TestGetXxx - Access Methods
 *
 * Description:
 *      Self-explanatory routine to obtain the command-line options.
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      Various.
 */

int TestGetAutomatic(void)
{
    /* Look for the "-a" flag. */

    return m_automatic;
}

int TestGetBasic(void)
{
    return m_basic;
}

int TestGetConsole(void)
{
    return m_console;
}

int TestGetList(void)
{
    return m_list;
}

int TestGetCurses(void)
{
    return m_curses;
}



/*
 * TestGetFilename - Get Output Filename
 *
 * Description:
 *      Returns a pointer to a string holding the filename specified on the
 *      command line with the "-f filename" extension.
 *
 * Arguments:
 *      None.
 *
 * Returns:
 *      const char*
 *          Pointer to name of file (excluding leading "f:") or NULL if
 *          not found.  This string should not be freed by the caller.
 */

const char* TestGetFilename(void)
{
    return m_filename;
}
