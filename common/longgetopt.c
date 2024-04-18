#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <err.h>
#include <getopt.h>
#include "longgetopt.h"

static void
permute(struct longgetopt* context)
{
    char* swap;
    size_t count = context->_optend - context->optind;
    if(count > 0) {
        swap = context->_argv[context->optind];
        memmove(&(context->_argv[context->optind]), &(context->_argv[context->optind + 1]), sizeof(char*) * (context->_argc - context->optind));
        context->_optend -= 1;
        context->_argv[context->_argc-1] = swap;
    } else if (count == 0)
        context->_optend -= 1;
}

static int
matchoption(char* s, const char* optstring, const struct option* longopts, int* longindex, struct longgetopt* context)
{
    size_t length;
    int ch;
    char* argument = NULL;
    if(context->_optpos == 0) {
        if((argument = strchr(&s[2],'=')) || (argument = strchr(&s[2],' ')) || (argument = strchr(&s[2],':'))) {
            length = argument - &s[2];
            argument += 1;
        } else {
            length = strlen(&s[2]);
        }
        for(int i=0; longopts && longopts[i].name; i++) {
            if(!strncmp(&s[2], longopts[i].name, length) && length == strlen(longopts[i].name)) {
                context->optopt = longopts[i].val;
                context->optarg = argument;
                if(longindex)
                    *longindex = i;
                if(longopts[i].has_arg == no_argument && argument != NULL) {
                    return '?';
                } else if(longopts[i].has_arg == required_argument && argument == NULL) {
                    if(context->optind < context->_optend) {
                        /* matched option required argument, use next item */
                        argument = context->_argv[context->optind];
                        context->optarg = argument;
                        context->optind += 1;
                    } else {
                        return '?';
                    }
                }
                if(longopts[i].flag) {
                    *(longopts[i].flag) = longopts[i].val;
                    return 0;
                } else {
                    return longopts[i].val;
                }
            }
        }
        if(length == 1) {
            context->_optpos = 2;
        } else {
            return '?';
        }
    }
    ch = s[context->_optpos];
    if(isgraph(ch) && strchr(":+-;",ch) == NULL) {
        for(int i=0; optstring[i]; i++) {
            if(ch == optstring[i]) {
                if(optstring[i+1]==':') {
                    /* matched option has optional or required argument */
                    if(s[context->_optpos+1] == '=' || s[context->_optpos+1] == ' ' || s[context->_optpos+1] == ':') {
                        /* option has (optional) argument, and one supplied with separator */
                        context->optopt = ch;
                        context->optarg = &s[context->_optpos+2];
                        context->_optpos = strlen(s)-1;
                        return ch;
                    } else if(s[context->_optpos+1] != '\0') {
                        /* option has (optional) argument, and one supplied without separator */
                        context->optopt = ch;
                        context->optarg = &s[context->_optpos+1];
                        context->_optpos = strlen(s)-1;
                        return ch;
                    } else if(optstring[i+2]!=':') {
                        if(s[context->_optpos+1] == '\0' && context->optind < context->_optend) {
                            /* matched option required argument, use next item */
                            argument = context->_argv[context->optind];
                            context->optind += 1;
                            context->optopt = ch;
                            context->optarg = argument;
                            context->_optpos = 0;
                            return ch;
                        } else {
                            /* match option required argument, but none given */
                            context->optopt = ch;
                            context->optarg = NULL;
                            return '?';
                        }
                    } else {
                        /* matched option has optional argument, but none given */
                        context->optopt = ch;
                        context->optarg = NULL;
                        return ch;
                    }
                } else {
                    /* matched option that should have no argument */
                    if(s[context->_optpos+1] == '=' || s[context->_optpos+1] == ' ') {
                        /* matched non-argument option has argument passed*/
                        context->optopt = ch;
                        context->optarg = &s[context->_optpos+2];
                        return '?';
                    } else {
                        /* matched non-argument option with no argument supplied */
                        context->optopt = ch;
                        context->optarg = NULL;
                        return ch;
                    }
                }
            }
        }
        /* no short option matched */
        context->optopt = '?';
        context->optarg = argument;
        return '?';
    } else {
        context->optopt = '?';
        context->optarg = argument;
        return '?';
    }
}

int
longgetopt(int argc, char** argv, const char* optstring, const struct option* longopts, int* longindex, struct longgetopt* context)
{
    if(optstring) {
        context->_permute = 1;
        if(getenv("POSIXLY_CORRECT"))
            context->_permute = 0;
        if(optstring[0] == '+') {
            context->_permute = 0;
            context->_optstring = (optstring[0] == '\0' ? optstring : &optstring[1]);
        } else
            context->_optstring = optstring;
        context->_optarray = longopts;
        context->_optend = argc;
        context->_argc = argc;
        context->_argv = argv;
        context->optind = 0;
        context->_optpos = 0;
        context->optarg = NULL;
        context->optopt = '?';
    } else {
        argv = context->_argv;
    }

    if(context->_optpos > 0) {
        if(argv[context->optind-1][context->_optpos + 1]) {
            context->_optpos += 1;
            return matchoption(argv[context->optind-1], context->_optstring, context->_optarray, longindex, context);
        } else {
            context->_optpos = 0;
            //context->optind += 1;
        }
    }

    while(context->optind < context->_optend && argv[context->optind][0] != '-') {
        if(context->_permute) {
            permute(context);
        } else {
            return -1;
        }
    }
    if(context->optind >= context->_optend) {
        context->_optend -= 1;
        return -1;
    }
    if(argv[context->optind][1] == '-') {
        if(argv[context->optind][2] == '\0') {
            context->optind += 1;
            while(context->_optend - context->optind > 1) {
                permute(context);
            }
            return -1;
        } else {
            context->optind += 1;
            return matchoption(argv[context->optind-1], context->_optstring, context->_optarray, longindex, context);
        }
    } else {
        context->_optpos = 1;
        context->optind += 1;
        return matchoption(argv[context->optind-1], context->_optstring, context->_optarray, longindex, context);
    }   
}

int
strtoargs(const char* arg, int* argcptr, char*** argvptr)
{
    int groupch;
    int lastch;
    char** argv = NULL;
    int argc;
    int argi;
    char* args;

    argv = NULL;
    for(int pass=0; pass<2; ++pass) {
        argc = 0;
        argi = 0;
        lastch = '\0';
        groupch = '\0';
        if(argv)
            argv[argc] = NULL;
        for(int i=0; arg[i]; i++) {
            if(argv != NULL && argv[argc] == NULL) {
                if(argc>0) {
                    argv[argc] = &argv[argc-1][argi];
                } else
                    argv[argc] = args;
                argi = 0;
            }
            switch(arg[i]) {
                case '\"':
                case '\'':
                    if(arg[i] == groupch) {
                        groupch = '\0';
                    } else if(!groupch) {
                        groupch = arg[i];
                    } else {
                        if(argv)
                            argv[argc][argi] = arg[i];
                        ++argi;                        
                    }
                    break;
                case '\\':
                    if(arg[i+1] && (arg[i+1]=='\'' || arg[i+1]=='\"')) {
                        ++i;
                    }
                    if(argv)
                        argv[argc][argi] = arg[i];
                    ++argi;
                    break;
                case ' ':
                case '\t':
                case '\n':
                case '\r':
                    if(groupch) {
                        if(argv)
                            argv[argc][argi] = arg[i];
                        ++argi;
                    } else {
                        if(lastch!='\0'&&lastch!=' '&&lastch!='\t'&&lastch!='\n'&&lastch!='\r') {
                            if (argv)
                                argv[argc][argi] = '\0';
                            ++argi;
                            ++argc;
                            if (argv)
                                argv[argc] = NULL;
                        }
                    }
                    break;
                default:
                    if(argv)
                        argv[argc][argi] = arg[i];
                    ++argi;
            }
            lastch = arg[i];
        }
        if(lastch!='\0'&&lastch!=' '&&lastch!='\t'&&lastch!='\n'&&lastch!='\r') {
            if (argv)
                argv[argc][argi] = '\0';
            ++argi;
            ++argc;
            if (argv)
                argv[argc] = NULL;
        }
        if(pass==0) {
            args = malloc(sizeof(void*) * (argc+1) + argi);
            argv = (char**)args;
            args = &args[sizeof(void*) * (argc+1)];
        }
    }
    argv[argc] = NULL;
    *argcptr = argc;
    *argvptr = argv;
    return 0;
}

