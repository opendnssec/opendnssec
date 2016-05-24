#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>

#include "janitor.h"

static int terminate;

void
crash(void)
{
    char* p;
    p = NULL;
    *p = '\0';
}

void __attribute__ ((noinline))
recurse(void) 
{
    crash();
}

void
y(void)
{
    while(!terminate) {
        printf("Hello World!\n");
        sleep(3);
    }
}

void
x(void)
{
    y();
}

void
fn1(void *dummy)
{
    (void)dummy;
    x();
}

void
fn2(void *dummy)
{
    (void)dummy;
    x();
}

void
fn3(void *dummy)
{
    (void)dummy;
    sleep(10);
    recurse();
}

int
main(int argc, char* argv[])
{
    int i;
    janitor_thread_t thr1;
    janitor_thread_t thr2;
    janitor_thread_t thr3;
    janitor_disablecoredump();
    janitor_trapsignals(argv[0]);
    terminate = 0;
    janitor_thread_create(&thr1, janitor_threadclass_DEFAULT, fn1, NULL);
    janitor_thread_create(&thr2, janitor_threadclass_DEFAULT, fn2, NULL);
    janitor_thread_create(&thr3, janitor_threadclass_DEFAULT, fn3, NULL);
    janitor_thread_start(thr1);
    janitor_thread_start(thr2);
    janitor_thread_start(thr3);
    sleep(16);
    terminate = 1;
    janitor_thread_join(thr1);
    janitor_thread_join(thr2);
    janitor_thread_join(thr3);
    return 0;
}
