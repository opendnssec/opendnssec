/* COPYRIGHT 2016 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>

#include "debug.h"

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

void *
fn1(void *dummy)
{
    (void)dummy;
    x();
    return NULL;
}

void *
fn2(void *dummy)
{
    (void)dummy;
    x();
    return NULL;
}

void *
fn3(void *dummy)
{
    (void)dummy;
    sleep(10);
    recurse();
    return NULL;
}

int
main(int argc, char* argv[])
{
    int i;
    thread_t thr1;
    thread_t thr2;
    thread_t thr3;
    installexit();
    daemon_disablecoredump();
    daemon_trapsignals(argv[0]);
    terminate = 0;
    daemon_thread_create(&thr1, fn1, NULL);
    daemon_thread_create(&thr2, fn2, NULL);
    daemon_thread_create(&thr3, fn3, NULL);
    daemon_thread_start(thr1);
    daemon_thread_start(thr2);
    daemon_thread_start(thr3);
    sleep(16);
    terminate = 1;
    daemon_thread_join(thr1, NULL);
    daemon_thread_join(thr2, NULL);
    daemon_thread_join(thr3, NULL);
    return 0;
}
