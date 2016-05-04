/* COPYRIGHT 2016 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>

#include "debug.h"

void
b(void)
{
    char* p;
    p = NULL;
    *p = '\0';
}

void __attribute__ ((noinline))
a(void) 
{
    b();
}

void
y(void)
{
    for(;;) {
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
    a();
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
    /*installcoreprevent();*/
    installcrashhandler(argv[0]);
    
    createthread(&thr1, fn1, NULL);
    createthread(&thr2, fn2, NULL);/*
    createthread(&thr3, fn3, NULL);*/
    startthread(thr1);
    startthread(thr2);/*
    startthread(thr3);*/
    sleep(8);
    dumpthreads();
    sleep(8);
    dumpthreads();
    sleep(8);
    fprintf(stderr,"will now try to exit\n");
    return 0;
}
