/*
 * $Id$
 *
 * Copyright 2008 Nominet UK, 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *     http://www.apache.org/licenses/LICENSE-2.0 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <security/cryptoki.h>
#include <pthread.h>
#include <wait.h>

#define PTHREAD_THREADS_MAX 2048

static CK_OBJECT_HANDLE key;
static int Iter = 1000;

typedef struct
{
    CK_SESSION_HANDLE ses;
} T_Arg;


/*
 * Check PKCS11 Return Values.
 * An error will cause exit, after de error is printed to stderr.
 * Returns nothing.
 */

void
check_rv (const char *message, CK_RV rv)
{
    if (rv != CKR_OK)
    {
        fprintf (stderr, "Error  0x%.8X in %s\n", (unsigned int) rv, message);
        exit (EXIT_FAILURE);
    }
}

/*
 * Signthread is a small loop that signs data "Iter" times.
 * Arguments: T_Arg struct pointer cast to void.
 * Returns nothing.
 */

void *
SignThread(void *Arg)
{
    CK_RV    rv;
    CK_ULONG len = 256;
    CK_BYTE  sig[256];
    int      x;
    T_Arg   *ThreadArg = Arg;

    // mech is a template to instruct what mechanism is needed for signing.

    CK_MECHANISM mech = { CKM_RSA_PKCS, NULL_PTR, 0 };

    for (x = 0; x < Iter; x++)
    {
        rv = C_SignInit(ThreadArg->ses, &mech, key);
        check_rv("C_SignInit", rv );

        // It is not relevant what is signed, hence the arbitrary message "Hello, World!"

        rv = C_Sign(ThreadArg->ses, (CK_UTF8CHAR *)"Hello, World!", 13, (CK_BYTE_PTR)sig, &len);
        check_rv("C_Sign", rv );
    }
    pthread_exit(NULL);
};

void
GetInfo(CK_SLOT_ID Slot)
{
    CK_RV          rv      = CKR_OK;
    CK_INFO        Info;
    CK_SLOT_INFO   slotInfo;
    rv = C_GetInfo(&Info);
    check_rv("C_GetInfo",rv);
    printf("Cryptoki Version: %d.%d\n",
        (int) Info.cryptokiVersion.major,
        (int) Info.cryptokiVersion.minor);

    printf("manufacturerID: %s\n", (char*) Info.manufacturerID);
    printf("Library Description: %s\n", (char*) Info.libraryDescription);
    printf("Library Version: %d.%d\n\n",
        (int) Info.libraryVersion.major,
        (int) Info.libraryVersion.minor);

    rv= C_GetSlotInfo(Slot,&slotInfo);
    check_rv("C_GetSlotInfo",rv);

    printf("Slot number:%d\n", (int) Slot);
    printf("Slot description: %s\n", (char*) slotInfo.slotDescription);
    printf("Manufacturer ID: %s\n", (char*) slotInfo.manufacturerID);
    printf("Hardware Version: %d.%d\n",
        (int) slotInfo.hardwareVersion.major,
        (int) slotInfo.hardwareVersion.minor);
    printf("Firmware Version: %d.%d\n",
        (int) slotInfo.firmwareVersion.major,
        (int) slotInfo.firmwareVersion.minor);
}

int
main (int argc, char *argv[])
{
    /* 
     * Variables for Forking
     */

    int            Forks     = 1;                 // default value
    int            ChildPID  = 0;

    /* 
     * Variables for multithreading
     */

    int            Threads   = 1;                 // default value
    pthread_t      ThreadArray[PTHREAD_THREADS_MAX];
    pthread_attr_t ThreadAttr;
    void          *ThreadStatus;
    T_Arg         *ThreadArg;

    /*
     * Variables for PKCS11
     */

    CK_SLOT_ID     Slot    = 0;                   // default value
    CK_UTF8CHAR   *Pin     = NULL;                // default value
    CK_UTF8CHAR   *label   = NULL_PTR;            // NO DEFAULT VALUE
    CK_ULONG       count   = 0;
    CK_RV          rv      = CKR_OK;
    CK_SESSION_HANDLE ses_array[PTHREAD_THREADS_MAX];

    /* 
     * Variables for timekeeping
     */

    static struct timeval start,end;

    /*
     * Handle Command Line Arguments.
     */

    int option;
    while ((option = getopt (argc, argv, "f:t:p:s:i:")) != -1)
    {
        switch (option)
        {
            case 'f':
                Forks = atoi (optarg);
                break;
            case 't':                             // Specifies amount of threads
                Threads = atoi (optarg);
                if (Threads > PTHREAD_THREADS_MAX)
                {
                    fprintf (stderr, "Can't specify more than %d threads\n",PTHREAD_THREADS_MAX);
                    exit (EXIT_FAILURE);
                };
                break;
            case 'p':                             // PIN for user login
                Pin = (CK_UTF8CHAR*)optarg;
                break;
            case 's':                             // Slot
                Slot = atoi (optarg);
                break;
            case 'i':
                Iter = atoi (optarg);
                break;
            default:
                fprintf (stderr, "Unrecognised option: -%c\n", optopt);
                exit (EXIT_FAILURE);
        }
    }

    if (argc <= optind)
    {
        perror("usage: hsm-speed [-t threads] [-s slot] [-p pin] [-i iterations] label\n");
        exit (EXIT_FAILURE);
    }

    label = (CK_UTF8CHAR *) argv[optind];

    if (!Pin) Pin = (CK_UTF8CHAR *) getpassphrase("Enter Pin: ");

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE search[] =
    {
        {CKA_LABEL, label, strlen ((char *) label)},
        {CKA_CLASS, &class, sizeof(class)}
    };
    int frks;
    gettimeofday(&start,NULL);
    for (frks=0;frks<Forks;frks++)
    {
        // Forking once is silly, since one child does the work of the parent
        // The purpose of forking is that we can use several children to do
        // the work.
        if (Forks > 1) ChildPID = fork();

        // We're either in the parent or child. The value Parent will contain
        // the PID of the forked child, if this would be the parent process.
        // else, the Parent value would be 0.
        if (ChildPID == 0)
        {

            // Initialize Library
            // Note that we do not need mutex locking for thread safety,
            // since we're using one session per thread.

            rv = C_Initialize(NULL_PTR);
            check_rv("C_Initialize",rv);

            // We want to see the library and slot info only once.
            // We can't do this in the parent, since the parent has not
            // initialized the library, so we do it on the first fork.
            // When there is no fork, the value of frks is zero anyway.

            if (frks == 0) GetInfo(Slot);

            // We will create one session per Thread.

            int c;
            for (c=0; c<Threads; c++)
            {
                rv = C_OpenSession (Slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &ses_array[c]);
                check_rv("C_OpenSession",rv);
            }

            // We need to login once. After that, all the sessions will now become user
            // sessions

            rv = C_Login(ses_array[0], CKU_USER, Pin, strlen ((char*)Pin));
            check_rv("C_Login", rv);

            // We need to find a key by its label. We use the search template for that.
            rv = C_FindObjectsInit (ses_array[0], search, 2);
            check_rv("C_FindObjectsInit", rv );

            // Return the first occurance of the key.
            rv = C_FindObjects(ses_array[0], &key, 1, &count);
            check_rv("C_FindObjects", rv );

            // We're done with searching.
            rv = C_FindObjectsFinal(ses_array[0]);
            check_rv("C_FindObjectsFinal", rv );

            // We're going to use multithreading to have parallel signing loops.
            // Since we need to wait until all threads are done, we need the threads
            // to join the main loop when they're done.

            pthread_attr_init(&ThreadAttr);
            pthread_attr_setdetachstate(&ThreadAttr, PTHREAD_CREATE_JOINABLE);

            // Since all threads use a single, shared memory, we can't just hand
            // them a session value, as that value will simply change.
            // Instead, we give a pointer to a struct.

            // Allocate memory for Thread Arguments
            ThreadArg=(T_Arg *)malloc(sizeof(T_Arg)*Threads);

            // Create threads.
            int rc;
            for (c=0;c<Threads;c++)
            {
                ThreadArg[c].ses = ses_array[c];
                rc = pthread_create( &ThreadArray[c], &ThreadAttr, SignThread, (void *)(ThreadArg+c));
                if (rc)
                {
                    fprintf(stderr, "ERROR, pthread_create() returned %d\n", rc);
                    exit(EXIT_FAILURE);
                }
            }

            // Wait for threads to join main.
            for (c=0;c<Threads;c++)
            {
                rc = pthread_join(ThreadArray[c], &ThreadStatus);
                if (rc)
                {
                    fprintf(stderr,"ERROR, pthread_join() returned %d\n", rc);
                    exit(EXIT_FAILURE);
                }
            }

            // Free memory for Thread Arguments
            free(ThreadArg);

            // We turn the user sessions back to public sessions.

            rv = C_Logout(ses_array[0]);
            check_rv("C_Logout", rv );

            // We can't rely on C_CloseAllSessions, as it has a bug in Sun's 
            // metaSlotManager.c where the function meta_release_slot_session() 
            // assumes there are no more then 100 idle sessions. As we allow 
            // many more threads, we need to avoid it.

            for (c=0;c<Threads;c++)
            {
                rv = C_CloseSession(ses_array[c]);
                check_rv("C_CloseSession", rv );
            }
            
            // We're done with the library
            rv = C_Finalize (NULL_PTR);
            check_rv("C_Finalize", rv);

            // Only exit here if we've forked.
            if (Forks>1) exit(EXIT_SUCCESS);
        }
    }

    // Wait for all forked children to exit.
    for (frks=0;frks<Forks;frks++)
    {
        wait(NULL);
    }

    // Measure the end time.
    gettimeofday(&end,NULL);

    end.tv_sec -=start.tv_sec;
    end.tv_usec-=start.tv_usec;
    double elapsed =(double)(end.tv_sec)+(double)(end.tv_usec)*.000001;
    double speed = Forks * Threads * Iter / elapsed;
    printf(" %d signatures, %.2f sig/s\n",Forks*Threads*Iter,speed);
    exit(EXIT_SUCCESS);
}
