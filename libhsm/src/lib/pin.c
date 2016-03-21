/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
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
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>

#include "libhsm.h"

/*! Global (initial) context */
extern hsm_ctx_t *_hsm_ctx;

/* Function from libhsm.c */
void
hsm_ctx_set_error(hsm_ctx_t *ctx, int error, const char *action,
                 const char *message, ...);

/* Constants */
#define SHM_KEY (key_t)0x0d50d5ec
#define SEM_KEY (key_t)0x0d50d5ec
#define SHM_PERM S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP
#define SEM_PERM S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP

#ifndef HAVE_UNION_SEMUN
/* From man page for semctl */
union semun {
    int              val;    /* Value for SETVAL */
    struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
    unsigned short  *array;  /* Array for GETALL, SETALL */
};
#endif

/* Remember PIN that we can save */
static char pin[HSM_MAX_PIN_LENGTH+1];

static char *
prompt_pass(char *prompt)
{
    int c, i = 0;
    static char pass[HSM_MAX_PIN_LENGTH+1];
    struct termios oldt, newt;

    if (prompt == NULL) return NULL;

    printf("%s", prompt);

    /* Turn echoing off */
    if (isatty(fileno(stdin))) {
        if (tcgetattr(fileno(stdin), &oldt) != 0) return NULL;
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        if (tcsetattr(fileno(stdin), TCSAFLUSH, &newt) != 0) return NULL;
    }

    /* Get the password */
    do {
        c = fgetc(stdin);
        pass[i] = c;
        i++;
    } while (c != EOF && c != '\n' && c != '\r' && i < HSM_MAX_PIN_LENGTH+1);
    pass[i-1] = '\0';

    /* Restore echoing */
    if (isatty(fileno(stdin))) {
        tcsetattr(fileno(stdin), TCSAFLUSH, &oldt);
    }
    printf("\n");

    return pass;
}

static int
hsm_sem_open()
{
    int semid;
    struct semid_ds buf;
    union semun arg;

    /* Create/get the semaphore */
    semid = semget(SEM_KEY, 1, IPC_CREAT|IPC_EXCL|SEM_PERM);
    if (semid == -1) {
        semid = semget(SEM_KEY, 1, IPC_CREAT|SEM_PERM);
        if (semid == -1) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_sem_open()",
                              "Could not access the semaphore: %s", strerror(errno));
            return -1;
        }
    } else {
        /* Set value to 1 if we created it */
        arg.val = 1;
        if (semctl(semid, 0, SETVAL, arg) == -1) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_sem_open()",
                              "Could not set value on the semaphore: %s", strerror(errno));
            return -1;
        }
    }

    /* Get information about the semaphore */
    arg.buf = &buf;
    if (semctl(semid, 0, IPC_STAT, arg) != 0) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_sem_open()",
                          "Could not stat the semaphore: %s", strerror(errno));
        return -1;
    }

    /* Check permission to avoid an attack */
    if ((buf.sem_perm.mode & (SEM_PERM)) != (SEM_PERM) ||
        buf.sem_perm.gid != getegid())
    {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_sem_open()",
                            "Bad permissions on the semaphore, please read Getting Help/Troubleshooting on OpenDNSSEC Wiki about this.");
        return -1;
    }

    return semid;
}

static int
hsm_sem_wait(int semid)
{
    struct sembuf sb = { 0, -1, 0 };

    if (semop(semid, &sb, 1) == -1) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_sem_wait()",
                          "Could not lock the semaphore: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int
hsm_sem_post(int semid)
{
    struct sembuf sb = { 0, 1, 0 };

    if (semop(semid, &sb, 1) == -1) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_sem_post()",
                          "Could not unlock the semaphore: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int
hsm_shm_open()
{
    int shmid;
    size_t shmsize;
    struct shmid_ds buf;

    /* Create/get the shared memory */
    shmsize = sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1);
    shmid = shmget(SHM_KEY, shmsize, IPC_CREAT|IPC_EXCL|SHM_PERM);
    if (shmid == -1) {
        shmid = shmget(SHM_KEY, shmsize, IPC_CREAT|SHM_PERM);
        if (shmid == -1) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_shm_open()",
                              "Could not access the shared memory: %s", strerror(errno));
            return -1;
        }
    } else {
        /* Zeroize if we created the memory area */

        /* The data should be set to zero according to man page */
    }

    /* Get information about the shared memory */
    if (shmctl(shmid, IPC_STAT, &buf) != 0) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_shm_open()",
                          "Could not stat the semaphore: %s", strerror(errno));
        return -1;
    }

    /* Check the size of the memory segment */
    if ((size_t)buf.shm_segsz != shmsize) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_shm_open()",
                            "Bad memory size, please read Getting Help/Troubleshooting on OpenDNSSEC Wiki about this.");
        return -1;
    }

    /* Check permission to avoid an attack */
    if ((buf.shm_perm.mode & (SHM_PERM)) != (SHM_PERM) ||
        buf.shm_perm.gid != getegid())
    {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_shm_open()",
                            "Bad permissions on the shared memory, please read Getting Help/Troubleshooting on OpenDNSSEC Wiki about this.");
        return -1;
    }

    return shmid;
}

char *
hsm_prompt_pin(unsigned int id, const char *repository, unsigned int mode)
{
    /* Shared memory */
    int shmid;
    int semid;
    char *pins = NULL;
    int index = id * (HSM_MAX_PIN_LENGTH + 1);

    /* PIN from getpass */
    char prompt[64];
    char *prompt_pin = NULL;
    unsigned int size = 0;

    /* Check input data */
    if (id >= HSM_MAX_SESSIONS) return NULL;
    if (repository == NULL) return NULL;
    if (mode != HSM_PIN_FIRST && mode != HSM_PIN_RETRY && mode != HSM_PIN_SAVE) return NULL;

    /* Create/get the semaphore */
    semid = hsm_sem_open();
    if (semid == -1) return NULL;

    /* Lock the semaphore */
    if (hsm_sem_wait(semid) != 0) return NULL;

    /* Create/get the shared memory */
    shmid = hsm_shm_open();
    if (shmid == -1) {
        hsm_sem_post(semid);
        return NULL;
    }

    /* Attach to the shared memory */
    pins = (char *)shmat(shmid, NULL, 0);
    if (pins == (char *)-1) {
        pins = NULL;
        hsm_sem_post(semid);
        return NULL;
    }

    /* Get the PIN */
    if (mode != HSM_PIN_SAVE) {
        /* Do we have a PIN in the shared memory? */
        if (mode == HSM_PIN_FIRST && pins[index] != '\0') {
            size = strlen(&pins[index]);
            if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
            memcpy(pin, &pins[index], size);
            pin[size] = '\0';
        } else {
            /* Zeroize bad PIN in shared memory */
            if (mode == HSM_PIN_RETRY && pins[index] != '\0') {
              memset(&pins[index], '\0', HSM_MAX_PIN_LENGTH+1);
            }

            /* Unlock the semaphore if someone would do Ctrl+C */
            hsm_sem_post(semid);

            /* Get PIN */
            snprintf(prompt, 64, "Enter PIN for token %s: ", repository);
            prompt_pin = prompt_pass(prompt);
            if (prompt_pin == NULL) {
                shmdt(pins);
                pins = NULL;
                return NULL;
            }

            /* Lock the semaphore */
            hsm_sem_wait(semid);

            /* Remember PIN */
            size = strlen(prompt_pin);
            if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
            memset(pin, '\0', HSM_MAX_PIN_LENGTH+1);
            memcpy(pin, prompt_pin, size);

            /* Zeroize the prompt_pass PIN */
            memset(prompt_pin, '\0', strlen(prompt_pin));
        }
    } else {
        /* Save the PIN */
        memcpy(&pins[index], pin, HSM_MAX_PIN_LENGTH+1);

        /* Zeroize the PIN */
        memset(pin, '\0', HSM_MAX_PIN_LENGTH+1);
    }

    /* Detach from the shared memory */
    shmdt(pins);
    pins = NULL;

    /* Unlock the semaphore */
    hsm_sem_post(semid);

    return pin;
}

char *
hsm_check_pin(unsigned int id, const char *repository, unsigned int mode)
{
    /* Shared memory */
    int shmid;
    int semid;
    char *pins = NULL;
    int index = id * (HSM_MAX_PIN_LENGTH + 1);

    unsigned int size = 0;

    /* Check input data */
    if (id >= HSM_MAX_SESSIONS) return NULL;
    if (repository == NULL) return NULL;
    if (mode != HSM_PIN_FIRST && mode != HSM_PIN_RETRY && mode != HSM_PIN_SAVE) return NULL;
    if (mode == HSM_PIN_SAVE) {
        /* Nothing to save */

        /* Zeroize the PIN */
        memset(pin, '\0', HSM_MAX_PIN_LENGTH+1);

        return pin;
    }

    /* Create/get the semaphore */
    semid = hsm_sem_open();
    if (semid == -1) return NULL;

    /* Lock the semaphore */
    if (hsm_sem_wait(semid) != 0) return NULL;

    /* Create/get the shared memory */
    shmid = hsm_shm_open();
    if (shmid == -1) {
        hsm_sem_post(semid);
        return NULL;
    }

    /* Attach to the shared memory */
    pins = (char *)shmat(shmid, NULL, 0);
    if (pins == (char *)-1) {
        pins = NULL;
        hsm_sem_post(semid);
        return NULL;
    }

    /* Zeroize PIN buffer */
    memset(pin, '\0', HSM_MAX_PIN_LENGTH+1);

    /* Check if there is no PIN */
    if (pins[index] == '\0') {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_check_pin()",
                          "No PIN in shared memory. "
                          "Please login with \"ods-hsmutil login\"");
        shmdt(pins);
        pins = NULL;
        hsm_sem_post(semid);
        return NULL;
    }

    /* Zeroize bad PIN in shared memory */
    if (mode == HSM_PIN_RETRY) {
        memset(&pins[index], '\0', HSM_MAX_PIN_LENGTH+1);
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_check_pin()",
                          "Removed bad PIN in shared memory. "
                          "Please login again with \"ods-hsmutil login\"");
        shmdt(pins);
        pins = NULL;
        hsm_sem_post(semid);
        return NULL;
    }

    /* Get the PIN */
    size = strlen(&pins[index]);
    if (size > HSM_MAX_PIN_LENGTH) size = HSM_MAX_PIN_LENGTH;
    memcpy(pin, &pins[index], size);
    pin[size] = '\0';

    /* Detach from the shared memory */
    shmdt(pins);
    pins = NULL;

    /* Unlock the semaphore */
    hsm_sem_post(semid);

    return pin;
}

int
hsm_logout_pin()
{
    int semid;
    int shmid;
    union semun arg;
    struct shmid_ds buf;

    /* Get the semaphore */
    semid = semget(SEM_KEY, 1, 0);
    if (semid == -1) {
        if (errno != ENOENT) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_logout_pin()",
                              "Could not access the semaphore: %s", strerror(errno));
            return HSM_ERROR;
        }
    } else {
        /* Remove the semaphore */
        if (semctl(semid, 0, IPC_RMID, arg) != 0) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_logout_pin()",
                              "Could not delete the semaphore: %s", strerror(errno));
            return HSM_ERROR;
        }
    }

    /* Get the shared memory */
    shmid = shmget(SHM_KEY, 0, 0);
    if (shmid == -1) {
        if (errno != ENOENT) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_logout_pin()",
                              "Could not access the shared memory: %s", strerror(errno));
            return HSM_ERROR;
        }
    } else {
        /* Remove the shared memory */
        if (shmctl(shmid, IPC_RMID, &buf) != 0) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_logout_pin()",
                              "Could not stat the semaphore: %s", strerror(errno));
            return HSM_ERROR;
        }
    }

    return HSM_OK;
}

