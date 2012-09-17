/* $Id$ */

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
#include <semaphore.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include "libhsm.h"

/*! Global (initial) context */
extern hsm_ctx_t *_hsm_ctx;

/* Function from libhsm.c */
void
hsm_ctx_set_error(hsm_ctx_t *ctx, int error, const char *action,
                 const char *message, ...);

/* Constants */
#define SHM_KEY (key_t)0x0d50d5ec
#define SEM_NAME "/ods_libhsm"
#define SHM_PERM S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP

/* Remember PIN that we can save */
static char pin[HSM_MAX_PIN_LENGTH+1];

char *
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

char *
hsm_prompt_pin(unsigned int id, const char *repository, unsigned int mode)
{
    /* Shared memory */
    int shmid;
    int created = 0;
    struct shmid_ds buf;
    size_t shm_size;
    char *pins = NULL;
    sem_t *pin_semaphore = NULL;
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
    pin_semaphore = sem_open(SEM_NAME, O_CREAT, SHM_PERM, 1);
    if (pin_semaphore == SEM_FAILED) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_prompt_pin()",
                          "Could not access the named semaphore");
        return NULL;
    }

    /* Lock the semaphore */
    if (sem_wait(pin_semaphore) != 0) {
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Create/get the shared memory */
    shm_size = sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1);
    shmid = shmget(SHM_KEY, shm_size, IPC_CREAT|IPC_EXCL|SHM_PERM);
    if (shmid == -1) {
        shmid = shmget(SHM_KEY, shm_size, IPC_CREAT|SHM_PERM);
        if (shmid == -1) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_prompt_pin()",
                              "Could not access the shared memory. May need to reset "
                              "it by running the command \"ipcrm -M 0x0d50d5ec\"");
            sem_post(pin_semaphore);
            sem_close(pin_semaphore);
            pin_semaphore = NULL;
            return NULL;
        }
    } else {
        created = 1;
    }

    /* Get information about the shared memory */
    if (shmctl(shmid, IPC_STAT, &buf) != 0) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Check the size of the memory segment */
    if (buf.shm_segsz != shm_size) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_prompt_pin()",
                            "Bad memory size. Please reset the shared memory "
                            "by running the command \"ipcrm -M 0x0d50d5ec\"");
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Check permission to avoid an attack */
    if ((buf.shm_perm.mode & (SHM_PERM)) != (SHM_PERM) ||
        buf.shm_perm.gid != getegid())
    {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_prompt_pin()",
                            "Bad permissions on the shared memory");
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Attach to the shared memory */
    pins = (char *)shmat(shmid, NULL, 0);
    if (pins == (char *)-1) {
        pins = NULL;
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Zeroize if we created the memory area */
    if (created == 1) {
        memset(pins, '\0', sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1));
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
            sem_post(pin_semaphore);

            /* Get PIN */
            snprintf(prompt, 64, "Enter PIN for token %s: ", repository);
            prompt_pin = prompt_pass(prompt);
            if (prompt_pin == NULL) {
                shmdt(pins);
                pins = NULL;
                sem_close(pin_semaphore);
                pin_semaphore = NULL;
                return NULL;
            }

            /* Lock the semaphore */
            sem_wait(pin_semaphore);

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
    sem_post(pin_semaphore);

    /* Close semaphore */
    sem_close(pin_semaphore);
    pin_semaphore = NULL;

    return pin;
}

char *
hsm_check_pin(unsigned int id, const char *repository, unsigned int mode)
{
    /* Shared memory */
    int shmid;
    int created = 0;
    struct shmid_ds buf;
    size_t shm_size;
    char *pins = NULL;
    sem_t *pin_semaphore = NULL;
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
    pin_semaphore = sem_open(SEM_NAME, O_CREAT, SHM_PERM, 1);
    if (pin_semaphore == SEM_FAILED) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_check_pin()",
                          "Could not access the named semaphore");
        return NULL;
    }

    /* Lock the semaphore */
    if (sem_wait(pin_semaphore) != 0) {
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Create/get the shared memory */
    shm_size = sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1);
    shmid = shmget(SHM_KEY, shm_size, IPC_CREAT|IPC_EXCL|SHM_PERM);
    if (shmid == -1) {
        shmid = shmget(SHM_KEY, shm_size, IPC_CREAT|SHM_PERM);
        if (shmid == -1) {
            hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_check_pin()",
                              "Could not access the shared memory. May need to reset "
                              "it by running the command \"ipcrm -M 0x0d50d5ec\"");
            sem_post(pin_semaphore);
            sem_close(pin_semaphore);
            pin_semaphore = NULL;
            return NULL;
        }
    } else {
        created = 1;
    }

    /* Get information about the shared memory */
    if (shmctl(shmid, IPC_STAT, &buf) != 0) {
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Check the size of the memory segment */
    if (buf.shm_segsz != shm_size) {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_check_pin()",
                            "Bad memory size. Please reset the shared memory "
                            "by running the command \"ipcrm -M 0x0d50d5ec\"");
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Check permission to avoid an attack */
    if ((buf.shm_perm.mode & (SHM_PERM)) != (SHM_PERM) ||
        buf.shm_perm.gid != getegid())
    {
        hsm_ctx_set_error(_hsm_ctx, HSM_ERROR, "hsm_check_pin()",
                            "Bad permissions on the shared memory");
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Attach to the shared memory */
    pins = (char *)shmat(shmid, NULL, 0);
    if (pins == (char *)-1) {
        pins = NULL;
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
        return NULL;
    }

    /* Zeroize if we created the memory area */
    if (created == 1) {
        memset(pins, '\0', sizeof(char)*HSM_MAX_SESSIONS*(HSM_MAX_PIN_LENGTH+1));
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
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
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
        sem_post(pin_semaphore);
        sem_close(pin_semaphore);
        pin_semaphore = NULL;
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
    sem_post(pin_semaphore);

    /* Close semaphore */
    sem_close(pin_semaphore);
    pin_semaphore = NULL;

    return pin;
}
