/*
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "wire/netio.h"


#ifndef HAVE_PSELECT
int pselect(int n, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
	    const struct timespec* timeout, const sigset_t* sigmask);
#else
#include <sys/select.h>
#endif

/* One second is 1e9 nanoseconds.  */
#define NANOSECONDS_PER_SECOND   1000000000L

static const char* netio_str = "netio";


/*
 * Create a new netio instance.
 * \return netio_type* netio instance
 *
 */
netio_type*
netio_create()
{
    netio_type* netio = NULL;
    CHECKALLOC(netio = (netio_type*) malloc(sizeof(netio_type)));
    netio->handlers = NULL;
    netio->dispatch_next = NULL;
    return netio;
}

/*
 * Add a new handler to netio.
 *
 */
void
netio_add_handler(netio_type* netio, netio_handler_type* handler)
{
    netio_handler_list_type* l = NULL;

    ods_log_assert(netio);
    ods_log_assert(handler);

    CHECKALLOC(l = (netio_handler_list_type*) malloc(sizeof(netio_handler_list_type)));
    l->next = netio->handlers;
    l->handler = handler;
    netio->handlers = l;
    ods_log_debug("[%s] handler added", netio_str);
}

/*
 * Remove the handler from netio. Caller is responsible for freeing
 * handler afterwards.
 */
void
netio_remove_handler(netio_type* netio, netio_handler_type* handler)
{
    netio_handler_list_type** lptr;
    if (!netio || !handler) {
        return;
    }
    for (lptr = &netio->handlers; *lptr; lptr = &(*lptr)->next) {
        if ((*lptr)->handler == handler) {
            netio_handler_list_type* next = (*lptr)->next;
            if ((*lptr) == netio->dispatch_next) {
                netio->dispatch_next = next;
            }
            (*lptr)->handler = NULL;
	    free(*lptr);
            *lptr = next;
            break;
        }
    }
    ods_log_debug("[%s] handler removed", netio_str);
}


/*
 * Convert timeval to timespec.
 *
 */
static void
timeval_to_timespec(struct timespec* left, const struct timeval* right)
{
    left->tv_sec = right->tv_sec;
    left->tv_nsec = 1000 * right->tv_usec;
}

/**
 * Compare timespec.
 *
 */
static int
timespec_compare(const struct timespec* left,
    const struct timespec* right)
{
    if (left->tv_sec < right->tv_sec) {
        return -1;
    } else if (left->tv_sec > right->tv_sec) {
        return 1;
    } else if (left->tv_nsec < right->tv_nsec) {
        return -1;
    } else if (left->tv_nsec > right->tv_nsec) {
         return 1;
    }
    return 0;
}


/**
 * Add timespecs.
 *
 */
void
timespec_add(struct timespec* left, const struct timespec* right)
{
    left->tv_sec += right->tv_sec;
    left->tv_nsec += right->tv_nsec;
    if (left->tv_nsec >= NANOSECONDS_PER_SECOND) {
        ++left->tv_sec;
        left->tv_nsec -= NANOSECONDS_PER_SECOND;
    }
}


/**
 * Substract timespecs.
 *
 */
static void
timespec_subtract(struct timespec* left, const struct timespec* right)
{
    left->tv_sec -= right->tv_sec;
    left->tv_nsec -= right->tv_nsec;
    if (left->tv_nsec < 0L) {
        --left->tv_sec;
        left->tv_nsec += NANOSECONDS_PER_SECOND;
    }
}


/*
 * Retrieve the current time (using gettimeofday(2)).
 *
 */
const struct timespec*
netio_current_time(netio_type* netio)
{
    struct timeval current_timeval;
    ods_log_assert(netio);
    if (!netio->have_current_time) {
        if (gettimeofday(&current_timeval, NULL) == -1) {
            ods_log_crit("[%s] unable to get current time: "
                "gettimeofday() failed (%s)", netio_str,
                strerror(errno));
            abort();
        }
        timeval_to_timespec(&netio->cached_current_time,
            &current_timeval);
        netio->have_current_time = 1;
    }
    return &netio->cached_current_time;
}


/*
 * Check for events and dispatch them to the handlers.
 *
 */
int
netio_dispatch(netio_type* netio, const struct timespec* timeout,
    const sigset_t* sigmask)
{
    fd_set readfds, writefds, exceptfds;
    int max_fd;
    int have_timeout = 0;
    struct timespec minimum_timeout;
    netio_handler_type* timeout_handler = NULL;
    netio_handler_list_type* l = NULL;
    int rc = 0;
    int result = 0;

    if (!netio || !netio->handlers) {
        return 0;
    }
    /* Clear the cached current time */
    netio->have_current_time = 0;
    /* Initialize the minimum timeout with the timeout parameter */
    if (timeout) {
        have_timeout = 1;
        memcpy(&minimum_timeout, timeout, sizeof(struct timespec));
    }
    /* Initialize the fd_sets and timeout based on the handler
     * information */
    max_fd = -1;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    for (l = netio->handlers; l; l = l->next) {
        netio_handler_type* handler = l->handler;
        if (handler->fd >= 0 && handler->fd < (int) FD_SETSIZE) {
            if (handler->fd > max_fd) {
                max_fd = handler->fd;
            }
            if (handler->event_types & NETIO_EVENT_READ) {
                FD_SET(handler->fd, &readfds);
            }
            if (handler->event_types & NETIO_EVENT_WRITE) {
                FD_SET(handler->fd, &writefds);
            }
            if (handler->event_types & NETIO_EVENT_EXCEPT) {
                FD_SET(handler->fd, &exceptfds);
            }
        }
        if (handler->timeout &&
            (handler->event_types & NETIO_EVENT_TIMEOUT)) {
            struct timespec relative;
            relative.tv_sec = handler->timeout->tv_sec;
            relative.tv_nsec = handler->timeout->tv_nsec;
            timespec_subtract(&relative, netio_current_time(netio));

            if (!have_timeout ||
                timespec_compare(&relative, &minimum_timeout) < 0) {
                have_timeout = 1;
                minimum_timeout.tv_sec = relative.tv_sec;
                minimum_timeout.tv_nsec = relative.tv_nsec;
                timeout_handler = handler;
            }
        }
    }

    if (have_timeout && minimum_timeout.tv_sec < 0) {
        /*
         * On negative timeout for a handler, immediately
         * dispatch the timeout event without checking for other events.
         */
        ods_log_debug("[%s] dispatch timeout event without checking for "
            "other events", netio_str);
        if (timeout_handler &&
            (timeout_handler->event_types & NETIO_EVENT_TIMEOUT)) {
            timeout_handler->event_handler(netio, timeout_handler,
                NETIO_EVENT_TIMEOUT);
        }
        return result;
    }
    /* Check for events. */
    rc = pselect(max_fd + 1, &readfds, &writefds, &exceptfds,
        have_timeout ? &minimum_timeout : NULL, sigmask);
    if (rc == -1) {
        if(errno == EINVAL || errno == EACCES || errno == EBADF) {
            ods_fatal_exit("[%s] fatal error pselect: %s", netio_str,
                strerror(errno));
        }
        return -1;
    }

    /* Clear the cached current_time (pselect(2) may block for
     * some time so the cached value is likely to be old).
     */
    netio->have_current_time = 0;
    if (rc == 0) {
        ods_log_debug("[%s] no events before the minimum timeout "
            "expired", netio_str);
        /*
         * No events before the minimum timeout expired.
         * Dispatch to handler if interested.
         */
        if (timeout_handler &&
            (timeout_handler->event_types & NETIO_EVENT_TIMEOUT)) {
            timeout_handler->event_handler(netio, timeout_handler,
                NETIO_EVENT_TIMEOUT);
        }
    } else {
        /*
         * Dispatch all the events to interested handlers
         * based on the fd_sets.  Note that a handler might
         * deinstall itself, so store the next handler before
         * calling the current handler!
         */
	ods_log_assert(netio->dispatch_next == NULL);
        for (l = netio->handlers; l && rc; ) {
            netio_handler_type* handler = l->handler;
            netio->dispatch_next = l->next;
            if (handler->fd >= 0 && handler->fd < (int) FD_SETSIZE) {
                netio_events_type event_types = NETIO_EVENT_NONE;
                if (FD_ISSET(handler->fd, &readfds)) {
                    event_types |= NETIO_EVENT_READ;
                    FD_CLR(handler->fd, &readfds);
                    rc--;
                }
                if (FD_ISSET(handler->fd, &writefds)) {
                    event_types |= NETIO_EVENT_WRITE;
                    FD_CLR(handler->fd, &writefds);
                    rc--;
                }
                if (FD_ISSET(handler->fd, &exceptfds)) {
                    event_types |= NETIO_EVENT_EXCEPT;
                    FD_CLR(handler->fd, &exceptfds);
                    rc--;
                }
                if (event_types & handler->event_types) {
                    handler->event_handler(netio, handler,
                        event_types & handler->event_types);
                    ++result;
                }
            }
            l = netio->dispatch_next;
        }
        netio->dispatch_next = NULL;
    }
    return result;
}


/**
 * Clean up netio instance
 *
 */
void
netio_cleanup(netio_type* netio)
{
    ods_log_assert(netio);
    while (netio->handlers) {
        netio_handler_list_type* handler = netio->handlers;
        netio->handlers = handler->next;
        if (handler->handler->free_handler) {
            free(handler->handler->user_data);
            free(handler->handler);
        }
        free(handler);
    }
    free(netio);
}

/**
 * Clean up netio instance
 */
void
netio_cleanup_shallow(netio_type* netio)
{
    ods_log_assert(netio);
    free(netio->handlers);
    free(netio);
}

