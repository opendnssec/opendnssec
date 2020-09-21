/*
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 *
 * The netio module implements event based I/O handling using
 * pselect(2).  Multiple event handlers can wait for a certain event
 * to occur simultaneously.  Each event handler is called when an
 * event occurs that the event handler has indicated that it is
 * willing to handle.
 *
 * There are four types of events that can be handled:
 *
 *   NETIO_EVENT_READ: reading will not block.
 *   NETIO_EVENT_WRITE: writing will not block.
 *   NETIO_EVENT_EXCEPT: an exception occurred.
 *   NETIO_EVENT_TIMEOUT: the timeout expired.
 *
 * A file descriptor must be specified if the handler is interested in
 * the first three event types.  A timeout must be specified if the
 * event handler is interested in timeouts.  These event types can be
 * OR'ed together if the handler is willing to handle multiple types
 * of events.
 *
 * The special event type NETIO_EVENT_NONE is available if you wish to
 * temporarily disable the event handler without removing and adding
 * the handler to the netio structure.
 *
 * The event callbacks are free to modify the netio_handler_type
 * structure to change the file descriptor, timeout, event types, user
 * data, or handler functions.
 *
 * The main loop of the program must call netio_dispatch to check for
 * events and dispatch them to the handlers.  An additional timeout
 * can be specified as well as the signal mask to install while
 * blocked in pselect(2).
 */

/**
 * Network I/O Support.
 *
 */

#ifndef WIRE_NETIO_H_
#define WIRE_NETIO_H_

#ifdef	HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <signal.h>

#include "config.h"
#include "status.h"

#ifndef PF_INET
#define PF_INET AF_INET
#endif
#ifndef PF_INET6
#define PF_INET6 AF_INET6
#endif

/*
 * The type of events a handler is interested in.
 * These can be OR'ed together to specify multiple event types.
 *
 */
enum netio_events_enum {
	NETIO_EVENT_NONE    = 0,
	NETIO_EVENT_READ    = 1,
	NETIO_EVENT_WRITE   = 2,
	NETIO_EVENT_EXCEPT  = 4,
	NETIO_EVENT_TIMEOUT = 8
};
typedef enum netio_events_enum netio_events_type;

typedef struct netio_struct netio_type;
typedef struct netio_handler_struct netio_handler_type;
typedef struct netio_handler_list_struct netio_handler_list_type;

/**
 * Network I/O event handler function.
 *
 */
typedef void (*netio_event_handler_type)(netio_type *netio,
    netio_handler_type* handler, netio_events_type event_types);

/**
 * Network I/O event handler list.
 *
 */
struct netio_handler_list_struct {
    netio_handler_list_type* next;
    netio_handler_type* handler;
};

/**
 * Network I/O event handler.
 *
 */
struct netio_handler_struct {
    /*
     * The file descriptor that should be checked for events.  If
     * the file descriptor is negative only timeout events are
     * checked for.
     */
    int fd;
    /*
     * The time when no events should be checked for and the
     * handler should be called with the NETIO_EVENT_TIMEOUT
     * event type.  Unlike most timeout parameters the time should
     * be absolute, not relative!
     */
    struct timespec* timeout;
    /*
     * User data.
     */
    void* user_data;
    /*
     * The type of events that should be checked for.  These types
     * can be OR'ed together to wait for multiple types of events.
     */
    netio_events_type event_types;
    /*
     * The event handler.  The event_types parameter contains the
     * OR'ed set of event types that actually triggered.  The
     * event handler is allowed to modify this handler object.
     * The event handler SHOULD NOT block.
     */
    netio_event_handler_type event_handler;
    int free_handler;
};

/**
 * Network I/O instance.
 *
 */
struct netio_struct {
    netio_handler_list_type* handlers;
    /*
     * Cached value of the current time.  The cached value is
     * cleared at the start of netio_dispatch to calculate the
     * relative timeouts of the event handlers and after calling
     * pselect(2) so handlers can use it to calculate a new
     * absolute timeout.
     *
     * Use netio_current_time() to read the current time.
     */
    int have_current_time;
    struct timespec cached_current_time;
    /*
     * Next handler in the dispatch. Only valid during callbacks.
     * To make sure that deletes respect the state of the iterator.
     */
    netio_handler_list_type* dispatch_next;
};

/*
 * Create a new netio instance.
 * \param[in] allocator memory allocator
 * \return netio_type* netio instance
 *
 */
extern netio_type* netio_create(void);

/*
 * Add a new handler to netio.
 * \param[in] netio netio instance
 * \param[in] handler handler
 *
 */
extern void netio_add_handler(netio_type* netio, netio_handler_type* handler);

/*
 * Remove the handler from netio.
 * \param[in] netio netio instance
 * \param[in] handler handler
 *
 */
extern void netio_remove_handler(netio_type* netio, netio_handler_type* handler);

/*
 * Retrieve the current time (using gettimeofday(2)).
 * \param[in] netio netio instance
 * \return const struct timespec* current time
 *
 */
extern const struct timespec* netio_current_time(netio_type* netio);

/*
 * Check for events and dispatch them to the handlers.
 * \param[in] netio netio instance
 * \param[in] timeout if specified, the maximum time to wait for an
 *                    event to arrive.
 * \param[in] sigmask is passed to the underlying pselect(2) call
 * \return int the number of non-timeout events dispatched, 0 on timeout,
 *             and -1 on error (with errno set appropriately).
 *
 */
extern int netio_dispatch(netio_type* netio, const struct timespec* timeout,
   const sigset_t* sigmask);

/**
 * Clean up netio instance
 * \param[in] netio netio instance
 *
 */
extern void netio_cleanup(netio_type* netio);
extern void netio_cleanup_shallow(netio_type* netio);

/**
 * Add timespecs.
 * \param[in] left left
 * \param[in] right right
 *
 */
extern void timespec_add(struct timespec* left, const struct timespec* right);


#ifdef __cplusplus
inline netio_events_type
operator | (netio_events_type lhs, netio_events_type rhs) {
	return (netio_events_type) (lhs | rhs);
}
inline netio_events_type
operator |= (netio_events_type &lhs, netio_events_type rhs) {
	lhs = (netio_events_type) (lhs | rhs);
	return lhs;
}
#endif /* __cplusplus */

#endif /* WIRE_NETIO_H_ */
