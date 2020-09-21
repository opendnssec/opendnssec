/*
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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

#ifndef _ENFORCER_ENFORCER_H_
#define _ENFORCER_ENFORCER_H_

#include "db/zone_db.h"
#include "db/policy.h"
#include "daemon/engine.h"

/**
 * Does any required work for a zone and its policy.
 * 
 * Does any required work for a zone and its policy.
 * insert new keys, check state of current keys and trashes old ones.
 * Returns the earliest time at which this zone needs attention.
 * When no further attention is needed return -1; Another date in the
 * past simply means ASAP. The function MAY be called again for this 
 * zone sooner than indicated. This is however pointless unless some
 * external event happened that influenced this zone/policy/keys.
 * 
 * @param[in] zone 
 * @param[in] now 
 * @param[in] keyfactory
 * @return time_t Time the function wishes to be called again.
 * */
extern time_t
update(engine_type *engine, db_connection_t *dbconn, zone_db_t *zone, policy_t const *policy, time_t now, int *zone_updated);

#endif /* _ENFORCER_ENFORCER_H_ */
