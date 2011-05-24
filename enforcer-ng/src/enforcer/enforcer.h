#ifndef _ENFORCER_ENFORCER_H_
#define _ENFORCER_ENFORCER_H_

#include "enforcer/enforcerdata.h"

/**
 * Does any required work for a zone and its policy.
 * insert new keys, check state of current keys and trashes old ones.
 * Returns the earliest time at which this zone needs attention.
 * When no further attention is needed return -1; Another date in the
 * past simply means ASAP. The function MAY be called again for this 
 * zone sooner than indicated. This is however pointless unless some
 * external event happened that influenced this zone/policy/keys.
 * 
 * \param[in] zone 
 * \param[in] now 
 * \param[in] keyfactory
 * \return time_t Time the function wishes to be called again.
 * */
time_t
update(EnforcerZone &zone, const time_t now, HsmKeyFactory &keyfactory);


#endif
