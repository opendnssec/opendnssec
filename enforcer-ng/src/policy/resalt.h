#ifndef _ENFORCER_RESALT_H_
#define _ENFORCER_RESALT_H_

#include "policy/kasp.pb.h"

/*+
 * PolicyUpdateSalt
 *
 * Description:
 *      Given a policy see if the salt needs updating (based on denial->resalt).
 *      If it is out of date then generate a new salt and write it to the object.
 *
 * Arguments:
 *      ::ods::kasp::Policy &policy
 *      	object that holds the current policy information should have been populated
 *
 * Returns:
 *      int
 *          Status return:
 *              1           success, policy was changed
 *              0           success, policy was unchanged
 *              <0          some error occurred and a message has been output.
 *              -1          no policy found
 *              -2          an error working out time difference between stamp and now
 *              -3          salt length in policy is out of range (either 0 or larger than 255)
 *
 -*/

int PolicyUpdateSalt(::ods::kasp::Policy &policy);

#endif
