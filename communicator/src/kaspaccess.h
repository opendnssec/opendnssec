/* 
* kaspaccess.h kasp acccess functions needed by keygend
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/
#include "ksm.h"

int kaspReadConfig(DAEMONCONFIG* config);
void kaspSetPolicyDefaults(KSM_POLICY *policy, char *name);
void kaspConnect(DAEMONCONFIG* config, DB_HANDLE	*handle);
void kaspDisconnect(DAEMONCONFIG* config, DB_HANDLE	*handle);
int kaspReadPolicy(KSM_POLICY* policy);