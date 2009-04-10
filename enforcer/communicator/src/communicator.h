/* 
* communicator.h code implements the server_main
* function needed by daemon.c
*
* The bit that makes the daemon do something useful
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/

#define OUR_PATH "/home/sion/temp"

int server_init(DAEMONCONFIG *config);
void server_main(DAEMONCONFIG *config);
int commGenSignConf(KSM_ZONE *zone, KSM_POLICY *policy);
int commKeyConfig(void* context, KSM_KEYDATA* key_data);
void commsleep(DAEMONCONFIG* config);
