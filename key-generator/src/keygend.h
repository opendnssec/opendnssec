/* 
* keygend.h code implements the server_main
* function needed by daemon.c
*
* The bit that makes the daemon do something useful
*
* Copyright (c) 2008 2009, John Dickinson. All rights reserved.
*
* See LICENSE for the license.
*/

int server_init(DAEMONCONFIG *config);
void server_main(DAEMONCONFIG *config);