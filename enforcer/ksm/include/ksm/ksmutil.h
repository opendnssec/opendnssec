/*
 * $Id$
 *
 * Copyright (c) 2008-2009 Nominet UK. All rights reserved.
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

#ifndef KSM_UTIL_H
#define KSM_UTIL_H

/*+
 * Filename: ksmutil.h
 *
 * Description:
 *      function definitions of stuff in the ksmutil code.
-*/
#include <stdio.h>
#include <ksm/ksm.h>
#include <ksm/database.h>
#include <libxml/xpath.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Function definitions */
int db_connect(DB_HANDLE *dbhandle, FILE** lock_fd, int backup);
void db_disconnect(FILE* lock_fd);
int read_filenames(char** zone_list_filename, char** kasp_filename);
int update_repositories();
int update_policies(char* kasp_filename);
int update_zones(char* zone_list_filename);
int get_lite_lock(char *lock_filename, FILE* lock_fd);
int release_lite_lock(FILE* lock_fd);
int SetParamOnPolicy(const xmlChar* new_value,
                     const char* name, 
                     const char* category, 
                     int current_value, 
                     int policy_id, 
                     int value_type);
void SetPolicyDefaults(KSM_POLICY *policy, char *name);
int backup_file(const char* orig_file, const char* backup_file);
int get_db_details(char** dbschema, 
                   char** host, 
                   char** port, 
                   char** user, 
                   char** password);
int read_zonelist_filename(char** zone_list_filename);
xmlDocPtr add_zone_node(const char *docname,
                        const char *zone_name, 
                        const char *policy_name, 
                        const char *sig_conf_name, 
                        const char *input_name, 
                        const char *output_name);
xmlDocPtr del_zone_node(const char *docname,
                        const char *zone_name);
void list_zone_node(const char *docname);
int append_policy(xmlDocPtr doc, KSM_POLICY *policy);
int printKey(void* context, KSM_KEYDATA* key_data);
void ksm_log_msg(const char *format);
int ListKeys(int zone_id);
int PurgeKeys(int zone_id, int policy_id);
int cmd_genkeys();
void SetPolicyDefaults(KSM_POLICY *policy, char *name);
int fix_file_perms(const char *dbschema);
int CountKeys(int *zone_id, int keytag, const char *cka_id, int *key_count, char **temp_cka_id, int *temp_key_state, int *temp_keypair_id);
int MarkDSSeen(int keypair_id, int zone_id, int policy_id, const char *datetime, int key_state);
int RetireOldKey(int zone_id, int policy_id, const char *datetime);
int CountKeysInState(int keytype, int keystate, int* count, int zone_id);
int ChangeKeyState(int keytype, const char *cka_id, int zone_id, int policy_id, const char *datetime, int key_state);
int get_conf_key_info(int* interval, int* man_key_gen);
int LinkKeys(const char* zone_name, int policy_id);
int allocateKeysToZone(KSM_POLICY *policy, int key_type, int zone_id, uint16_t interval, const char* zone_name, int man_key_gen, int rollover_scheme);

#ifdef __cplusplus
}
#endif

#endif /* KSM_UTIL_H */
