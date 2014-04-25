/*
 * Copyright (c) 2011 Surfnet 
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 * Copyright (c) 2011 OpenDNSSEC AB (svb)
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
 *
 */

#include "hsmkey/update_hsmkeys_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "libhsm.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"
#include "daemon/clientpipe.h"
#include "xmlext-pb/xmlext-rd.h"

#include <map>
#include <fcntl.h>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "update_hsmkeys_task";

static int 
import_all_keys_from_all_hsms(int sockfd, OrmConn conn)
{
    hsm_ctx_t * hsm_ctx = hsm_create_context();
    if (!hsm_ctx) {
        ods_log_error_and_printf(sockfd, module_str, "could not connect to HSM");
        return 1;
    }
    size_t nkeys;
    libhsm_key_t **kl = hsm_list_keys(hsm_ctx, &nkeys);
    if (!kl) {
        ods_log_error_and_printf(sockfd, module_str, "could not list hsm keys");
        return 1;
    }

    client_printf(sockfd,
				"HSM keys:\n"
				"        "
				"Algorithm: "
				"Bits:   "
				"Id:                                      "
				"\n"
				);

	OrmTransactionRW transaction(conn);
	if (!transaction.started()) {
        ods_log_error_and_printf(sockfd, module_str,
								 "could not start database transaction");
		libhsm_key_list_free(kl,nkeys);
		hsm_destroy_context(hsm_ctx);
        return 1;
	}
	int error = 0;
    for (int i=0; i<nkeys; ++i) {
        libhsm_key_t *k = kl[i];
        libhsm_key_info_t *kinf = hsm_get_key_info(hsm_ctx,k);

		OrmResultRef result;
		if (!OrmMessageEnumWhere(conn, ::ods::hsmkey::HsmKey::descriptor(),
								 result, "locator='%s'",kinf->id))
		{
			// free allocated resources
			libhsm_key_info_free(kinf);

			ods_log_error_and_printf(sockfd, module_str,
									 "database query failed");
			error = 1;
			break;
		}
			
		if (OrmFirst(result)) {
			// Key already exists
			::ods::hsmkey::HsmKey key;
			OrmContextRef context;
			if (!OrmGetMessage(result,key,true,context)) {
				// free allocated resources
				libhsm_key_info_free(kinf);
				// release query result, we don't need it anymore.
				result.release();
				
				// This is an unexpected error !
				ods_log_error_and_printf(sockfd, module_str,
										 "database record retrieval failed");
				error = 1;
				break;
			} else {
				// release query result, we don't need it anymore.
				result.release();

				// retrieved the key from the database
				
				// Change key settings based on information from HSM key info
				if (key.key_type() == std::string(kinf->algorithm_name)
					|| key.repository() == std::string(k->module->name))
				{

					// key in the table does NOT need updating.
					
				} else {
					// key in the table needs updating.
					key.set_key_type( kinf->algorithm_name );
					key.set_repository( k->module->name );
					
					if (!OrmMessageUpdate(context)) {
						
						// This is an unexpected error !
						ods_log_error_and_printf(sockfd, module_str,
											"database record retrieval failed");
						
					} else {

						client_printf(sockfd,
									"%-7s %-10s %-7ld %-40s\n",
									"update",
									kinf->algorithm_name,
									kinf->keysize,
									kinf->id
									);

					}
				}
				
				// release the context, we don't need it anymore.
				context.release();
			}
		} else {
			// release query result, we don't need it anymore.
			result.release();
			
			// key does not exist
			::ods::hsmkey::HsmKey key;
			key.set_locator(kinf->id);
			key.set_bits(kinf->keysize);
			key.set_key_type( kinf->algorithm_name );
			key.set_repository( k->module->name );
			
			// verify that according to the proto file definition the key is
			// fully initialized.
			if(!key.IsInitialized()) {
				// free allocated resources
				libhsm_key_info_free(kinf);
				
				ods_log_error_and_printf(sockfd, module_str,
										 "new HsmKey missing required fields");				
				error = 1;
				break;
			}
			
			pb::uint64 keyid;
			if (!OrmMessageInsert(conn, key, keyid)) {
				// free allocated resources
				libhsm_key_info_free(kinf);

				// This is an unexpected error !
				ods_log_error_and_printf(sockfd, module_str,
										 "database record insertion failed");
				
				error = 1;
				break;
			} else {
				
				// Key was inserted successfully
				client_printf(sockfd,
							"%-7s %-10s %-7ld %-40s\n",
							"import",
							kinf->algorithm_name,
							kinf->keysize,
							kinf->id
							);
			}
		}

        libhsm_key_info_free(kinf);
    }
    libhsm_key_list_free(kl,nkeys);
    hsm_destroy_context(hsm_ctx);
    return error;
}

int 
perform_update_hsmkeys(int sockfd, engineconfig_type *config, int bManual)
{
	// check that we are using a compatible protobuf version.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	
	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return 1; // errors have already been reported.
	
	// Go through all the keys in HSMs and import them if they are 
	// not already present
	if (bManual) {
		client_printf(sockfd, "Database set to: %s\n", config->datastore);
		// DEPRECATED, key state import should selectively import keys.
		return import_all_keys_from_all_hsms(sockfd,conn);
	}
	return 0;
}
