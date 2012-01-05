#include "hsmkey/hsmkey_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "shared/str.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext-rd.h"

#include <fcntl.h>

#include "protobuf-orm/pb-orm.h"
#include "daemon/orm.h"

static const char *module_str = "hsmkey_list_task";

void 
perform_hsmkey_list(int sockfd, engineconfig_type *config, int bVerbose)
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    // Load the current list of pre-generated keys

	OrmConnRef conn;
	if (!ods_orm_connect(sockfd, config, conn))
		return; // errors have already been reported.
	
    if (!bVerbose){
        ods_printf(sockfd,
                       "HSM keys:\n"
                       "Id:                                      "
                       "Key type:  "
                       "Bits:   "
                       "Repository:  "
                       "First use:                 "
                       "\n"
                       );
    } else {
        ods_printf(sockfd,
                       "HSM keys:\n"
                       "Id:                                      "
                       "Key type:  "
                       "Bits:   "
                       "Repository:  "
                       "First use:                 "
                       "Key role:   "
                       "Algorithm : "
                       "Policy :                        "
                       "\n"
                       );
    }

	{	OrmTransaction transaction(conn);
		
		if (!transaction.started()) {
			ods_printf(sockfd,"error: database transaction failed\n");
			return false;
		}
			
		{	OrmResultRef rows;

			if (!OrmMessageEnum(conn, ::ods::hsmkey::HsmKey::descriptor(), rows)) {
				ods_printf(sockfd,"error: database hsm key enumeration failed\n");
				return false;
			}
			
			// Enumerate the hsm keys referenced in the database
			for (bool next=OrmFirst(rows); next; next=OrmNext(rows)) {
				::ods::hsmkey::HsmKey key;
				if (OrmGetMessage(rows, key, true)) {
					std::string ktype  = key.key_type();
					uint32_t bits = key.bits();
					std::string loca = key.locator();
					std::string repo = key.repository();
					char incep[32];
					if (key.inception() != 0) {
						if (!ods_ctime_r(incep,sizeof(incep),key.inception())) {
							strncpy(incep,"invalid date/time",sizeof(incep));
							incep[sizeof(incep)-1] = '\0';
						}
					} else {
						strncpy(incep,"never",sizeof(incep));
						incep[sizeof(incep)-1] = '\0';
					}
					
					char keyalgo[32];
					if (key.has_algorithm()) {
						snprintf(keyalgo,sizeof(keyalgo),"%d",key.algorithm());
					} else {
						strncpy(keyalgo,"not set",sizeof(keyalgo));
					}
					keyalgo[sizeof(keyalgo)-1] = '\0';
					
					std::string role;
					if ( key.has_role() )
						role.assign( ::ods::hsmkey::keyrole_Name(key.role()) );
					else
						role.assign("not set");
					
					
					std::string polic;
					if ( key.has_policy() )
						polic.assign( key.policy() );
					else
						polic.assign("not set");
					
					if (!bVerbose) {
						ods_printf(sockfd,
									   "%-40s %-10s %-7u %-12s %-26s\n",
									   loca.c_str(),ktype.c_str(),bits,repo.c_str(),incep);
					} else {
						ods_printf(sockfd,
									   "%-40s %-10s %-7u %-12s %-26s %-11s %-11s %-31s\n",
									   loca.c_str(),ktype.c_str(),bits,repo.c_str(),incep,
									   role.c_str(),keyalgo,polic.c_str());
					}
				}
			}
		}
	}
}
