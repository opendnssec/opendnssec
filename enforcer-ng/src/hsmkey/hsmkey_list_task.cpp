extern "C" {
#include "hsmkey/hsmkey_list_task.h"
#include "shared/file.h"
#include "shared/duration.h"
#include "shared/str.h"
}

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "hsmkey/hsmkey.pb.h"

#include "xmlext-pb/xmlext-rd.h"


#include <fcntl.h>

static const char *module_str = "hsmkey_list_task";

void 
perform_hsmkey_list(int sockfd, engineconfig_type *config, int bVerbose)
{
    char buf[ODS_SE_MAXLINE];
    const char *datastore = config->datastore;
    
	GOOGLE_PROTOBUF_VERIFY_VERSION;
    
    // Load the current list of pre-generated keys
    ::ods::hsmkey::HsmKeyDocument *hsmkeyDoc = 
        new ::ods::hsmkey::HsmKeyDocument;
    {
        std::string datapath(datastore);
        datapath += ".hsmkey.pb";
        int fd = open(datapath.c_str(),O_RDONLY);
        if (hsmkeyDoc->ParseFromFileDescriptor(fd)) {
            ods_log_debug("[%s] HSM key info list has been loaded",
                          module_str);
        } else {
            ods_log_error("[%s] HSM key info list could not be loaded "
                          "from \"%s\"",
                          module_str,datapath.c_str());
        }
        close(fd);
    }


    if (!bVerbose){
        (void)snprintf(buf, ODS_SE_MAXLINE,
                       "HSM keys:\n"
                       "Id:                                      "
                       "Key type:  "
                       "Bits:   "
                       "Repository:  "
                       "First use:                 "
                       "\n"
                       );
    } else {
        (void)snprintf(buf, ODS_SE_MAXLINE,
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
    ods_writen(sockfd, buf, strlen(buf));
    
    // Enumerate the keys found in the doc file on disk.
    for (int k=0; k<hsmkeyDoc->keys_size(); ++k) {
        const ::ods::hsmkey::HsmKey& key = hsmkeyDoc->keys(k);
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
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-40s %-10s %-7u %-12s %-26s\n",
                           loca.c_str(),ktype.c_str(),bits,repo.c_str(),incep);
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                           "%-40s %-10s %-7u %-12s %-26s %-11s %-11s %-31s\n",
                           loca.c_str(),ktype.c_str(),bits,repo.c_str(),incep,
                           role.c_str(),keyalgo,polic.c_str());
        }
        ods_writen(sockfd, buf, strlen(buf));
    }
}
