/*
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

/**
 * Parsing zonelist files.
 *
 */

#include "adapter/adapter.h"
#include "parser/zonelistparser.h"
#include "file.h"
#include "log.h"
#include "status.h"
#include "signer/zonelist.h"
#include "signer/zone.h"

#include <libxml/xpath.h>
#include <libxml/xmlreader.h>
#include <stdlib.h>
#include <string.h>

#include "settings.h"

ods_status
parse_conf_zonelist(struct zonelist_struct* zlist, const char* zlfile)
{
    int count;
    int valid = 0;
    char* zone_name;
    int adapter_default = ADAPTER_FILE;
    const char* adapter_names[] = {"File", "DNS"};
    int adapter_values[] = {ADAPTER_FILE, ADAPTER_DNS};
    char* adapter_directions[] = { "Output", "Input" };
    zone_type* new_zone;
    char* content;
    adapter_type* adapter;
    int mode;

    settings_handle h;
    settings_access(&h, -1, zlfile);
    valid |= settings_getcompound(h, &count, "//Zonelist/Zone");
    for(int i = 0; i<count; i++) {
        valid |= settings_getstring(h, &zone_name, NULL, "//Zonelist/Zone[%d]/@name", i+1);
        new_zone = zone_create(zone_name, LDNS_RR_CLASS_IN);
        valid |= settings_getstring(h, (char**)&new_zone->policy_name, NULL, "//Zonelist/Zone[%d]/Policy", i+1);
        valid |= settings_getstring(h, (char**)&new_zone->signconf_filename, NULL, "//Zonelist/Zone[%d]/SignerConfiguration", i+1);
        for(int isinbound = 0; isinbound<=1; isinbound++) {
            char* adapter_direction = adapter_directions[isinbound];
            if(!settings_getstring(h, &content, NULL, "//Zonelist/Zone[%d]/Adapters/%s/File", i+1, adapter_direction)) {
                mode = ADAPTER_FILE;
            } else if(!settings_getstring(h, &content, NULL, "//Zonelist/Zone[%d]/Adapters/%s/Adapter", i+1, adapter_direction)) {
                valid |= settings_getenum2(h, &mode, &adapter_default, adapter_names, adapter_values, "//Zonelist/Zone[%d]/Adapters/%s/Adapter/@type", i+1, adapter_direction);
                valid |= settings_getstring(h, &content, NULL, "//Zonelist/Zone[%d]/Adapters/%s/Adapter", i+1, adapter_direction);
                adapter = adapter_create(content, mode, isinbound);
                switch(isinbound) {
                    case 0:
                        new_zone->adoutbound = adapter;
                        break;
                    case 1:
                        new_zone->adinbound = adapter;
                        break;
                }
            }
        }
        zonelist_add_zone(zlist, new_zone);
    }
    settings_access(&h, -1, NULL);
    return valid;
}
