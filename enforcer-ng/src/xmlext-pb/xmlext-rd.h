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

#ifndef _XMLEXT_PB_XMLEXT_RD_H_
#define _XMLEXT_PB_XMLEXT_RD_H_

/**
 * Protocol Buffer Extension to read a Message from an XML file.
 *
 * This module can read an XML file and create a (nested) protocol buffer message from it.
 * The .proto file that was used to generate the C++ protocol buffer Message classes should
 * have protocol buffer options set that indicate where in the XML file data can be found.
 *
 */

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

bool read_pb_message_from_xml_file(google::protobuf::Message *document, const char *xmlfilepath);
bool read_pb_message_from_xml_memory(google::protobuf::Message *document, const char *buffer, int size);


/* helper function to recursively dump the descriptor passed in */
void recurse_dump_descriptor(const ::google::protobuf::Descriptor *descriptor);

#endif /* _XMLEXT_PB_XMLEXT_RD_H_ */
