#ifndef _XMLEXT_PB_XMLEXT_H_
#define _XMLEXT_PB_XMLEXT_H_

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

#endif /* _XMLEXT_PB_XMLEXT_ */
