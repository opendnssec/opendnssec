#ifndef _XMLEXT_PB_XMLEXT_WR_H_
#define _XMLEXT_PB_XMLEXT_WR_H_

/**
 * Protocol Buffer Extension to write a Message to an XML file.
 *
 * This module can write a (nested) protocol buffer message to an XML file.
 * The .proto file that was used to generate the C++ protocol buffer Message 
 * classes should have protocol buffer options set that indicate where in the 
 * XML file data should be written.
 *
 */

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

bool write_pb_message_to_xml_file(google::protobuf::Message *document, 
                                  const char *xmlfilepath);

#endif
