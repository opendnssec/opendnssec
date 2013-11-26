/*
 * $Id$
 *
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
#include <iostream>
#include <errno.h>
#include <set>

#include "config.h"
#include "xmlext-wr.h"
#include "xmlext.pb.h"

#include "shared/log.h"
#include "shared/file.h"

static const char *module_str = "xmlext_wr";

void
ods_strcat_printf(std::string &str, const char *format, ...)
{
    char buf[ODS_SE_MAXLINE] = "";
    int nbuf;
    va_list args;
    va_start(args, format);
    nbuf = vsnprintf(buf,ODS_SE_MAXLINE,format,args);
    if (nbuf<0)
        ods_log_error("[%s] ods_strcat_printf: encoding error" ,module_str);
    else
        if (nbuf>=ODS_SE_MAXLINE)
            ods_log_error("[%s] ods_strcat_printf: printed string too long",
                          module_str);
    str += buf;
    va_end(args);
}

void
generate_attributes(std::string &a, const google::protobuf::Message *msg)
{
    a.clear();

    const ::google::protobuf::Descriptor *descriptor = msg->GetDescriptor();
    const ::google::protobuf::Reflection *reflection = msg->GetReflection();
    
    std::vector<const ::google::protobuf::FieldDescriptor*> fields;
    std::vector<const ::google::protobuf::FieldDescriptor*>::iterator it;
    reflection->ListFields(*msg, &fields);
    
    for (it=fields.begin(); it != fields.end(); ++it) {
        const ::google::protobuf::FieldDescriptor *field = *it;
        if (!field) continue;
        const xmloption xmlopt = field->options().GetExtension(xml);
        if (xmlopt.path().find('@') == 0) {
            int snprintf_size = 0;
            const char *fmt;
            
            switch (field->type()) {
                case ::google::protobuf::FieldDescriptor::TYPE_FLOAT:
                    // float, exactly four bytes on the wire.
                    ods_strcat_printf(a, " %s=\"%g\"",
                                      xmlopt.path().substr(1).c_str(),
                                      reflection->GetFloat(*msg,field));
                    break;
                case ::google::protobuf::FieldDescriptor::TYPE_DOUBLE:
                    // double, exactly eight bytes on the wire.
                    ods_strcat_printf(a, " %s=\"%g\"",
                                      xmlopt.path().substr(1).c_str(),
                                      reflection->GetDouble(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_INT32:
                    // int32, varint on the wire.  Negative numbers
                case ::google::protobuf::FieldDescriptor::TYPE_SFIXED32:
                    // int32, exactly four bytes on the wire
                case ::google::protobuf::FieldDescriptor::TYPE_SINT32:
                    // int32, ZigZag-encoded varint on the wire
                    if (xmlopt.type()==duration)
                        fmt = " %s=\"PT%dS\"";
                    else
                        fmt = " %s=\"%d\"";
                    ods_strcat_printf(a, fmt,
                                      xmlopt.path().substr(1).c_str(),
                                      reflection->GetInt32(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_INT64:
                    // int64, varint on the wire.  Negative numbers
                case ::google::protobuf::FieldDescriptor::TYPE_SFIXED64:
                    // int64, exactly eight bytes on the wire
                case ::google::protobuf::FieldDescriptor::TYPE_SINT64:
                    // int64, ZigZag-encoded varint on the wire
                    if (xmlopt.type()==duration)
                        fmt = " %s=\"PT%lldS\"";
                    else
                        fmt = " %s=\"%lld\"";
                    ods_strcat_printf(a, fmt,
                                      xmlopt.path().substr(1).c_str(),
                                      reflection->GetInt64(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_UINT32:
                    // uint32, varint on the wire
                case ::google::protobuf::FieldDescriptor::TYPE_FIXED32:
                    // uint32, exactly four bytes on the wire.
                    if (xmlopt.type()==duration)
                        fmt = " %s=\"PT%uS\"";
                    else
                        fmt = " %s=\"%u\"";
                    ods_strcat_printf(a, fmt,
                                      xmlopt.path().substr(1).c_str(),
                                      reflection->GetUInt32(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_UINT64:
                    // uint64, varint on the wire.
                case ::google::protobuf::FieldDescriptor::TYPE_FIXED64:
                    // uint64, exactly eight bytes on the wire.
                    if (xmlopt.type()==duration)
                        fmt = " %s=\"PT%lluS\"";
                    else
                        fmt = " %s=\"%llu\"";
                    ods_strcat_printf(a, fmt,
                                      xmlopt.path().substr(1).c_str(),
                                      reflection->GetUInt64(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_BOOL:
                    // bool, varint on the wire.
                    ods_strcat_printf(a, " %s=\"%d\"",
                                      xmlopt.path().substr(1).c_str(),
                                      (int)reflection->GetBool(*msg,field)?1:0);
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_STRING:
                    // UTF-8 text.
                    ods_strcat_printf(a, " %s=\"%s\"",
                                      xmlopt.path().substr(1).c_str(),
                                      reflection->GetString(*msg,field).c_str());
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_MESSAGE:
                    // Length-delimited message.
                    ods_strcat_printf(a, " %s=\"%s\"",
                                  xmlopt.path().substr(1).c_str(),
                                  "ERROR: Message doesn't fit in xml attribute");
                    ods_log_error("[%s] Message doesn't fit in xml attribute",
                                  module_str);
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_BYTES:
                    // Arbitrary byte array.
                    ods_strcat_printf(a, " %s=\"%s\"",
                                      xmlopt.path().substr(1).c_str(),
                                      "ERROR: Bytes don't fit in xml attribute");
                    ods_log_error("[%s] Bytes don't fit in xml attribute",
                                  module_str);
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_ENUM:
                    // Enum, varint on the wire
                    ods_strcat_printf(a, " %s=\"%s\"",
                              xmlopt.path().substr(1).c_str(),
                              reflection->GetEnum(*msg,field)->name().c_str());
                    break;
                    
                default:
                    ods_strcat_printf(a, " %s=\"%s\"",
                                      xmlopt.path().substr(1).c_str(),
                                      "ERROR: UNKNOWN FIELD TYPE");
                    ods_log_error("[%s] Unknow field type",
                                  module_str);
            }
        }
    }
}

void write_msg(FILE *fw,const ::google::protobuf::Message *msg);

void
recurse_write(
    FILE *fw,
    const ::google::protobuf::Message *msg,
    const std::vector<const ::google::protobuf::FieldDescriptor*> &fields,
    int ccskip)
{
	ods_printf(9,"44--------1111111111111111111111\n");
    const ::google::protobuf::Reflection *reflection = msg->GetReflection();
    static int level = -1;
    ++level;

    std::set<const ::google::protobuf::FieldDescriptor*> processed_fields;
    std::vector<const ::google::protobuf::FieldDescriptor*>::const_iterator it;
    for (it=fields.begin(); it != fields.end(); ++it) {
    	ods_printf(9,"44--------4444444444444444444444\n");
        const ::google::protobuf::FieldDescriptor *field = *it;
        ods_printf(9,"55--------11\n");
        if (!field) continue;
        ods_printf(9,"55--------22\n");
		//printf("FIELD: %s\n",field->name().c_str());
			   

        // skip fields of the message that already have been processed
        if (processed_fields.find(field) != processed_fields.end()) continue;
        ods_printf(9,"55--------33\n");
        // skip fields that have no xml option set
        if (!field->options().HasExtension(xml)) continue;
        ods_printf(9,"55--------44\n");
        std::string indent(level,'\t');
        ods_printf(9,"55--------55\n");
        const xmloption xmlopt = field->options().GetExtension(xml);
        ods_printf(9,"55--------66\n");
		//printf("	XPATH: %s\n",xmlopt.path().c_str());
        
        // skip fields that represent xml attributes when processing the 
        // field list to expand fields into xml elements.
        if (xmlopt.path().find('@') == 0) continue;
        ods_printf(9,"55--------77\n");
        /*
         * if there is a / inside the xml attribute, then 
         * it may indicate a nested element something like 
         * e.g. Validity/Denial. In this case collect all the other
         * fields in the current message that also start with e.g. Validity/ 
         * and mark them as processed.
         * Put the fields in a new list of fields and pass that 
         * recursively into recurse_write.
         */
        int sspos = xmlopt.path().find('/',ccskip);
        ods_printf(9,"55--------88\n");
        if (sspos != std::string::npos) {
        	ods_printf(9,"55--------99\n");
            // get single component of nested element name
            std::string elem = xmlopt.path().substr(ccskip,sspos-ccskip);
            
            fprintf(fw,"%s<%s>\n",indent.c_str(),elem.c_str());

            std::vector<const ::google::protobuf::FieldDescriptor*> subfields;
            std::vector<const ::google::protobuf::FieldDescriptor*>::const_iterator it;
            for (it=fields.begin(); it != fields.end(); ++it) {
                
                const xmloption subxmlopt = (*it)->options().GetExtension(xml);
                
                if (subxmlopt.path().find(elem,ccskip) == 0) {
                
                    // process these fields in a nested call to recurse_write
                    subfields.push_back(*it);
                    // don't process these fields in the current processing loop.
                    processed_fields.insert(*it);
                }
            }
            ods_printf(9,"44--------5555555555555555555555\n");
            recurse_write(fw,msg,subfields,sspos+1);
            ods_printf(9,"44--------666666666666666666666666\n");

            fprintf(fw,"%s</%s>\n",indent.c_str(),elem.c_str());
            continue;
        }
        ods_printf(9,"55--------1010\n");
        std::string elem = xmlopt.path().substr(0,ccskip);
        ods_printf(9,"55--------1111\n");
        std::string attributes;
        ods_printf(9,"55--------1212\n");
        if (field->is_repeated()) {
        	ods_printf(9,"44--------22222222222222222222222222222\n");
            // REPEATED
            int field_size = reflection->FieldSize(*msg,field);
            for (int f=0; f<field_size; ++f) {

                switch (field->type()) {
                    case ::google::protobuf::FieldDescriptor::TYPE_BOOL:
                        break;
                    case ::google::protobuf::FieldDescriptor::TYPE_MESSAGE:
                        generate_attributes(attributes,
                                 &reflection->GetRepeatedMessage(*msg,field,f));
                        fprintf(fw,"%s<%s%s>",indent.c_str(),elem.c_str(),
                               attributes.c_str());
                        break;
                    default:
                        fprintf(fw,"%s<%s>",indent.c_str(),elem.c_str());
                }
                
                const char *fmt;
                switch (field->type()) {
                    case ::google::protobuf::FieldDescriptor::TYPE_FLOAT:
                        // float, exactly four bytes on the wire.
                        fprintf(fw,"%g",reflection->GetRepeatedFloat(*msg,field,f));
                        break;
                    case ::google::protobuf::FieldDescriptor::TYPE_DOUBLE:
                        // double, exactly eight bytes on the wire.
                        fprintf(fw,"%g",reflection->GetRepeatedDouble(
                                                                  *msg,field,f));
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_INT32:
                        // int32, varint on the wire.  Negative numbers
                    case ::google::protobuf::FieldDescriptor::TYPE_SFIXED32:
                        // int32, exactly four bytes on the wire
                    case ::google::protobuf::FieldDescriptor::TYPE_SINT32:
                        // int32, ZigZag-encoded varint on the wire
                        if (xmlopt.type()==duration)
                            fmt = "PT%dS";
                        else
                            fmt = "%d";
                        fprintf(fw,fmt,reflection->GetRepeatedInt32(
                                                                 *msg,field,f));
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_INT64:
                        // int64, varint on the wire.  Negative numbers
                    case ::google::protobuf::FieldDescriptor::TYPE_SFIXED64:
                        // int64, exactly eight bytes on the wire
                    case ::google::protobuf::FieldDescriptor::TYPE_SINT64:
                        // int64, ZigZag-encoded varint on the wire
                        if (xmlopt.type()==duration)
                            fmt = "PT%lldS";
                        else
                            fmt = "%lld";
                        fprintf(fw,fmt,reflection->GetRepeatedInt64(*msg,field,f));
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_UINT32:
                        // uint32, varint on the wire
                    case ::google::protobuf::FieldDescriptor::TYPE_FIXED32:
                        // uint32, exactly four bytes on the wire.
                        if (xmlopt.type()==duration)
                            fmt = "PT%uS";
                        else
                            fmt = "%u";
                        fprintf(fw,fmt,reflection->GetRepeatedUInt32(*msg,field,f));
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_UINT64:
                        // uint64, varint on the wire.
                    case ::google::protobuf::FieldDescriptor::TYPE_FIXED64:
                        // uint64, exactly eight bytes on the wire.
                        if (xmlopt.type()==duration)
                            fmt = "PT%lluS";
                        else
                            fmt = "%llu";
                        fprintf(fw,fmt,reflection->GetRepeatedUInt64(*msg,field,f));
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_BOOL:
                        // bool, varint on the wire.
                        if (reflection->GetRepeatedBool(*msg,field,f)) 
                            fprintf(fw,"%s<%s/>\n",indent.c_str(),elem.c_str());
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_STRING:
                        // UTF-8 text.
                        fprintf(fw,"%s",reflection->GetRepeatedString(
                                                         *msg,field,f).c_str());
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_MESSAGE:
                        // Length-delimited message.
                        fprintf(fw,"\n");
                        ods_printf(9,"33--------111111111111111111111111\n");
                        write_msg(fw,&reflection->GetRepeatedMessage(*msg,field,f));
                        ods_printf(9,"33--------222222222222222222222222\n");
                        fprintf(fw,"%s",indent.c_str());
                        ods_printf(9,"33--------333333333333333333333333\n");
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_BYTES:
                        // Arbitrary byte array.
                        break;
                        
                    case ::google::protobuf::FieldDescriptor::TYPE_ENUM:
                        // Enum, varint on the wire
                        fprintf(fw,"%s",reflection->GetRepeatedEnum(
                                                *msg,field,f)->name().c_str());
                        break;
                        
                    default:
                        fprintf(fw,"ERROR: UNKNOWN FIELD TYPE");
                }
                if (field->type() 
                    != ::google::protobuf::FieldDescriptor::TYPE_BOOL)
                {
                    fprintf(fw,"</%s>\n",elem.c_str());
                }
                
            }
        } else {
        	ods_printf(9,"44--------333333333333333333333333\n");
            // REQUIRED or OPTIONAL
            switch (field->type()) {
                case ::google::protobuf::FieldDescriptor::TYPE_BOOL:
                    break;
                case ::google::protobuf::FieldDescriptor::TYPE_MESSAGE:
                    generate_attributes(attributes,
                                        &reflection->GetMessage(*msg,field));
                    fprintf(fw,"%s<%s%s>",indent.c_str(),elem.c_str(),
                           attributes.c_str());
                    break;
                default:
					if (elem == "text()")
						fprintf(fw,"%s",indent.c_str());
					else
						fprintf(fw,"%s<%s>",indent.c_str(),elem.c_str());
            }
            const char *fmt;
            switch (field->type()) {
                case ::google::protobuf::FieldDescriptor::TYPE_FLOAT:
                    // float, exactly four bytes on the wire.
                    fprintf(fw,"%g",reflection->GetFloat(*msg,field));
                    break;
                case ::google::protobuf::FieldDescriptor::TYPE_DOUBLE:
                    // double, exactly eight bytes on the wire.
                    fprintf(fw,"%g",reflection->GetDouble(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_INT32:
                    // int32, varint on the wire.  Negative numbers
                case ::google::protobuf::FieldDescriptor::TYPE_SFIXED32:
                    // int32, exactly four bytes on the wire
                case ::google::protobuf::FieldDescriptor::TYPE_SINT32:
                    // int32, ZigZag-encoded varint on the wire
                    if (xmlopt.type()==duration)
                        fmt = "PT%dS";
                    else
                        fmt = "%d";
                    fprintf(fw,fmt,reflection->GetInt32(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_INT64:
                    // int64, varint on the wire.  Negative numbers
                case ::google::protobuf::FieldDescriptor::TYPE_SFIXED64:
                    // int64, exactly eight bytes on the wire
                case ::google::protobuf::FieldDescriptor::TYPE_SINT64:
                    // int64, ZigZag-encoded varint on the wire
                    if (xmlopt.type()==duration)
                        fmt = "PT%lldS";
                    else
                        fmt = "%lld";
                   fprintf(fw,fmt,reflection->GetInt64(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_UINT32:
                    // uint32, varint on the wire
                case ::google::protobuf::FieldDescriptor::TYPE_FIXED32:
                    // uint32, exactly four bytes on the wire.
                    fprintf(fw,"%u",reflection->GetUInt32(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_UINT64:
                    // uint64, varint on the wire.
                case ::google::protobuf::FieldDescriptor::TYPE_FIXED64:
                    // uint64, exactly eight bytes on the wire.
                    if (xmlopt.type()==duration)
                        fmt = "PT%lluS";
                    else
                        fmt = "%llu";
                    fprintf(fw,fmt,reflection->GetUInt64(*msg,field));
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_BOOL:
                    // bool, varint on the wire.
                    if (reflection->GetBool(*msg,field))
                        fprintf(fw,"%s<%s/>\n",indent.c_str(),elem.c_str());
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_STRING:
                    // UTF-8 text.
                    fprintf(fw,"%s",
                           reflection->GetString(*msg,field).c_str());
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_MESSAGE:
                    // Length-delimited message.
                    fprintf(fw,"\n");
                    ods_printf(9,"33--------4444444444444444444444444\n");
                    write_msg(fw,&reflection->GetMessage(*msg,field));
                    ods_printf(9,"33--------5555555555555555555555555\n");
                    fprintf(fw,"%s",indent.c_str());
                    ods_printf(9,"33--------66666666666666666666666666\n");
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_BYTES:
                    // Arbitrary byte array.
                    break;
                    
                case ::google::protobuf::FieldDescriptor::TYPE_ENUM:
                    // Enum, varint on the wire
                    fprintf(fw,"%s",
                           reflection->GetEnum(*msg,field)->name().c_str());
                    break;
                    
                default:
                	ods_printf(9,"44--------77777777777777777777\n");
                    fprintf(fw,"ERROR: UNKNOWN FIELD TYPE");
            }
            if (field->type() 
                != ::google::protobuf::FieldDescriptor::TYPE_BOOL)
            {
				if (elem == "text()")
					fprintf(fw,"\n");
				else
					fprintf(fw,"</%s>\n",elem.c_str());
            }
        }
        ods_printf(9,"44--------888888888888888888888888888\n");
    }
    ods_printf(9,"44--------99999999999999999999999999\n");
    --level;
}

void 
write_msg(FILE *fw, const ::google::protobuf::Message *msg)
{
	ods_printf(9,"22--------111111111111111111111111\n");
    std::vector<const ::google::protobuf::FieldDescriptor*> fields;
    ods_printf(9,"22--------222222222222222222222\n");
    msg->GetReflection()->ListFields(*msg, &fields);
    ods_printf(9,"22--------33333333333333333333333\n");
    recurse_write(fw,msg,fields,0);
    ods_printf(9,"22--------444444444444444444444444\n");
}

bool write_pb_message_to_xml_file(const google::protobuf::Message *document, 
                                  const char *xmlfilepath)
{
    FILE *fw = ods_fopen(xmlfilepath,NULL,"w");
    if (!fw) return false;
    write_msg(fw,document);
    ods_fclose(fw);
    return true;
}

bool write_pb_message_to_xml_fd(const google::protobuf::Message *document, 
								int fd)
{	ods_printf(fd,"11--------1111111111111\n");
    if (fd<0) {
    	ods_printf(fd,"11-------2222222222222\n");
        ods_log_error("[%s] write_pb_message_to_xml_fd: invalid fd: %d",
                      module_str,fd);
        ods_printf(fd,"11--------333333333333333\n");
        return false;
        ods_printf(fd,"11--------444444444444444\n");
    }
    ods_printf(fd,"11--------5555555555555\n");
    int dfd = dup(fd);
    if (dfd<0) {
    	ods_printf(fd,"11--------6666666666666\n");
        ods_log_error("[%s] write_pb_message_to_xml_fd: can't dup fd: %s",
                      module_str,strerror(errno));
        ods_printf(fd,"11--------777777777777777\n");
        return false;
        ods_printf(fd,"11--------888888888888888\n");
    }
    ods_printf(fd,"11-------99999999999999\n");
    FILE *fw = fdopen(dfd,"w");
    ods_printf(fd,"11--------101010101010101\n");
    if (!fw) return false;
    ods_printf(fd,"11--------11-11-11-11-11-11-1\n");
    ods_printf(fd,"%d\n",fd);
    write_msg(fw,document);
    ods_printf(fd,"11--------22-22-22-22-22-22-22-22-2\n");
    ods_fclose(fw);
    return true;
}
