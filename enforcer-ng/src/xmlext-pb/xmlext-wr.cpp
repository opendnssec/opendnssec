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

using namespace ::google::protobuf;
using namespace std;


string
get_value(const Message *msg, const FieldDescriptor *field)
{
    const Reflection *reflection = msg->GetReflection();
    const xmloption xmlopt = field->options().GetExtension(xml);
    string a;
    
    switch (field->type()) {
        case FieldDescriptor::TYPE_FLOAT:
            // float, exactly four bytes on the wire.
            ods_strcat_printf(a, "%g",reflection->GetFloat(*msg, field));
            break;
        case FieldDescriptor::TYPE_MESSAGE:
            a = "";
            break;
        case FieldDescriptor::TYPE_DOUBLE: // double, exactly eight bytes on the wire.
            ods_strcat_printf(a, "%g", reflection->GetDouble(*msg, field));
            break;
        case FieldDescriptor::TYPE_INT32:    // int32, varint on the wire.  Negative numbers
        case FieldDescriptor::TYPE_SFIXED32: // int32, exactly four bytes on the wire
        case FieldDescriptor::TYPE_SINT32:   // int32, ZigZag-encoded varint on the wire
            if (xmlopt.type()==duration)
                ods_strcat_printf(a, "PT%dS", reflection->GetInt32(*msg, field));
            else
                ods_strcat_printf(a, "%d", reflection->GetInt32(*msg, field));
            break;
        case FieldDescriptor::TYPE_INT64:    // int64, varint on the wire.  Negative numbers
        case FieldDescriptor::TYPE_SFIXED64: // int64, exactly eight bytes on the wire
        case FieldDescriptor::TYPE_SINT64:   // int64, ZigZag-encoded varint on the wire
            if (xmlopt.type()==duration)
                ods_strcat_printf(a, "PT%lldS", reflection->GetInt64(*msg, field));
            else
                ods_strcat_printf(a, "%lld", reflection->GetInt64(*msg, field));
            break;
        case FieldDescriptor::TYPE_UINT32: // uint32, varint on the wire
        case FieldDescriptor::TYPE_FIXED32: // uint32, exactly four bytes on the wire.
            if (xmlopt.type()==duration)
                ods_strcat_printf(a, "PT%uS", reflection->GetUInt32(*msg, field));
            else
                ods_strcat_printf(a, "%u", reflection->GetUInt32(*msg, field));
            break;
        case FieldDescriptor::TYPE_UINT64: // uint64, varint on the wire.
        case FieldDescriptor::TYPE_FIXED64: // uint64, exactly eight bytes on the wire.
            if (xmlopt.type()==duration)
                ods_strcat_printf(a, "PT%lluS", reflection->GetUInt64(*msg, field));
            else
                ods_strcat_printf(a, "%llu", reflection->GetUInt64(*msg, field));
            break;
        case FieldDescriptor::TYPE_BOOL: // bool, varint on the wire.
            ods_strcat_printf(a, "%d", (int)reflection->GetBool(*msg, field)?1:0);
            break;
        case FieldDescriptor::TYPE_STRING: // UTF-8 text.
            ods_strcat_printf(a, "%s", reflection->GetString(*msg, field).c_str());
            break;
        //~ case FieldDescriptor::TYPE_MESSAGE: // Length-delimited message.
            //~ ods_strcat_printf(a, "%s", "ERROR: Message doesn't fit in xml attribute");
            //~ ods_log_error("[%s] Message doesn't fit in xml attribute", module_str);
            //~ break;
        case FieldDescriptor::TYPE_BYTES: // Arbitrary byte array.
            ods_strcat_printf(a, "%s", "ERROR: Bytes don't fit in xml attribute");
            ods_log_error("[%s] Bytes don't fit in xml attribute", module_str);
            break;
        case FieldDescriptor::TYPE_ENUM: // Enum, varint on the wire
            ods_strcat_printf(a, "%s", reflection->GetEnum(*msg,field)->name().c_str());
            break;
        default:
            ods_strcat_printf(a, "%s", "ERROR: UNKNOWN FIELD TYPE");
            ods_log_error("[%s] Unknow field type", module_str);
    }
    return a;
}

bool
isattr(const FieldDescriptor *field) {
    const xmloption xmlopt = field->options().GetExtension(xml);
    return xmlopt.path().find('@') != string::npos;
}

void
getSubForElem( const FieldDescriptor *field,
    std::vector<const FieldDescriptor*> *input,
    std::vector<const FieldDescriptor*> *output
)
{
    std::vector<const FieldDescriptor*> keep;
    vector<const FieldDescriptor*>::iterator fld_iter;
    string elempath = field->options().GetExtension(xml).path();
    //~ printf("\tFIELD: %s\n", elempath.c_str());
    
    for (fld_iter=input->begin(); fld_iter != input->end(); ++fld_iter) {
        string attrpath = (*fld_iter)->options().GetExtension(xml).path();
        if (attrpath.find(elempath, 0) == 0) {
            //~ printf("\tATTRCAN: %s\n", attrpath.c_str());
            output->push_back(*fld_iter);
        } else {
            keep.push_back(*fld_iter);
        }
    }
    input->clear();
    for (fld_iter=keep.begin(); fld_iter != keep.end(); ++fld_iter) {
        input->push_back(*fld_iter);
    }
}

string
strip_path(string in)
{
    size_t pos = in.rfind('/');
    if (pos == string::npos) return in;
    return in.substr(pos+1, in.length());
}

string
scrub_attr(string in)
{
    size_t pos = in.rfind('@');
    if (pos == string::npos) return in;
    return in.substr(pos+1, in.length());
}

void
open_element(FILE *fw, const FieldDescriptor *field,
    std::vector<const FieldDescriptor*> elements,
    std::vector<const FieldDescriptor*> attributes,
    const Message *msg
)
{
    /* get everything after last '/' */
    string elempath = field->options().GetExtension(xml).path();
    string elemname = strip_path(elempath);

    fprintf(fw, "<%s", elemname.c_str());
    //~ printf(" ((attrlen %d)) ", attributes.size());
    vector<const FieldDescriptor*>::const_iterator fld_iter;
    for (fld_iter=attributes.begin(); fld_iter != attributes.end(); ++fld_iter) {
        
        string attrpath = (*fld_iter)->options().GetExtension(xml).path();
        string attrname = scrub_attr(attrpath);
        fprintf(fw, " %s = \"%s\"", attrname.c_str(), get_value(msg, *fld_iter).c_str());
    }
    
    string val =  get_value(msg, field);
    if (!val.empty())
        fprintf(fw, ">%s",  val.c_str());
    else if (elements.empty())
        fprintf(fw, "/>\n");
    else
        fprintf(fw, ">\n");
}

void
close_element(FILE *fw, const FieldDescriptor *field,
    std::vector<const FieldDescriptor*> elements,
    std::vector<const FieldDescriptor*> attributes,
    const Message *msg
)
{
    string elempath = field->options().GetExtension(xml).path();
    string elemname = strip_path(elempath);
    string val =  get_value(msg, field);
    if (elements.empty() && val.empty()) return;
    fprintf(fw, "</%s>\n",  elemname.c_str());
}

void
write_nonterminals(const Message *msg, 
    const vector<const FieldDescriptor*> &nonterminal_elements)
{
    if (nonterminal_elements.empty()) return;
    printf("PROC NON TERMINALs\n");
    
}


void
recurse_write(FILE *fw, const FieldDescriptor *parentfield,
    const vector<const FieldDescriptor*> &fields,
    const vector<const FieldDescriptor*> &attrs,
    const Message *msg,
    int lvl)
{
    const Reflection *reflection = msg->GetReflection();
    vector<const FieldDescriptor*>::const_iterator fld_iter;
    
    if (parentfield) {
        const xmloption xmlopt = parentfield->options().GetExtension(xml); //WHERE is xml defined? what is it?
        printf("%d PARENT: \"%s\" -> (\"%s\")\n", lvl, parentfield->name().c_str(), xmlopt.path().c_str());
    } else {
        printf("ROOT\n");
    }
    
    //collect all subfields
    std::vector<const FieldDescriptor*> attributes;
    std::vector<const FieldDescriptor*> elements;
    std::vector<const FieldDescriptor*> nonterminal_elements;
    
    for (fld_iter=fields.begin(); fld_iter != fields.end(); ++fld_iter) {
        if (!(*fld_iter)->options().HasExtension(xml)) {
            printf("%d ignoring field without xml path: %s\n", lvl, (*fld_iter)->name().c_str());
            continue;
        }
        string xmlpath = (*fld_iter)->options().GetExtension(xml).path();
        if (isattr(*fld_iter)) {
            printf("%d attribute found: %s (\"%s\")\n", lvl, (*fld_iter)->name().c_str(), xmlpath.c_str());
            attributes.push_back(*fld_iter);
        } else {
            printf("%d element found: %s (\"%s\")\n", lvl, (*fld_iter)->name().c_str(), xmlpath.c_str());
            if (xmlpath.find('/') == string::npos) 
                elements.push_back(*fld_iter);
            else
                nonterminal_elements.push_back(*fld_iter);
        }
    }
    for (fld_iter=attrs.begin(); fld_iter != attrs.end(); ++fld_iter) {
        attributes.push_back(*fld_iter);
    }
    
    if (parentfield) {
        std::vector<const FieldDescriptor*> parent_attr;
        getSubForElem(parentfield, &attributes, &parent_attr);
        open_element(fw, parentfield, elements, parent_attr, msg);
    }
    
    for (fld_iter=elements.begin(); fld_iter != elements.end(); ++fld_iter) {
        string xmlpath = (*fld_iter)->options().GetExtension(xml).path();
        
        printf("%d processing element: %s (\"%s\")\n", lvl, (*fld_iter)->name().c_str(), xmlpath.c_str());
        
        //find attributes applicable to this elem
        std::vector<const FieldDescriptor*> elem_attr;
        //~ printf("\n\t\t%d %d\n", attributes.size(), elem_attr.size());
        getSubForElem(*fld_iter, &attributes, &elem_attr);
        //~ printf("\t\t%d %d\n\n", attributes.size(), elem_attr.size());
        
        //TODO posibility: This field has an (empty) non-terminal in path
        
        std::vector<const FieldDescriptor*> subfields;
        if ((*fld_iter)->type() == FieldDescriptor::TYPE_MESSAGE) {
            
            if ((*fld_iter)->is_repeated()) {
                for (int f = 0; f < reflection->FieldSize(*msg, *fld_iter); f++) {
                    const Message *submsg = &reflection->GetRepeatedMessage(*msg, *fld_iter, f);
                    submsg->GetReflection()->ListFields(*submsg, &subfields);
                    getSubForElem(*fld_iter, &nonterminal_elements, &subfields);
                    recurse_write(fw, *fld_iter, subfields, elem_attr, submsg, lvl+1);
                }
            } else {
                const Message *submsg = &reflection->GetMessage(*msg, *fld_iter);
                submsg->GetReflection()->ListFields(*submsg, &subfields);
                getSubForElem(*fld_iter, &nonterminal_elements, &subfields);
                recurse_write(fw, *fld_iter, subfields, elem_attr, submsg, lvl+1);
            }
        } else {
            //We have a terminal (element w/o children)
            if ((*fld_iter)->is_repeated()) {
                printf("DUBUG skipping repeated field");
                continue;
            } else {
                open_element (fw, *fld_iter, subfields, elem_attr, msg);
                close_element(fw, *fld_iter, subfields, elem_attr, msg);
            }
        }
    }
    
    write_nonterminals(msg, nonterminal_elements);
    
    if (parentfield) {
        close_element(fw, parentfield, elements, attributes, msg);
    }
}

void 
write_msg(FILE *fw, const ::google::protobuf::Message *msg)
{
    std::vector<const ::google::protobuf::FieldDescriptor*> fields;
    msg->GetReflection()->ListFields(*msg, &fields);
    std::vector<const FieldDescriptor*> attributes;
    recurse_write(fw, NULL, fields, attributes, msg, 0);
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
{
    if (fd<0) {
        ods_log_error("[%s] write_pb_message_to_xml_fd: invalid fd: %d",
                      module_str,fd);
        return false;
    }
    int dfd = dup(fd);
    if (dfd<0) {
        ods_log_error("[%s] write_pb_message_to_xml_fd: can't dup fd: %s",
                      module_str,strerror(errno));
        return false;
    }
    FILE *fw = fdopen(dfd,"w");
    if (!fw) return false;
    write_msg(fw,document);
    ods_fclose(fw);
    return true;
}
