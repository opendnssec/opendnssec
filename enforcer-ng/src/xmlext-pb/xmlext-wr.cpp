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
#include <sstream>

#include "config.h"
#include "xmlext-wr.h"
#include "xmlext.pb.h"

#include "shared/log.h"
#include "shared/file.h"

using namespace ::google::protobuf;
using namespace std;

static const char *module_str = "xmlext_wr";

template <typename T> string tostr(const T& t) { 
	ostringstream os; os<<t; return os.str();
}

string
get_value(const Message *msg, const FieldDescriptor *field)
{
    const Reflection *reflection = msg->GetReflection();
    const xmloption xmlopt = field->options().GetExtension(xml);
    char tmp[ODS_SE_MAXLINE];
    
    switch (field->type()) {
        case FieldDescriptor::TYPE_FLOAT:    // float, exactly four bytes on the wire.
            return tostr(reflection->GetFloat(*msg, field));
        case FieldDescriptor::TYPE_MESSAGE:
            return "";
        case FieldDescriptor::TYPE_DOUBLE:   // double, exactly eight bytes on the wire.
            return tostr(reflection->GetDouble(*msg, field));
        case FieldDescriptor::TYPE_INT32:    // int32, varint on the wire.  Negative numbers
        case FieldDescriptor::TYPE_SFIXED32: // int32, exactly four bytes on the wire
        case FieldDescriptor::TYPE_SINT32:   // int32, ZigZag-encoded varint on the wire
            if (xmlopt.type() != duration)
                return tostr(reflection->GetInt32(*msg, field));
            snprintf(tmp, ODS_SE_MAXLINE, "PT%dS", reflection->GetInt32(*msg, field));
            return tostr(tmp);
        case FieldDescriptor::TYPE_INT64:    // int64, varint on the wire.  Negative numbers
        case FieldDescriptor::TYPE_SFIXED64: // int64, exactly eight bytes on the wire
        case FieldDescriptor::TYPE_SINT64:   // int64, ZigZag-encoded varint on the wire
            if (xmlopt.type() != duration)
                return tostr(reflection->GetInt64(*msg, field));
            snprintf(tmp, ODS_SE_MAXLINE, "PT%lldS", reflection->GetInt64(*msg, field));
            return tostr(tmp);
        case FieldDescriptor::TYPE_UINT32:   // uint32, varint on the wire
        case FieldDescriptor::TYPE_FIXED32:  // uint32, exactly four bytes on the wire.
            if (xmlopt.type() != duration)
                return tostr(reflection->GetUInt32(*msg, field));
            snprintf(tmp, ODS_SE_MAXLINE, "PT%uS", reflection->GetUInt32(*msg, field));
            return tostr(tmp);
        case FieldDescriptor::TYPE_UINT64:   // uint64, varint on the wire.
        case FieldDescriptor::TYPE_FIXED64:  // uint64, exactly eight bytes on the wire.
            if (xmlopt.type() != duration)
                return tostr(reflection->GetUInt64(*msg, field));
            snprintf(tmp, ODS_SE_MAXLINE, "PT%lluS", reflection->GetUInt64(*msg, field));
            return tostr(tmp);
        case FieldDescriptor::TYPE_BOOL:     // bool, varint on the wire.
            return tostr((int)reflection->GetBool(*msg, field)?1:0);
        case FieldDescriptor::TYPE_STRING:   // UTF-8 text.
            return reflection->GetString(*msg, field);
        case FieldDescriptor::TYPE_BYTES:    // Arbitrary byte array.
            ods_log_error("[%s] Bytes don't fit in xml attribute", module_str);
            return tostr("ERROR: Bytes don't fit in xml attribute");
        case FieldDescriptor::TYPE_ENUM:     // Enum, varint on the wire
            return reflection->GetEnum(*msg,field)->name();
        default:
            ods_log_error("[%s] Unknow field type", module_str);
            return tostr("ERROR: UNKNOWN FIELD TYPE");
    }
}

bool
isattr(const FieldDescriptor *field) {
    const xmloption xmlopt = field->options().GetExtension(xml);
    return xmlopt.path().find('@') != string::npos;
}

void
getSubForElemStr( string elempath,
    std::vector<const FieldDescriptor*> *input,
    std::vector<const FieldDescriptor*> *output
)
{
    std::vector<const FieldDescriptor*> keep;
    vector<const FieldDescriptor*>::iterator fld_iter;
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

void
getSubForElem( const FieldDescriptor *field,
    std::vector<const FieldDescriptor*> *input,
    std::vector<const FieldDescriptor*> *output
)
{
    string elempath = field->options().GetExtension(xml).path();
    getSubForElemStr(elempath, input, output);
}

string
strip_path(string in)
{
    size_t pos = in.rfind('/');
    if (pos == string::npos) return in;
    return in.substr(pos+1, in.length());
}

string
strip_pathlabel(string in)
{
    size_t pos = in.find('/');
    if (pos == string::npos) return in;
    return in.substr(pos+1, in.length());
}

string
get_pathroot(string in)
{
    size_t pos = in.find('/');
    if (pos == string::npos) return in;
    return in.substr(0, pos);
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
    const Message *msg, int lvl
)
{
    /* get everything after last '/' */
    string elempath = field->options().GetExtension(xml).path();
    string elemname = strip_path(elempath);

    for (int i = 0; i<lvl; i++) fprintf(fw, "  ");
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
    const Message *msg, int lvl
)
{
    string elempath = field->options().GetExtension(xml).path();
    string elemname = strip_path(elempath);
    string val =  get_value(msg, field);
    if (elements.empty() && val.empty()) return;
    if (!elements.empty())
        for (int i = 0; i<lvl; i++) fprintf(fw, "  ");
    fprintf(fw, "</%s>\n",  elemname.c_str());
}

void
recurse_write(FILE *, const FieldDescriptor *,
    const vector<const FieldDescriptor*> &,
    const vector<const FieldDescriptor*> &,
    const Message *, int, string);
    
void
write_nonterminals(FILE *fw, const Message *msg, 
    vector<const FieldDescriptor*> *nonterminal_elements, int lvl)
{
    vector<const FieldDescriptor*>::const_iterator fld_iter;
    std::vector<const FieldDescriptor*> sibblings;
    std::vector<const FieldDescriptor*> attrs;
    
    if (nonterminal_elements->empty()) return;
    printf("PROC NON TERMINALs\n");
    
    while (!nonterminal_elements->empty()) {
        sibblings.clear();
        fld_iter = nonterminal_elements->begin();
        string root = get_pathroot((*fld_iter)->options().GetExtension(xml).path());
        getSubForElemStr(root, nonterminal_elements, &sibblings);
        
        for (int i = 0; i<lvl; i++) fprintf(fw, "  ");
        fprintf(fw, "<%s>\n",  root.c_str());
        recurse_write(fw, NULL, sibblings, attrs, msg, lvl+1, root);
        for (int i = 0; i<lvl; i++) fprintf(fw, "  ");
        fprintf(fw, "</%s>\n",  root.c_str());
    }
}


void
recurse_write(FILE *fw, const FieldDescriptor *parentfield,
    const vector<const FieldDescriptor*> &fields,
    const vector<const FieldDescriptor*> &attrs,
    const Message *msg,
    int lvl, string nonterm_prfx)
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
        if (nonterm_prfx.length() > 0) {
            xmlpath = xmlpath.substr(nonterm_prfx.length()+1, xmlpath.length());
        }
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
        open_element(fw, parentfield, elements, parent_attr, msg, lvl-1);
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
                    recurse_write(fw, *fld_iter, subfields, elem_attr, submsg, lvl+1, "");
                }
            } else {
                const Message *submsg = &reflection->GetMessage(*msg, *fld_iter);
                submsg->GetReflection()->ListFields(*submsg, &subfields);
                getSubForElem(*fld_iter, &nonterminal_elements, &subfields);
                recurse_write(fw, *fld_iter, subfields, elem_attr, submsg, lvl+1, "");
            }
        } else {
            //We have a terminal (element w/o children)
            if ((*fld_iter)->is_repeated()) {
                printf("DUBUG skipping repeated field");
                continue;
            } else {
                open_element (fw, *fld_iter, subfields, elem_attr, msg, lvl);
                close_element(fw, *fld_iter, subfields, elem_attr, msg, lvl);
            }
        }
    }
    
    write_nonterminals(fw, msg, &nonterminal_elements, lvl);
    
    if (parentfield) {
        close_element(fw, parentfield, elements, attributes, msg, lvl-1);
    }
}

void 
write_msg(FILE *fw, const ::google::protobuf::Message *msg)
{
    std::vector<const ::google::protobuf::FieldDescriptor*> fields;
    msg->GetReflection()->ListFields(*msg, &fields);
    std::vector<const FieldDescriptor*> attributes;
    recurse_write(fw, NULL, fields, attributes, msg, 0, "");
}

bool
write_pb_message_to_xml_file(const google::protobuf::Message *document, 
    const char *xmlfilepath)
{
    FILE *fw = ods_fopen(xmlfilepath,NULL,"w");
    if (!fw) return false;
    write_msg(fw,document);
    ods_fclose(fw);
    return true;
}

bool
write_pb_message_to_xml_fd(const google::protobuf::Message *document, 
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
