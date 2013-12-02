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

/* FILE
 * Convert protobuf datastructure to formatted xml output. This
 * is less straight-forward than it seems. Not all data has a nice tree
 * like structure.
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

static void
recurse_write(FILE *, const FieldDescriptor *,
    const vector<const FieldDescriptor*> &,
    const vector<const FieldDescriptor*> &,
    const Message *, int, string);

/* Reads value of specified field and returns as human readable string.
 * param msg: Structure containing data
 * field: Description of field to get the data from
 * return string, empty string on field not containing data.
 */
static string
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

/* Return if this field is an attribute or element. 
 * (<element attribute="value">)
 * param field: field to evaluate
 * return True for attribute, false for element
 */
static bool
isattr(const FieldDescriptor *field) {
    const xmloption xmlopt = field->options().GetExtension(xml);
    return xmlopt.path().find('@') != string::npos;
}

/* Given path, filter out any fields starting with prefix
 * param prefix: path of parent element
 * param[in/out] input: Fields to sort out, subfields will be removed
 * param[out] subfields: all fields containing prefix
 */
static void
getSubForElemStr( string prefix, vector<const FieldDescriptor*> *input,
    vector<const FieldDescriptor*> *subfields)
{
    /* TODO: I bet this function can be more efficient */
    vector<const FieldDescriptor*> keep;
    vector<const FieldDescriptor*>::iterator fld_iter;
    
    for (fld_iter=input->begin(); fld_iter != input->end(); ++fld_iter) {
        string attrpath = (*fld_iter)->options().GetExtension(xml).path();
        if (attrpath.find(prefix, 0) == 0)
            subfields->push_back(*fld_iter);
        else
            keep.push_back(*fld_iter);
    }
    /* Return non subelements to input vector */
    input->clear();
    for (fld_iter=keep.begin(); fld_iter != keep.end(); ++fld_iter) {
        input->push_back(*fld_iter);
    }
}

/* Given field, filter out any fields starting with prefix
 * param field: parent element
 * param[in/out] input: Fields to sort out, subfields will be removed
 * param[out] subfields: all fields containing prefix
 */
static void
getSubForElem( const FieldDescriptor *field,
    vector<const FieldDescriptor*> *input,
    vector<const FieldDescriptor*> *subfields)
{
    string elempath = field->options().GetExtension(xml).path();
    getSubForElemStr(elempath, input, subfields);
}

/* Remove entire path
 * lvl1/lvl2/lvl3/lvl4 -> lvl4 
 */
static string
strip_path(string in)
{
    size_t pos = in.rfind('/');
    if (pos == string::npos) return in;
    return in.substr(pos+1, in.length());
}

/* Remove one path level
 * lvl1/lvl2/lvl3/lvl4 -> lvl2/lvl3/lvl4
 * lvl1 -> lvl1
 */
static string
strip_pathlabel(string in)
{
    size_t pos = in.find('/');
    if (pos == string::npos) return in;
    return in.substr(pos+1, in.length());
}

/* Find top level parent of string
 * lvl1/lvl2/lvl3/lvl4 -> lvl1
 * lvl1 -> lvl1
 */
static string
get_pathroot(string in)
{
    size_t pos = in.find('/');
    if (pos == string::npos) return in;
    return in.substr(0, pos);
}

/* return attribute name. If attribute is not found entire string is 
 * returned.
 * lvl1/lvl2/lvl3/@attr -> attr
 * lvl1/lvl2/lvl3/attr -> lvl1/lvl2/lvl3/attr
 */
static string
scrub_attr(string in)
{
    size_t pos = in.rfind('@');
    if (pos == string::npos) return in;
    return in.substr(pos+1, in.length());
}

/* Write opening tag of element. If element has no value and no children
 * tag will be closed: <boolelement/>. Regardless the close_element 
 * function should be called.
 * param fw: file to write
 * param no_children: if true, open and close tag might be combined
 * param attributes: attributes to write in the tag.
 * param msg: data container
 * param lvl: indent level
 */
static void
open_element(FILE *fw, const FieldDescriptor *field,
    bool no_children, vector<const FieldDescriptor*> attributes,
    const Message *msg, int lvl)
{
    /* get everything after last '/' */
    string elempath = field->options().GetExtension(xml).path();
    string elemname = strip_path(elempath);

    for (int i = 0; i<lvl; i++) fprintf(fw, "  ");
    fprintf(fw, "<%s", elemname.c_str());
    vector<const FieldDescriptor*>::const_iterator fld_iter;
    for (fld_iter=attributes.begin(); fld_iter != attributes.end(); ++fld_iter) {
        
        string attrpath = (*fld_iter)->options().GetExtension(xml).path();
        string attrname = scrub_attr(attrpath);
        fprintf(fw, " %s = \"%s\"", attrname.c_str(), get_value(msg, *fld_iter).c_str());
    }
    
    string val =  get_value(msg, field);
    if (!val.empty())
        fprintf(fw, ">%s",  val.c_str());
    else if (no_children)
        fprintf(fw, "/>\n");
    else
        fprintf(fw, ">\n");
}

/* Write closing tag of element. If element has no value and no children
 * close_element will assume it is already closed and write nothing.
 * param fw: file to write
 * param no_children: if true, open and close tag might be combined
 * param attributes: attributes to write in the tag.
 * param msg: data container
 * param lvl: indent level
 */
static void
close_element(FILE *fw, const FieldDescriptor *field, bool no_children, 
    vector<const FieldDescriptor*> attributes, const Message *msg,
    int lvl)
{
    string elempath = field->options().GetExtension(xml).path();
    string elemname = strip_path(elempath);
    string val =  get_value(msg, field);
    if (no_children && val.empty()) return;
    if (!no_children) for (int i = 0; i<lvl; i++) fprintf(fw, "  ");
    fprintf(fw, "</%s>\n",  elemname.c_str());
}

/* Write empty non terminal elements. The problem is that these elements
 * have no corresponding field descriptors. It will extract the non
 * terminal elements, write the tags and call recurse_write()
 * param fw: file to write
 * param msg: datastructure containing all data
 * param nonterminal_elements: Fields with paths containing non-terminal
 *      elements
 * param lvl: Indent level
 */
static void
write_nonterminals(FILE *fw, const Message *msg, 
    vector<const FieldDescriptor*> *nonterminal_elements, int lvl)
{
    vector<const FieldDescriptor*>::const_iterator fld_iter;
    vector<const FieldDescriptor*> sibblings;
    vector<const FieldDescriptor*> attrs;
    
    if (nonterminal_elements->empty()) return;
    
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

/* Write xml file recursively
 * param fw: file to write
 * param parentfield: Field to write in this pass, may be NULL
 * param fields: subfields of parent element
 * param attrs: attributes of parent element
 * param msg: datastructure with all values
 * param lvl: indentation lvl, initially call with 0
 * param nonterm_prfx: prefix of non-terminal element in path (these 
 *     are not represented by field descriptors). Init with empty string.
 * */
static void
recurse_write(FILE *fw, const FieldDescriptor *parentfield,
    const vector<const FieldDescriptor*> &fields,
    const vector<const FieldDescriptor*> &attrs, const Message *msg,
    int lvl, string nonterm_prfx)
{
    /* a reflection is 'a view' on the data. This is particularity 
     * useful when accessing repeated fields */
    const Reflection *reflection = msg->GetReflection();
    vector<const FieldDescriptor*>::const_iterator fld_iter;
    
    /* sort out subelements of parent */
    vector<const FieldDescriptor*> attributes, elements, nonterminal_elements;
    for (fld_iter=fields.begin(); fld_iter != fields.end(); ++fld_iter) {
        /* Not defined in xml structure, ignore */
        if (!(*fld_iter)->options().HasExtension(xml)) continue;
        string xmlpath = (*fld_iter)->options().GetExtension(xml).path();
        /* Strip empty non-terminal prefix */
        if (nonterm_prfx.length() > 0)
            xmlpath = xmlpath.substr(nonterm_prfx.length()+1, xmlpath.length());
        if (isattr(*fld_iter)) { /* attribute */
            attributes.push_back(*fld_iter);
        } else { /* element */
            if (xmlpath.find('/') == string::npos) 
                elements.push_back(*fld_iter);
            else
                nonterminal_elements.push_back(*fld_iter);
        }
    }
    /* Merge attr with newly found attributes */
    for (fld_iter=attrs.begin(); fld_iter != attrs.end(); ++fld_iter) {
        attributes.push_back(*fld_iter);
    }
    
    if (parentfield) {
        vector<const FieldDescriptor*> parent_attr;
        getSubForElem(parentfield, &attributes, &parent_attr);
        open_element(fw, parentfield, elements.empty(), parent_attr, msg, lvl-1);
    }
    
    /* Process all subelements, recurs if needed. */
    for (fld_iter=elements.begin(); fld_iter != elements.end(); ++fld_iter) {
        const Message *submsg;
        string xmlpath = (*fld_iter)->options().GetExtension(xml).path();

        /* find attributes for current elem */
        vector<const FieldDescriptor*> elem_attr;
        getSubForElem(*fld_iter, &attributes, &elem_attr);
        
        vector<const FieldDescriptor*> subfields;
        if ((*fld_iter)->type() == FieldDescriptor::TYPE_MESSAGE) {
            /* If this field is a MESSAGE start recursion */
            if ((*fld_iter)->is_repeated()) {
                /* Repeated field, get an unique reflection on the data
                 * for each iteration */
                for (int f = 0; f < reflection->FieldSize(*msg, *fld_iter); f++) {
                    submsg = &reflection->GetRepeatedMessage(*msg, *fld_iter, f);
                    submsg->GetReflection()->ListFields(*submsg, &subfields);
                    getSubForElem(*fld_iter, &nonterminal_elements, &subfields);
                    recurse_write(fw, *fld_iter, subfields, elem_attr, submsg, lvl+1, "");
                }
            } else {
                submsg = &reflection->GetMessage(*msg, *fld_iter);
                submsg->GetReflection()->ListFields(*submsg, &subfields);
                getSubForElem(*fld_iter, &nonterminal_elements, &subfields);
                recurse_write(fw, *fld_iter, subfields, elem_attr, submsg, lvl+1, "");
            }
        } else {
            /* This element has no children */
            if ((*fld_iter)->is_repeated()) {
                for (int f = 0; f < reflection->FieldSize(*msg, *fld_iter); f++) {
                    submsg = &reflection->GetRepeatedMessage(*msg, *fld_iter, f);
                    open_element (fw, *fld_iter, true, elem_attr, submsg, lvl);
                    close_element(fw, *fld_iter, true, elem_attr, submsg, lvl);
                }
            } else {
                open_element (fw, *fld_iter, subfields.empty(), elem_attr, msg, lvl);
                close_element(fw, *fld_iter, subfields.empty(), elem_attr, msg, lvl);
            }
        }
    }
    
    /* Everything left in nonterminal_elements after processing is in
     * fact an empty non-terminal, these need special treatment */
    write_nonterminals(fw, msg, &nonterminal_elements, lvl);
    
    if (parentfield) {
        close_element(fw, parentfield, elements.empty(), attributes, msg, lvl-1);
    }
}

void 
write_msg(FILE *fw, const ::google::protobuf::Message *msg, int lvl)
{
    vector<const ::google::protobuf::FieldDescriptor*> fields;
    msg->GetReflection()->ListFields(*msg, &fields);
    vector<const FieldDescriptor*> attributes;
    recurse_write(fw, NULL, fields, attributes, msg, lvl, "");
}

bool
write_pb_message_to_xml_file(const google::protobuf::Message *document, 
    const char *xmlfilepath)
{
    FILE *fw = ods_fopen(xmlfilepath,NULL,"w");
    if (!fw) return false;
    write_msg(fw,document, 0);
    ods_fclose(fw);
    return true;
}

bool
write_pb_message_to_xml_fd(const google::protobuf::Message *document, 
    int fd, int lvl)
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
    write_msg(fw, document, lvl);
    ods_fclose(fw);
    return true;
}

bool
write_pb_message_to_xml_fd(const google::protobuf::Message *document, 
    int fd)
{
    return write_pb_message_to_xml_fd(document, fd, 0);
}
