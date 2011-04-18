#include <stdio.h>
#include <cstring>
#include <memory.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <string>
#include <cerrno>
#include "xmlext.h"

extern "C" {
#include "shared/duration.h"
}

#include "xmlext.pb.h"

namespace xmlext {

	typedef struct {
		std::vector< ::google::protobuf::Message* > stack;
		std::vector< std::string > paths;
		const ::google::protobuf::FieldDescriptor* field;
	} Context;

/*
	enum CppType {
		CPPTYPE_INT32       = 1,     // TYPE_INT32, TYPE_SINT32, TYPE_SFIXED32	-	int32,sint32,sfixed32
		CPPTYPE_INT64       = 2,     // TYPE_INT64, TYPE_SINT64, TYPE_SFIXED64	-	int64,sint64,sfixed64
		CPPTYPE_UINT32      = 3,     // TYPE_UINT32, TYPE_FIXED32				-	uint32,fixed32
		CPPTYPE_UINT64      = 4,     // TYPE_UINT64, TYPE_FIXED64				-	uint64,fixed64
		CPPTYPE_DOUBLE      = 5,     // TYPE_DOUBLE								-	double
		CPPTYPE_FLOAT       = 6,     // TYPE_FLOAT								-	float
		CPPTYPE_BOOL        = 7,     // TYPE_BOOL								-	bool
		CPPTYPE_ENUM        = 8,     // TYPE_ENUM								-	enum
		CPPTYPE_STRING      = 9,     // TYPE_STRING, TYPE_BYTES					-	string,bytes
		CPPTYPE_MESSAGE     = 10,    // TYPE_MESSAGE, TYPE_GROUP				-	message,group
	}
*/
	
// long is at least 32 bits signed integer, may be 64 bits on 64 bit platform
static bool long_value(const std::string &value, long &longval)
{
	errno = 0;
	longval = strtol(value.c_str(),NULL,10);
	if (errno==EINVAL) {
		printf("ERROR: '%s' invalid value (EINVAL) !\n",value.c_str());
		return false;
	}
	if (errno==ERANGE) {
		printf("ERROR: '%s' value out of range (ERANGE) !\n",value.c_str());
		return false;
	}
	return true;
}

static bool longlong_value(const std::string &value, long long &longlongval)
{
	errno = 0;
	longlongval = strtoll(value.c_str(),NULL,10);
	if (errno==EINVAL) {
		printf("ERROR: '%s' invalid value (EINVAL) !\n",value.c_str());
		return false;
	}
	if (errno==ERANGE) {
		printf("ERROR: '%s' value out of range (ERANGE) !\n",value.c_str());
		return false;
	}
	return true;
}

// unsigned long is at least 32 bits unsigned integer
static bool ulong_value(const std::string &value, unsigned long &ulongval)
{
	errno = 0;
	ulongval = strtoul(value.c_str(),NULL,10);
	if (errno==EINVAL) {
		printf("ERROR: '%s' invalid value (EINVAL) !\n",value.c_str());
		return false;
	}
	if (errno==ERANGE) {
		printf("ERROR: '%s' value out of range (ERANGE) !\n",value.c_str());
		return false;
	}
	return true;
}
	
static bool ulonglong_value(const std::string &value, unsigned long long &ulonglongval)
{
	errno = 0;
	ulonglongval = strtoull(value.c_str(),NULL,10);
	if (errno==EINVAL) {
		printf("ERROR: '%s' invalid value (EINVAL) !\n",value.c_str());
		return false;
	}
	if (errno==ERANGE) {
		printf("ERROR: '%s' value out of range (ERANGE) !\n",value.c_str());
		return false;
	}
	return true;
}
	
static bool double_value(const std::string &value, double &doubleval)
{
	errno = 0;
	doubleval = strtod(value.c_str(),NULL);
	if (errno==EINVAL) {
		printf("ERROR: '%s' invalid value (EINVAL) !\n",value.c_str());
		return false;
	}
	if (errno==ERANGE) {
		printf("ERROR: '%s' value out of range (ERANGE) !\n",value.c_str());
		return false;
	}
	return true;
}
	
static bool float_value(const std::string &value,  double &floatval)
{
	errno = 0;
	floatval = strtof(value.c_str(),NULL);
	if (errno==EINVAL) {
		printf("ERROR: '%s' invalid value (EINVAL) !\n",value.c_str());
		return false;
	}
	if (errno==ERANGE) {
		printf("ERROR: '%s' value out of range (ERANGE) !\n",value.c_str());
		return false;
	}
	return true;
}
	
static bool bool_value(const std::string &value, bool &boolval)
{
	const char *b = value.c_str();
	if (!b) {
		printf("ERROR: '(null)' invalid bool value (EINVAL) !\n");
		return false;
	}
		
	// check for properly encoded true
	boolval = (*b == '1') || strncasecmp(b, "yes", value.size())==0 || strncasecmp(b, "true", value.size())==0;
	if (boolval)
		return true; // if boolval was set it must have been properly encoded.
	
	// properly encoded false, no then return false
	if (*b == '0' || strncasecmp(b, "no", value.size())==0 || strncasecmp(b, "false", value.size())==0)
		return true; // properly encoded.
	
	printf("ERROR: '%s' invalid bool value (EINVAL) !\n",value.c_str());
	return false;
}

// TODO: We handle repeated messages, but we should also handle repeated fields of other types.
	
static bool assign_xml_duration_value_to_protobuf_field(const std::string &value, ::google::protobuf::Message* msg, const ::google::protobuf::FieldDescriptor* field)
{
	// convert a duration text to a time_t value that can then be assigned to a numeric field.
	time_t durationtime;
	duration_type* duration = duration_create_from_string(value.c_str());
	if (duration) {
		durationtime = duration2time(duration);
		duration_cleanup(duration);
	} else {
		printf("ERROR: '%s' not a valid duration !\n",value.c_str());
		return false;
	}
	
	const ::google::protobuf::Reflection* reflection = msg->GetReflection();
	switch (field->cpp_type()) {
		case ::google::protobuf::FieldDescriptor::CPPTYPE_INT32:
			reflection->SetInt32(msg, field, durationtime);
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_INT64:
			reflection->SetInt64(msg, field, durationtime);
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
			reflection->SetUInt32(msg, field, durationtime);
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
			reflection->SetUInt64(msg, field, durationtime);
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
			reflection->SetDouble(msg, field, durationtime);
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
			reflection->SetFloat(msg, field, durationtime);
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
			printf("ERROR: unable to assign a duration to a bool !\n");
			return false;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_ENUM:
			printf("ERROR: unable to assign a duration to an enum !\n");
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_STRING:
			printf("ERROR: unable to assign a duration to a string !\n");
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
			printf("ERROR: unable to assign a duration to a message !\n");
			return false;
		default:
			printf("ERROR: Unsupported field type '%d' !\n", field->cpp_type());
			return false;
	}
	return true;
}		
static bool assign_xml_value_to_protobuf_field(const std::string &value, xmltype xtype, ::google::protobuf::Message* msg, const ::google::protobuf::FieldDescriptor* field)
{
	if (xtype==duration)
		return assign_xml_duration_value_to_protobuf_field(value,msg,field);
		
	// handle xmltype 'automatic'
	const ::google::protobuf::Reflection* reflection = msg->GetReflection();
	switch (field->cpp_type()) {
		case ::google::protobuf::FieldDescriptor::CPPTYPE_INT32: {
			long longval;
			if (long_value(value,longval))
				reflection->SetInt32(msg, field, longval);
			else
				printf("ERROR:\n");
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_INT64: {
			long longval;
			if (long_value(value,longval))
				reflection->SetInt64(msg, field, longval);
			else
				printf("ERROR:\n");
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT32: {
			unsigned long ulongval;
			if (ulong_value(value,ulongval))
				reflection->SetUInt32(msg, field, ulongval);
			else
				printf("ERROR:\n");
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT64: {
			unsigned long ulongval;
			if (ulong_value(value,ulongval))
				reflection->SetUInt64(msg, field, ulongval);
			else
				printf("ERROR:\n");
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE: {
			double doubleval;
			if (double_value(value,doubleval))
				reflection->SetDouble(msg, field, doubleval);
			else
				printf("ERROR:\n");
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_FLOAT: {
			double floatval;
			if (float_value(value,floatval))
				reflection->SetFloat(msg, field, floatval);
			else
				printf("ERROR:\n");
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_BOOL: {
			bool boolval;
			if (bool_value(value,boolval))
				reflection->SetBool(msg, field, boolval);
			else
				printf("ERROR:\n");
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_ENUM: {
			const ::google::protobuf::EnumDescriptor *enu = field->enum_type();
			const ::google::protobuf::EnumValueDescriptor *enuval =  enu->FindValueByName(value);
			if (!enuval) {
				printf("ERROR: '%s' not a valid value for %s !\n",value.c_str(),enu->name().c_str());
			} else {
				//printf("SUCCESS: '%s' is a valid value for %s !\n",value.c_str(),enu->name().c_str());
				reflection->SetEnum(msg, field, enuval);
			}
			break;
		}
		case ::google::protobuf::FieldDescriptor::CPPTYPE_STRING:
			reflection->SetString(msg, field, value);
			break;
		case ::google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
			printf("ERROR: element should not contain text data but we got '%s' !\n",value.c_str());
			return false;
		default:
			printf("ERROR: Unsupported field type '%d' !\n", field->cpp_type());
			return false;
	}
	return true;
}

void assignAttributes(::google::protobuf::Message* msg, const std::string &path, int nb_attributes, int nb_defaulted, const xmlChar ** attributes)
{
	const ::google::protobuf::Descriptor* descriptor = msg->GetDescriptor();
	std::string messagename = msg->GetTypeName();

	// Go through all the fields on the message descriptor and match those with an xml option to the 
	// attributes passed into this function.
	// Although we can tell that fields on the message are required, they may be assigned 
	// from elements at a deeper recursion level.
	// e.g. the required "name" field of the message may be assigned from "Title/@name" and we may 
	// still be processing the element that contains the Title element.
	for (int f=0; f<descriptor->field_count(); ++f) {
		if (descriptor->field(f)->options().HasExtension(xml)) {
			const ::google::protobuf::FieldDescriptor* field = descriptor->field(f);
			const xmloption xmlopt = field->options().GetExtension(xml);

			// if the xml.path option has an @ in it, then the field field should be set from an 
			// attribute in the xml element. In that case scan the attributes of the current xml 
			// element for a matching attribute name.
			if (xmlopt.path().find_first_of('@') != std::string::npos) {
				// Try to match an attribute in the element to the xml.path for the current field.
				for (int ia = 0; ia < nb_attributes; ++ia) {
					int index = 5*ia;
					const xmlChar *localname = attributes[index];
					std::string fieldPath = std::string("@") + (char*)localname;
					if (path.size())
						fieldPath = path + "/" + fieldPath;
					if (xmlopt.path() == fieldPath) {
#if 0
						printf( "ASSIGN %s/@%s=%s\n", messagename.c_str(), field->name().c_str(),xmlopt.path().c_str());
#endif
						//const xmlChar *prefix = attributes[index+1];
						//const xmlChar *nsURI = attributes[index+2]; 
						const xmlChar *valueBegin = attributes[index+3];
						const xmlChar *valueEnd = attributes[index+4];
						std::string value( (const char *)valueBegin, (const char *)valueEnd );
						if (!assign_xml_value_to_protobuf_field(value,xmlopt.type(),msg,field))
							printf("ERROR: Unable to assign xml attribute value to protobuf field !\n");
						break;
					}
				}
			}
		}
	}
	
}

void startElementNs(void * ctx, const xmlChar * localname, const xmlChar * prefix, const xmlChar * URI, int nb_namespaces, const xmlChar ** namespaces, int nb_attributes, int nb_defaulted, const xmlChar ** attributes )
{
	Context &context = *((Context *)ctx);
	::google::protobuf::Message* msg = context.stack.back();
	if (!msg)
		return;
	
	std::string messagename = msg->GetTypeName();
	
	// Allow nested xml elementents to map to a single field.
	std::string path = context.paths.back();
	if (path.size()>0)
		path = path + "/" + (char*)localname;
	else
		path = (char*)localname;

#if 0
	printf( "PROCESSING [%s] for path \"%s\"\n", messagename.c_str(), path.c_str());
#endif
	
	// Go through all the fields in the protobuf message on the top of the stack (the one
	// currently being processed) and assign attributes from the XML element we have 
	// just encountered in the XML file. The protobuf message got created based on 
	// an XML element previously encountered, so now we are evaluating XML elements nested
	// inside the element that caused this protobuf message to be instantiated.
	assignAttributes(msg, path, nb_attributes, nb_defaulted, attributes);
	
	// Again go through all the fields in the protobuf message currently being processed 
	// and this time see whether the fields have an xml option that specifies the tag name
	// of the element we have just encountered in the XML file.
	const ::google::protobuf::Descriptor* descriptor = msg->GetDescriptor();
	bool bFieldMatchedToElement = false;
	for (int f=0; f<descriptor->field_count(); ++f) {
		if (descriptor->field(f)->options().HasExtension(xml)) {
			const ::google::protobuf::FieldDescriptor *field = descriptor->field(f);
			const xmloption xmlopt = field->options().GetExtension(xml);
			if (xmlopt.path() == path) {
				
#if 0
				printf( "ASSIGN %s/@%s=%s\n", messagename.c_str(), field->name().c_str(),xmlopt.path().c_str());
#endif
				if (bFieldMatchedToElement) {
					printf("ERROR: Matched multiple fields to the same element, please modify the proto file !\n");
					// TODO: We can cancel reading the xml file now
					return;
				}
				bFieldMatchedToElement = true;
				
				
				// Value is assigned during characters callback
				// Only for xml.type of element is a 1 assigned to the field to indicate presence of the element.
				
				switch (field->type()) {
					case ::google::protobuf::FieldDescriptor::TYPE_BOOL: 
					{
						if (!assign_xml_value_to_protobuf_field("1",xmlopt.type(),msg,field)) {
							printf("ERROR: Unable to assign xml attribute value to protobuf field !\n");
							// TODO: We can cancel reading the xml file now
							return;
						}
						// Act as if this match did not occur, otherwise the match will 
						// disallow other matches of nested elements. This will prevent
						// the depositing of values in the fields of this protobuf message.
						bFieldMatchedToElement = false;
						break;
					}
					case ::google::protobuf::FieldDescriptor::TYPE_MESSAGE:
					{
						const ::google::protobuf::Reflection* reflection = msg->GetReflection();
						if (field->is_repeated()) {
							msg = reflection->AddMessage(msg,field);
						} else {
							msg = reflection->MutableMessage(msg,field);
						}
						
						// Attributes that are part of the element for which we just created a message
						// may need to be assigned to fields of that message.
						assignAttributes(msg, "", nb_attributes, nb_defaulted, attributes);
						
						context.stack.push_back(msg);
						context.field = NULL;
						context.paths.push_back("");
						break;
					}
					default:
					{
						// The protobuf message field matches the current XML element exactly.
						// So we need to assign the textual content of the XML element to the field.
						// Therefore we push the message and assign the field and wait for the 
						// characters callback to perform the actual assignment.
						context.stack.push_back(msg);
						context.field = field;
						context.paths.push_back("");
					}
				}
			}
		}
	}
	
	if (!bFieldMatchedToElement) {
		// No field in the protobuf message matched with the XML element currently 
		// under evaluation. We now push the current message so we can try again to 
		// match fields in this message to XML elements nested in the XML element 
		// we are currently evaluating.
		context.stack.push_back(msg);
		context.field = NULL;
		context.paths.push_back(path);
	}
}

void characters(void * ctx, const xmlChar * ch, int len)
{
	if (len<=0) return;
	const char *start = (const char *)&ch[0];
	const char *stop = (const char *)&ch[len-1];
#if 1
	// trim leading and trailing whitespace
	while (start<=stop && isspace(*start)) ++start;
	while (start<=stop && isspace(*stop)) --stop;
	if (start>stop) return;
#endif
	std::string value(start,stop+1);

	Context &context = *((Context *)ctx);

	if (! context.field) {
		std::string path = context.paths.back();
		printf("ERROR: No field for '%s' !\n",path.c_str());
		return;
	}
	
	if (context.field->options().HasExtension(xml)) {
		const xmloption xmlopt = context.field->options().GetExtension(xml);
		::google::protobuf::Message* msg = context.stack.back();
		if (!assign_xml_value_to_protobuf_field(value,xmlopt.type(),msg,context.field))
			printf("ERROR: Unable to assign xml element text to protobuf field !\n");
	} else {
		// should never happen, because the field is assigned based on matching xml.path option
		printf("ERROR: field has no xml option specified !\n");
	}
}

void endElementNs(void * ctx, const xmlChar * localname, const xmlChar * prefix, const xmlChar * URI )
{
	Context &context = *((Context *)ctx);
	if (!context.stack.back())
		return;
	context.stack.pop_back();
	context.paths.pop_back();
	context.field = NULL;

	//TODO: Go through all the required fields on a popped context and report errors when "required" ones were not assigned a value.
	
	//printf( "<%s\n", localname); // printf( "/%s\t prefix = '%s' uri = '%s'\n", localname, prefix, URI  );
}

void error( void * ctx, const char * msg, ... )
{
	va_list args;
	va_start(args, msg);
	vprintf( msg, args );
	va_end(args);
}

void warning(void * ctx, const char * msg, ... )
{
	va_list args;
	va_start(args, msg);
	vprintf( msg, args );
	va_end(args);
}

}

static void init_xmlSAXHandler(xmlSAXHandler *sax)
{
	memset( sax, 0, sizeof(xmlSAXHandler) );
#if 0
	// This will hookup internal handlers from SAX2 that expect
	// the context to be of a certain type used when creating a dom.
	// So don't use this,
	xmlSAXVersion( sax, 2 );
#else
	// Make the parser us SAX2 call backs
	sax->initialized = XML_SAX2_MAGIC;
#endif
	sax->startElementNs = &xmlext::startElementNs;
	sax->characters = &xmlext::characters;
	sax->endElementNs = &xmlext::endElementNs;
	sax->warning = &xmlext::warning;
	sax->error = &xmlext::error;
}

bool read_pb_message_from_xml_file(google::protobuf::Message *document, const char *xmlfilepath)
{
	LIBXML_TEST_VERSION

	xmlSAXHandler sax;
	init_xmlSAXHandler(&sax);

	xmlext::Context context;
	context.stack.push_back(document);
	context.paths.push_back("");
	int result = xmlSAXUserParseFile(&sax, &context, xmlfilepath);
	context.paths.pop_back();
	context.stack.pop_back();

	if ( result != 0 ) {
		printf("Failed to parse document.\n" );
		return false;
	}

	xmlCleanupParser();
	xmlMemoryDump();
	return true;
}

bool read_pb_message_from_xml_memory(google::protobuf::Message *document, const char *buffer, int size)
{
	LIBXML_TEST_VERSION
	
	xmlSAXHandler sax;
	init_xmlSAXHandler(&sax);
	
	xmlext::Context context;
	context.stack.push_back(document);
	context.paths.push_back("");
	int result = xmlSAXUserParseMemory(&sax, &context, buffer, size);
	context.paths.pop_back();
	context.stack.pop_back();
	
	if ( result != 0 ) {
		printf("Failed to parse document.\n" );
		return false;
	}
	
	xmlCleanupParser();
	xmlMemoryDump();
	return true;
}

void recurse_dump_descriptor(const ::google::protobuf::Descriptor *descriptor)
{
	static size_t level = 0;
	
	printf("%s[%s]\n",std::string(level,'\t').c_str(),
           descriptor->name().c_str());
	for (int i=0; i<descriptor->field_count(); ++i) {
		const ::google::protobuf::FieldDescriptor *field = descriptor->field(i);
		
		if (field->options().HasExtension(xml)) {
			const xmloption xmlopt = field->options().GetExtension(xml);
			
			printf("%s-%s = %s\n",std::string(level,'\t').c_str(),
                   field->name().c_str(),xmlopt.path().c_str());
		} else {
			printf("%s-%s\n",std::string(level,'\t').c_str(),
                   field->name().c_str());
		}
		
		if (field && field->type() == ::google::protobuf::FieldDescriptor::TYPE_MESSAGE) {
			++level;
			recurse_dump_descriptor(field->message_type());
			--level;
		}
	}
}
