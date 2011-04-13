#include "xmlext-wr.h"

bool write_pb_message_to_xml_file(google::protobuf::Message *document, 
                                  const char *xmlfilepath)
{
    //    int fd = open(path.c_str(),O_WRONLY|O_CREAT, 0644);
    const ::google::protobuf::Reflection *reflection = document->GetReflection();

    std::vector<const ::google::protobuf::FieldDescriptor*> fields;
    std::vector<const ::google::protobuf::FieldDescriptor*>::iterator it;
    reflection->ListFields(*document, &fields);
    for (it=fields.begin(); it != fields.end(); ++it) {

/*TODO: recursively go through the message and write an XML file
 
        printf("%s\n",(*it)->name().c_str());
        
 
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
*/        
        
    }

//    close(fd);
}
