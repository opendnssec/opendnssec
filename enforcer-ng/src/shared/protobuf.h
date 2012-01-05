/*
 * Integration of protobuf code in ods codebase
 * Hooks logging etc.
 *
 */
#ifndef protobuf_h
#define protobuf_h

#ifdef __cplusplus
extern "C" {
#endif

void ods_protobuf_initialize();
	
void ods_protobuf_shutdown();

#ifdef __cplusplus
	}
#endif

#endif
