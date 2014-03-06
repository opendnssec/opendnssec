#include "db/DbBackend.h"

void DbBackend::configure(db_configuration_t& configuration) {
	throw new DbBackendException("function configure not overloaded");
}
void DbBackend::connect(void) {
	throw new DbBackendException("function connect not overloaded");
}
void DbBackend::disconnect(void) {
	throw new DbBackendException("function disconnect not overloaded");
}
