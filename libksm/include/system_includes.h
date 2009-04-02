#ifndef SYSTEM_INCLUDES_H
#define SYSTEM_INCLUDES_H

/*+
 * Filename: system_includes.h
 *
 * Description:
 *      Between the Sun and Linux boxes, some definitions are in different
 *      files.  This includes file includes the set of system includes files
 *      used by the DAC/Whois programs that differ between the Sun and Linux
 *      systems.
 *
 *
 * Copyright:
 *      Copyright 2008 Nominet
 *      
 * Licence:
 *      Licensed under the Apache Licence, Version 2.0 (the "Licence");
 *      you may not use this file except in compliance with the Licence.
 *      You may obtain a copy of the Licence at
 *      
 *          http://www.apache.org/licenses/LICENSE-2.0
 *      
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the Licence is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the Licence for the specific language governing permissions and
 *      limitations under the Licence.
-*/

#include <sys/socket.h>

#ifdef __sun

#include <sys/types.h>
#include <limits.h>
#include <xti_inet.h>

#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif



#elif __APPLE__

#include <sys/types.h>
#include <limits.h>



#else   /* ... for Linux */

#include <stdint.h>

#ifndef AF_UNIX
#define AF_UNIX AF_LOCAL
#endif

#endif  /* __sun */

#endif  /* SYSTEM_INCLUDES_H */
